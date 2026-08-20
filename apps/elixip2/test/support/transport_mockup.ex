defmodule SIP.Test.Transport.Mockup do
  @moduledoc """
  In-process fake transport for unit tests. It implements the same contract as
  the real transports (`sendmsg`, `getlocalipandport`, `setupperlayer`,
  `transport_str/0`, `is_reliable/0`) but puts nothing on the network.

  The module itself is deliberately dumb; the *behaviour* of the fake remote
  party is delegated to a pluggable peer (`SIP.Test.Peer` behaviour, canned
  implementations in `SIP.Test.Peers.*`):

    * every message the stack sends lands in `sendmsg`, is parsed, notified to
      the attached probe (`SIP.Test.Probe`), then handed to the peer;
    * the peer returns actions; `{:inject, msg, after_ms}` messages are
      scheduled and fed back into the local stack as if received from the
      network — a response goes to the transaction layer, a request through
      the full inbound routing (transaction/dialog creation);
    * tests inject inbound traffic themselves with `inject/2`.

  Selected by the Selector for any R-URI carrying `;unittest=1`, through the
  `:unittest_transport` application env (set in `test_helper.exs`). The
  instance is shared per destination (registered as "UDPMockup" in
  `Registry.SIPTransport`), so tests must `set_peer/3` — it fully replaces the
  peer and its state — rather than assume a fresh instance.
  """
  use GenServer
  require Logger
  alias SIP.Test.Probe

  # The fake resolved destination the Selector stamps on unittest URIs, echoed
  # here as the transport's "socket" identity.
  @mock_socket {{1, 2, 3, 4}, 5080}

  # The fake remote address inbound (injected) requests appear to come from.
  @mock_remote_ip "82.184.8.2"
  @mock_remote_port 53_936

  defstruct localip: nil,
            localport: 5060,
            upperlayer: nil,
            peer: SIP.Test.Peers.Passive,
            peer_state: %{},
            probe: nil

  # ── Transport contract ──────────────────────────────────────────────────────

  def transport_str, do: "udp"

  @spec is_reliable() :: boolean()
  def is_reliable, do: false

  @doc """
  Which mockup process serves this URI (see `SIP.Transport.Selector`).

  `;unittest=1` is THE shared instance every suite uses. Any other value names a
  peer of its own: `;unittest=callee` and `;unittest=caller` are two different
  processes, each with its own peer and peer state.

  That distinction is what a B2BUA test needs: with one shared instance the two
  legs overwrite each other's stored request, and an answer meant for the callee
  is built from the caller's INVITE.
  """
  @spec select_instance(SIP.Uri.t()) :: binary()
  def select_instance(ruri) do
    case SIP.Uri.get_uri_param(ruri, "unittest") do
      {:ok, "1"} -> "UDPMockup"
      {:ok, name} when is_binary(name) and name != "" -> "UDPMockup:" <> name
      _ -> "UDPMockup"
    end
  end

  # ── Test-facing API ─────────────────────────────────────────────────────────

  @doc """
  Find or launch the shared mockup transport instance and return its pid.
  Requires `SIP.Transport.Selector.start/0` (tests do it in `setup_all`).
  Useful to install a peer *before* the code under test sends anything.
  """
  @spec instance!() :: pid()
  def instance!(url \\ "sip:mockup@unit.test;unittest=1") do
    case SIP.Transport.Selector.select_transport(url) do
      %SIP.Uri{tp_pid: pid} when is_pid(pid) -> pid
      other -> raise "could not obtain the mockup transport instance: #{inspect(other)}"
    end
  end

  @doc """
  Install the simulated remote peer. Replaces the previous peer *and* its
  state, so a test starts deterministic even on the shared instance.
  """
  @spec set_peer(pid(), module(), keyword()) :: :ok
  def set_peer(t_pid, peer_mod, opts \\ []) when is_atom(peer_mod) do
    GenServer.call(t_pid, {:set_peer, peer_mod, opts})
  end

  @doc "Attach the probe process receiving the `{:sip_mockup, event}` stream."
  @spec attach_probe(pid(), pid()) :: :ok
  def attach_probe(t_pid, probe \\ self()) when is_pid(probe) do
    GenServer.call(t_pid, {:attach_probe, probe})
  end

  @doc "Inject an inbound SIP message, as if received from the network."
  @spec inject(pid(), map()) :: :ok
  def inject(t_pid, sipmsg) when is_map(sipmsg) do
    send(t_pid, {:inject, sipmsg})
    :ok
  end

  @doc """
  Hand a command to the installed peer (`SIP.Test.Peer.on_command/2`).

  For the peers a test drives at runtime rather than canning up front — see
  `SIP.Test.Peers.Manual`, where the test asserts on the request that went out
  before deciding how the far end answers it.
  """
  @spec tell_peer(pid(), term()) :: :ok
  def tell_peer(t_pid, cmd) do
    GenServer.call(t_pid, {:tell_peer, cmd})
  end

  # ── GenServer callbacks ─────────────────────────────────────────────────────

  @impl true
  def init({_dest_ip, _dest_port}) do
    case SIP.NetUtils.get_local_ips([:ipv4]) do
      [] ->
        Logger.error(
          module: __MODULE__,
          message: "Could not find any valid IP V4 address. Check your network connection"
        )

        {:stop, :networkdown}

      [ip | _] ->
        {:ok, %__MODULE__{localip: ip}}
    end
  end

  @impl true
  def handle_call({:sendmsg, msgstr, destip, destport}, _from, state) do
    destipstr =
      case SIP.NetUtils.ip2string(destip) do
        {:error, :einval} ->
          raise "Mockup transport: invalid destination IP address #{inspect(destip)}"

        ipstr when is_binary(ipstr) ->
          ipstr
      end

    Logger.debug(
      "Mockup transport: message sent to #{destipstr}:#{destport} ---->\r\n" <>
        msgstr <> "\r\n-----------------"
    )

    case SIPMsg.parse(msgstr, &log_parse_error/4) do
      {:ok, sipmsg} ->
        {:reply, :ok, handle_sent_msg(sipmsg, state)}

      err ->
        Logger.error("Mockup transport: failed to parse sent msg: #{inspect(err)}")
        {:reply, :transporterror, state}
    end
  end

  def handle_call(:getlocalipandport, _from, state) do
    {:reply, {:ok, state.localip, state.localport}, state}
  end

  # Set the upper layer handler for transactions to process
  def handle_call({:setupperlayer, ul_pid}, _from, state) when is_pid(ul_pid) do
    {:reply, :ok, %{state | upperlayer: ul_pid}}
  end

  def handle_call({:setupperlayer, ul_func}, _from, state) when is_function(ul_func, 2) do
    {:reply, :ok, %{state | upperlayer: ul_func}}
  end

  def handle_call({:setupperlayer, nil}, _from, state) do
    {:reply, :ok, %{state | upperlayer: nil}}
  end

  def handle_call({:set_peer, peer_mod, opts}, _from, state) do
    {:reply, :ok, %{state | peer: peer_mod, peer_state: peer_mod.init(opts)}}
  end

  def handle_call({:attach_probe, probe}, _from, state) do
    {:reply, :ok, %{state | probe: probe}}
  end

  def handle_call({:tell_peer, cmd}, _from, state) do
    {actions, peer_state} = state.peer.on_command(cmd, state.peer_state)
    Enum.each(actions, &execute_action(&1, state))
    {:reply, :ok, %{state | peer_state: peer_state}}
  end

  @impl true
  # A scheduled peer action or a test injection: a request goes through the
  # full inbound routing (transaction/dialog creation)...
  def handle_info({:inject, sipmsg}, state)
      when is_atom(sipmsg.method) and sipmsg.method != false do
    Logger.debug(
      module: __MODULE__,
      message: "Injecting inbound SIP #{sipmsg.method}"
    )

    {:ok, remote_ip} = SIP.NetUtils.parse_address(@mock_remote_ip)

    SIP.Transport.ImplHelpers.process_incoming_message(
      state,
      SIPMsg.serialize(sipmsg),
      "UDP",
      __MODULE__,
      @mock_socket,
      remote_ip,
      @mock_remote_port
    )
  end

  # ...and a response goes straight to the transaction layer.
  def handle_info({:inject, sipmsg}, state) do
    Logger.debug(
      module: __MODULE__,
      message: "Injecting inbound SIP response #{sipmsg.response}"
    )

    SIP.Transac.process_sip_message(SIPMsg.serialize(sipmsg))
    {:noreply, state}
  end

  # ── Internals ───────────────────────────────────────────────────────────────

  # Notify the probe of everything the stack sends, then let the peer react.
  defp handle_sent_msg(sipmsg, state) do
    {event, callback} =
      if sipmsg.method == false do
        {{:response_sent, sipmsg.response, sipmsg}, :on_response}
      else
        {{:request_sent, sipmsg.method, sipmsg}, :on_request}
      end

    Probe.notify(state.probe, event)

    {actions, peer_state} = apply(state.peer, callback, [sipmsg, state.peer_state])
    Enum.each(actions, &execute_action(&1, state))
    %{state | peer_state: peer_state}
  end

  # Always go through the mailbox (even for 0 ms) so the stack never re-enters
  # the transport while it is still inside the sendmsg call.
  defp execute_action({:inject, sipmsg, after_ms}, _state) do
    Process.send_after(self(), {:inject, sipmsg}, after_ms)
  end

  defp execute_action({:notify, event}, state) do
    Probe.notify(state.probe, event)
  end

  defp log_parse_error(code, errmsg, lineno, line) do
    Logger.error("Mockup transport: failed to parse sent msg: " <> errmsg)
    Logger.debug("Mockup transport: offending line #{lineno}: #{line}")
    Logger.debug("Mockup transport: error code #{code}")
  end
end
