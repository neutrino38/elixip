defmodule SIP.Test.Transport.UDPMockup do
  @moduledoc """
  Mockup for transport module for unit testing
  """
  alias SIP.NetUtils
  use GenServer
  require Logger
  require SIP.Transac
  require SIPMsg
  import SIP.Msg.Ops

  # @destproxy "1.2.3.4"
  # @destport 5080
  #  @ringing_time 2000

  @transport_str "udp"
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: false

  @doc """
  Which mockup process serves this URI (see `SIP.Transport.Selector`).

  `;unittest=1` is THE shared instance every suite has always used — unchanged,
  so nothing existing moves. Any other value names a peer of its own:
  `;unittest=callee` and `;unittest=caller` are two different processes, each
  with its own current request and canned scenario.

  That distinction is what a B2BUA test needs: with one shared instance the two
  legs overwrite each other's `state.req`, and an answer meant for the callee is
  built from the caller's INVITE.
  """
  def select_instance(ruri) do
    case SIP.Uri.get_uri_param(ruri, "unittest") do
      {:ok, "1"} -> "UDPMockup"
      {:ok, name} when is_binary(name) and name != "" -> "UDPMockup:" <> name
      _ -> "UDPMockup"
    end
  end

  # Simulated call scenarii

  def simulate_successful_answer(t_pid) do
    GenServer.cast(t_pid, {:simulate, :successfulcall})
  end

  def simulate_noanswer_answer(t_pid) do
    GenServer.cast(t_pid, {:simulate, :noanswer})
  end

  @spec simulate_busy_answer(pid()) :: :ok
  def simulate_busy_answer(t_pid) do
    GenServer.cast(t_pid, {:simulate, :busy})
  end

  def simulate_challenge(t_pid) do
    GenServer.cast(t_pid, {:simulate, :challenge})
  end

  def simulate_successful_register(t_pid) do
    GenServer.cast(t_pid, {:simulate, :successfulregister})
  end

  # Control whether the mockup answers OPTIONS keepalives. Setting it to true
  # simulates an unreachable peer (exercises the missed-keepalive dialog
  # teardown). The instance is shared per destination, so tests reset it to
  # false before establishing their dialog.
  def drop_options(t_pid, drop \\ true) do
    GenServer.cast(t_pid, {:drop_options, drop})
  end

  @doc """
  Answer relayed BYEs with a 200, without selecting a canned call scenario.

  Answering a BYE was gated on `:inboundinvite` / `:successfulcall` only. A B2BUA
  suite drives every response itself and therefore selects no scenario, so the BYE
  it relayed was never answered and the scenario sat in its `wait_far_bye_ok` state
  for the full 5 s fallback ("BYE unanswered, closing anyway") before ending — four
  tests at five seconds each, and the normal path, where the far end *does* answer,
  went unexercised while the tests' own comments claimed it was what ended them.

  Separate from the canned scenarios rather than folded into them, because those also
  auto-answer the INVITE, which is exactly what such a suite is driving by hand.
  """
  def answer_bye(t_pid, answer \\ true) do
    GenServer.cast(t_pid, {:answer_bye, answer})
  end

  defp handle_req(state, :INVITE, sipreq) do
    # Tell the test the INVITE actually went out, mirroring {:options_sent, …}.
    # Without it a test cannot know *when* to simulate an answer: it would race
    # the request it is answering, and `{:simulate, …}` reads `state.req`. It
    # also hands the test the request as it left the stack, which is what a
    # B2BUA suite asserts the forwarding rules on.
    if state.testapppid != nil, do: send(state.testapppid, {:invite_sent, sipreq})
    Map.put(state, :req, sipreq)
  end

  defp handle_req(state, :REGISTER, sipreq) do
    Map.put(state, :req, sipreq)
  end

  defp handle_req(state, :ACK, _sipreq) do
    if Map.has_key?(state, :req) and state.req.method == INVITE do
      Map.delete(state, :req)
    else
      state
    end
  end

  # Answering a CANCEL *we* received, i.e. one the stack sent out (a B2BUA
  # cancelling the call attempt it forwarded). Two responses go back: 200 to the
  # CANCEL itself, then 487 to the INVITE it cancels — which is the request the
  # 487 must be built from (RFC 3261 §9.2), not the CANCEL.
  #
  # Both carry a To tag: any response above 100 needs one, and reply_to_request/5
  # raises without it. The CANCEL as sent has no tag on its To (it copies the
  # INVITE's), so the tag has to be supplied here — this peer's own, the same one
  # its other answers carry.
  defp handle_req(state, :CANCEL, sipreq) do
    if Map.has_key?(state, :req) do
      if sipreq.transid == state.req.transid do
        siprsp = reply_to_request(sipreq, 200, "OK", [], state.totag)
        Process.send_after(self(), {:recv, siprsp}, 100)
        siprsp2 = reply_to_request(state.req, 487, nil, [], state.totag)
        Process.send_after(self(), {:recv, siprsp2}, 200)
      end

      state
    else
      siprsp = reply_to_request(sipreq, 481, "No such transaction", [], state.totag)
      Process.send_after(self(), {:recv, siprsp}, 100)
      state
    end
  end

  defp handle_req(state, :BYE, sipreq) do
    # Say that a BYE went out whenever someone is listening — pure observation,
    # independent of any canned scenario. A test that hangs a call up itself
    # (a B2BUA relaying a BYE, say) has no scenario selected, and gating the
    # notification on one made "no BYE was sent" assertions pass vacuously.
    if state.testapppid != nil do
      send(state.testapppid, :BYE)
    end

    # Answering it, on the other hand, stays part of the canned call scenarios:
    # that is a response on the wire, and it ends the dialog.
    if Map.get(state, :scenario) in [:inboundinvite, :successfulcall] or
         Map.get(state, :answer_bye, false) do
      resp = SIP.Msg.Ops.reply_to_request(sipreq, 200, "OK")
      Process.send_after(self(), {:recv, resp}, 100)
      Logger.debug("UDPMockup: replied to BYE")
    end

    state
  end

  defp handle_req(state, :OPTIONS, sipreq) do
    # Forward the sent OPTIONS to the test process so it can assert on keepalives.
    if state.testapppid != nil do
      send(state.testapppid, {:options_sent, sipreq})
    end

    # Auto-reply 200 OK unless the test asked us to stay silent (dead-peer sim).
    unless Map.get(state, :drop_options, false) do
      resp = SIP.Msg.Ops.reply_to_request(sipreq, 200, "OK", [], state.totag)
      Process.send_after(self(), {:recv, resp}, 50)
    end

    state
  end

  defp handle_req(state, _method, _sipreq) do
    state
  end

  defp handle_resp(state, code, sipresp) do
    cond do
      # A response to an OPTIONS, first: the stack answers an out-of-dialog one on its
      # own, under no canned scenario, and this instance is shared — a :inboundinvite
      # left over from an earlier test file would otherwise capture it and forward a
      # bare code where the test expects the parsed response.
      match?([_, :OPTIONS], Map.get(sipresp, :cseq)) and state.testapppid != nil ->
        send(state.testapppid, {:uas_response, code, sipresp})

      Map.get(state, :scenario) == :inboundinvite and state.testapppid != nil ->
        # Forward event to the test process. 100 is forwarded too so tests can
        # assert the IST-emitted automatic 100 Trying.
        case code do
          100 -> send(state.testapppid, code)
          180 -> send(state.testapppid, code)
          c when c in 200..699 -> send(state.testapppid, c)
          _ -> nil
        end

      # For an inbound REGISTER handled by a UAS scenario, forward the full
      # parsed response (challenge / 200 OK / reject) so tests can assert on it.
      Map.get(state, :scenario) == :inboundregister and state.testapppid != nil ->
        send(state.testapppid, {:uas_response, code, sipresp})

      true ->
        nil
    end

    state
  end

  # Callbacks

  @impl true
  def init({_dest_ip, _dest_port}) do
    ips = SIP.NetUtils.get_local_ips([:ipv4])

    if ips == [] do
      Logger.error(
        module: SIP.Test.Transport.UDPMockup,
        message: "Could not find any valid IP V4 address. Check your network connection"
      )

      {:stop, :networkdown}
    else
      initial_state = %{
        t_isreliable: false,
        # This peer's own To tag. It used to be the same literal for every
        # instance, so two named peers answered a forked INVITE with the same
        # tag and nothing could tell which branch a response came from.
        totag: SIP.Msg.Ops.generate_from_or_to_tag(),
        localip: hd(ips),
        localport: 5060,
        upperlayer: nil,
        testapppid: nil
      }

      {:ok, initial_state}
    end
  end

  @impl true
  def handle_call({:sendmsg, msgstr, destip, dest_port}, _from, state) do
    destipstr =
      case SIP.NetUtils.ip2string(destip) do
        {:error, :einval} ->
          Logger.error(
            module: SIP.Test.Transport.UDPMockup,
            message: "sendmsg: invalid destination address #{inspect(destip)}."
          )

          raise "UDPMockup: invalid IP address"

        ipstr when is_binary(ipstr) ->
          ipstr
      end

    Logger.debug(
      "UDPMockup: Message sent to #{destipstr}:#{dest_port} ---->\r\n" <>
        msgstr <> "\r\n-----------------"
    )

    case SIPMsg.parse(msgstr, fn code, errmsg, lineno, line ->
           Logger.error("UDPMockup: failed to parse sent msg:" <> errmsg)
           Logger.debug("UDPMockup: Offending line #{lineno}: #{line}")
           Logger.debug("UDPMockup: Error code #{code}")
         end) do
      {:ok, sipmsg} ->
        case sipmsg.method do
          false ->
            {:reply, :ok, handle_resp(state, sipmsg.response, sipmsg)}

          method ->
            {:reply, :ok, handle_req(state, method, sipmsg)}
        end

      err ->
        Logger.error("UDPMockup: failed to parse sent msg: #{inspect(err)}")
        {:reply, :transporterror, state}
    end
  end

  # Obtain localip and port values
  def handle_call(:getlocalipandport, _from, state) do
    {:reply, {:ok, state.localip, state.localport}, state}
  end

  # Set the upper layer handler for transactions to process
  def handle_call({:setupperlayer, ul_pid}, _from, state) when is_pid(ul_pid) do
    {:reply, :ok, Map.put(state, :upperlayer, ul_pid)}
  end

  def handle_call({:setupperlayer, ul_func}, _from, state) when is_function(ul_func, 2) do
    {:reply, :ok, Map.put(state, :upperlayer, ul_func)}
  end

  def handle_call({:setupperlayer, nil}, _from, state) do
    {:reply, :ok, Map.put(state, :upperlayer, nil)}
  end

  def handle_call(:settestapp, {pid, _ref}, state) do
    {:reply, :ok, Map.put(state, :testapppid, pid)}
  end

  # Simulate call scenario
  @impl true
  @spec handle_cast({:simulate, 100, non_neg_integer()}, map()) :: {:noreply, map()}
  # Simulating an answer before there is anything to answer. It used to raise
  # (`badkey :req`) inside the GenServer, killing the transport instance — which
  # is *shared*, so one mis-ordered test took the following ones down with it.
  # Say so and carry on: the test will fail on its own assertion, which is the
  # failure that names the actual problem.
  def handle_cast({:simulate, code, _after_ms}, state)
      when is_integer(code) and not is_map_key(state, :req) do
    Logger.warning(
      module: SIP.Test.Transport.UDPMockup,
      message: "Asked to simulate a #{code} but no request has been sent yet. Ignoring."
    )

    {:noreply, state}
  end

  def handle_cast({:simulate, 100, after_ms}, state) do
    siprsp = reply_to_request(state.req, 100, "Trying")
    Process.send_after(self(), {:recv, siprsp}, after_ms)
    {:noreply, state}
  end

  def handle_cast({:drop_options, drop}, state) do
    {:noreply, Map.put(state, :drop_options, drop)}
  end

  def handle_cast({:answer_bye, answer}, state) do
    {:noreply, Map.put(state, :answer_bye, answer)}
  end

  def handle_cast({:simulate, scenario}, state) when is_atom(scenario) do
    new_state = Map.put(state, :scenario, scenario)

    case scenario do
      :successfulcall -> handle_cast({:simulate, 100, 200}, new_state)
      :successfulregister -> handle_cast({:simulate, 200, 200}, new_state)
      :busy -> handle_cast({:simulate, 100, 200}, new_state)
      :notregistered -> handle_cast({:simulate, 100, 200}, new_state)
      :challenge -> handle_cast({:simulate, 401, 200}, new_state)
    end
  end

  @spec handle_cast({:simulate, 180, non_neg_integer()}, map()) :: {:noreply, map()}
  def handle_cast({:simulate, 180, after_ms}, state) do
    siprsp = reply_to_request(state.req, 180, "Ringing", [], state.totag)

    Logger.debug(
      transid: state.req.transid,
      module: SIP.Test.Transport.UDPMockup,
      message: "Simulating a 180 Ringing after #{after_ms} ms."
    )

    Process.send_after(self(), {:recv, siprsp}, after_ms)
    {:noreply, state}
  end

  @spec handle_cast({:simulate, 200, non_neg_integer()}, map()) :: {:noreply, map()}
  def handle_cast({:simulate, 200, after_ms}, state) do
    siprsp =
      if state.req.method == :INVITE do
        # invite case
        # Minimal but valid SDP answer so the media layer (ExSDP.parse) accepts it.
        sdp_answer =
          "v=0\r\n" <>
            "o=- 1 1 IN IP4 212.83.152.250\r\n" <>
            "s=-\r\n" <>
            "c=IN IP4 212.83.152.250\r\n" <>
            "t=0 0\r\n" <>
            "m=audio 7344 RTP/AVP 0\r\n" <>
            "a=rtpmap:0 PCMU/8000\r\n"

        sdp_body = %{contenttype: "application/sdp", data: sdp_answer}

        reply_to_request(
          state.req,
          200,
          "OK",
          [body: [sdp_body], contact: "<sip:90901@212.83.152.250:5090>"],
          state.totag
        )
      else
        # register case
        reply_to_request(state.req, 200, "OK", [contact: state.req.contact], state.totag)
      end

    Logger.debug(
      transid: state.req.transid,
      module: SIP.Test.Transport.UDPMockup,
      message: "Simulating a 200 OK after #{after_ms} ms."
    )

    Process.send_after(self(), {:recv, siprsp}, after_ms)
    {:noreply, state}
  end

  @spec handle_cast({:simulate, 401 | 407, non_neg_integer()}, map()) :: {:noreply, map()}
  def handle_cast({:simulate, resp, after_ms}, state) when resp in [401, 407] do
    siprsp =
      SIP.Msg.Ops.challenge_request(
        state.req,
        resp,
        "Digest",
        "elioz.net",
        "SHA256",
        [],
        state.totag
      )

    Logger.debug(
      transid: state.req.transid,
      module: SIP.Test.Transport.UDPMockup,
      message: "Simulating a #{resp} Digest challenge after #{after_ms} ms."
    )

    Process.send_after(self(), {:recv, siprsp}, after_ms)
    {:noreply, state}
  end

  def handle_cast({:simulate, resp, after_ms}, state) when resp in 400..487 do
    siprsp = reply_to_request(state.req, resp, nil, [], state.totag)

    Logger.debug(
      transid: state.req.transid,
      module: SIP.Test.Transport.UDPMockup,
      message: "Simulating a #{resp} Answer #{after_ms} ms."
    )

    Process.send_after(self(), {:recv, siprsp}, after_ms)
    {:noreply, state}
  end

  defp set_inbound_scenario(state, sipreq) when sipreq.method == :REGISTER do
    Map.put(state, :req, sipreq) |> Map.put(:scenario, :inboundregister)
  end

  defp set_inbound_scenario(state, sipreq) when sipreq.method == :INVITE do
    Map.put(state, :req, sipreq) |> Map.put(:scenario, :inboundinvite)
  end

  # Any other inbound method (an OPTIONS, an in-dialog ACK or BYE…): leave the state
  # alone. Claiming a scenario here would overwrite the one in progress — an inbound
  # ACK during a call reset :inboundinvite and the canned call scenario stopped
  # forwarding anything to the test.
  defp set_inbound_scenario(state, sipreq) when is_atom(sipreq.method) do
    state
  end

  @impl true

  # Handle 100 Trying
  def handle_info({:recv, siprsp}, state) when siprsp.response == 100 do
    Logger.debug(
      transid: state.req.transid,
      module: SIP.Test.Transport.UDPMockup,
      message:
        "Received SIP resp #{siprsp.response} scenario #{inspect(Map.get(state, :scenario))}"
    )

    SIP.Transac.process_sip_message(SIPMsg.serialize(siprsp))

    case Map.get(state, :scenario) do
      :successfulcall ->
        # We received the 100 Trying -- simulate a 180 ringing after some time
        GenServer.cast(self(), {:simulate, 180, 200})

      # No canned scenario: the test drives the responses itself.
      nil ->
        :ok

      :notregistered ->
        # answer with 480 Temporary Unavailable
        GenServer.cast(self(), {:simulate, 480, 200})

      :busy ->
        # We received the 100 Trying -- simulate a 180 ringing after some time
        # then simulate 486 Busy sent by the user
        GenServer.cast(self(), {:simulate, 180, 200})

      :noanswer ->
        # We received the 100 Trying -- simulate a 180 ringing after some time
        # then simulate 486 Busy sent by the user
        GenServer.cast(self(), {:simulate, 180, 200})

      _ ->
        Logger.warning(
          module: SIP.Test.Transport.UDPMockup,
          message: "Unidentified SIP scenario #{inspect(Map.get(state, :scenario))}"
        )

        GenServer.cast(self(), {:simulate, 404, 200})
    end

    {:noreply, state}
  end

  # Handle 180 Ringing
  def handle_info({:recv, siprsp}, state) when siprsp.response == 180 do
    Logger.debug(
      transid: state.req.transid,
      module: SIP.Test.Transport.UDPMockup,
      message:
        "Received SIP resp #{siprsp.response} scenario #{inspect(Map.get(state, :scenario))}"
    )

    SIP.Transac.process_sip_message(SIPMsg.serialize(siprsp))

    case Map.get(state, :scenario) do
      :successfulcall ->
        # We received the 180 Ringing -- simulate a 200 OK after some time
        GenServer.cast(self(), {:simulate, 200, 4000})

      :noanswer ->
        GenServer.cast(self(), {:simulate, 408, 2000})

      :busy ->
        GenServer.cast(self(), {:simulate, 486, 2000})

      # No canned scenario: the test drives the responses itself, one
      # `{:simulate, …}` at a time. Reading `state.scenario` directly used to
      # raise here (the key is absent until a scenario is selected), killing the
      # shared instance.
      _ ->
        :ok
    end

    {:noreply, state}
  end

  # Include case with 486, 487
  def handle_info({:recv, siprsp}, state) when is_integer(siprsp.response) do
    Logger.debug(
      transid: state.req.transid,
      module: SIP.Test.Transport.UDPMockup,
      message:
        "Received SIP resp #{siprsp.response} scenario #{inspect(Map.get(state, :scenario))}"
    )

    SIP.Transac.process_sip_message(SIPMsg.serialize(siprsp))

    {:noreply, state}
  end

  def handle_info({:recv, sipreq}, state) when is_atom(sipreq.method) do
    state = set_inbound_scenario(state, sipreq)

    # Map.get, not state.scenario: a method with no canned scenario (an inbound
    # OPTIONS) leaves the key absent, and this log used to raise a KeyError — the
    # mockup died on the message it was asked to deliver.
    Logger.info(
      transid: sipreq.transid,
      module: SIP.Test.Transport.UDPMockup,
      message: "Received SIP #{sipreq.method} in scenario #{inspect(Map.get(state, :scenario))}"
    )

    # Simulate remote IP
    {:ok, ip} = NetUtils.parse_address("82.184.8.2")
    port = 53936

    SIP.Transport.ImplHelpers.process_incoming_message(
      state,
      SIPMsg.serialize(sipreq),
      "UDP",
      __MODULE__,
      {{1, 2, 3, 4}, 5080},
      ip,
      port
    )
  end
end
