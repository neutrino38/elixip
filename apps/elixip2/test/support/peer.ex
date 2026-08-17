defmodule SIP.Test.Peer do
  @moduledoc """
  Behaviour implemented by the simulated remote peers driven by the mockup
  transport (`SIP.Test.Transport.Mockup`).

  A peer is the *behaviour* of the fake remote party: which SIP messages it
  sends back, and when. It is pure — callbacks receive a parsed message plus
  the peer state and return **actions**; the transport interprets them
  (schedules the timers, feeds injected messages back into the SIP stack,
  forwards events to the probe). This keeps each canned scenario readable in
  one place (one module per peer, see `SIP.Test.Peers.*`) and unit-testable
  without a GenServer.

  Actions:

    * `{:inject, msg, after_ms}` — deliver `msg` to the local SIP stack after
      `after_ms` ms, as if it had been received from the network;
    * `{:notify, event}` — push `event` to the attached probe
      (see `SIP.Test.Probe`).

  `use SIP.Test.Peer` provides default implementations for all callbacks
  (`init/1` stores the opts, `on_request/2` falls back to `default_request/2`,
  `on_response/2` does nothing). A peer overriding `on_request/2` replaces the
  whole function: end with a catch-all clause delegating to
  `default_request/2` to keep the OPTIONS/BYE defaults.
  """

  # The To tag stamped on every response the peers fabricate.
  @totag "as424e7930"

  # The fake remote media endpoint advertised in 200 OK answers.
  @remote_media_ip "212.83.152.250"

  @type action :: {:inject, map(), non_neg_integer()} | {:notify, term()}

  @doc "Build the peer state from the opts given to `Mockup.set_peer/3`."
  @callback init(opts :: keyword()) :: map()

  @doc "The local stack sent us this request; return the peer's reaction."
  @callback on_request(req :: map(), state :: map()) :: {[action()], map()}

  @doc "The local stack sent us this response; return the peer's reaction."
  @callback on_response(resp :: map(), state :: map()) :: {[action()], map()}

  @doc """
  The test drives this peer at runtime (`Mockup.tell_peer/2`); return its
  reaction. Only peers whose behaviour is not canned up front implement it.
  """
  @callback on_command(cmd :: term(), state :: map()) :: {[action()], map()}

  defmacro __using__(_opts) do
    quote do
      @behaviour SIP.Test.Peer
      import SIP.Test.Peer

      @impl true
      def init(opts), do: Map.new(opts)

      @impl true
      def on_request(req, state), do: SIP.Test.Peer.default_request(req, state)

      @impl true
      def on_response(_resp, state), do: {[], state}

      @impl true
      def on_command(_cmd, state), do: {[], state}

      defoverridable init: 1, on_request: 2, on_response: 2, on_command: 2
    end
  end

  @doc """
  Baseline reaction every peer should fall back to:

    * answer the stack's OPTIONS keepalives with 200 OK — unless the peer was
      created with `reply_options: false`, which simulates a dead peer and
      exercises the missed-keepalive dialog teardown;
    * answer the stack's BYE with 200 OK so the NICT terminates quickly;
    * ignore anything else.
  """
  def default_request(%{method: :OPTIONS} = req, state) do
    if Map.get(state, :reply_options, true) do
      {[reply(req, 200, "OK")], state}
    else
      {[], state}
    end
  end

  def default_request(%{method: :BYE} = req, state) do
    {[reply(req, 200, "OK")], state}
  end

  def default_request(_req, state), do: {[], state}

  # ── Action builders ─────────────────────────────────────────────────────────

  @doc "Reply to `req` with `code` after `after_ms` ms (default 50)."
  @spec reply(map(), integer(), binary() | nil, keyword(), non_neg_integer()) :: action()
  def reply(req, code, reason \\ nil, fields \\ [], after_ms \\ 50) do
    reply_as(@totag, req, code, reason, fields, after_ms)
  end

  @doc """
  Same as `reply/5` with an explicit To tag. A fork test needs one tag per peer:
  two named peers answering the same forked INVITE with the same tag leave
  nothing to tell the branches apart.
  """
  @spec reply_as(binary(), map(), integer(), binary() | nil, keyword(), non_neg_integer()) ::
          action()
  def reply_as(totag, req, code, reason \\ nil, fields \\ [], after_ms \\ 50) do
    {:inject, SIP.Msg.Ops.reply_to_request(req, code, reason, fields, totag), after_ms}
  end

  @doc "A 100 Trying carries no To tag (none has been assigned yet)."
  @spec trying(map(), non_neg_integer()) :: action()
  def trying(req, after_ms \\ 0) do
    {:inject, SIP.Msg.Ops.reply_to_request(req, 100, "Trying"), after_ms}
  end

  @doc "Challenge `req` with a Digest 401/407."
  @spec challenge(map(), 401 | 407, non_neg_integer(), binary()) :: action()
  def challenge(req, code, after_ms \\ 50, realm \\ "elioz.net") do
    {:inject,
     SIP.Msg.Ops.challenge_request(req, code, "Digest", realm, "SHA256", [], @totag), after_ms}
  end

  @doc "Push an event to the probe attached to the transport."
  @spec notify(term()) :: action()
  def notify(event), do: {:notify, event}

  # ── Shared canned message parts ─────────────────────────────────────────────

  @doc "Minimal but valid SDP answer so the media layer (ExSDP.parse) accepts it."
  def sdp_answer_body do
    sdp =
      "v=0\r\n" <>
        "o=- 1 1 IN IP4 #{@remote_media_ip}\r\n" <>
        "s=-\r\n" <>
        "c=IN IP4 #{@remote_media_ip}\r\n" <>
        "t=0 0\r\n" <>
        "m=audio 7344 RTP/AVP 0\r\n" <>
        "a=rtpmap:0 PCMU/8000\r\n"

    %{contenttype: "application/sdp", data: sdp}
  end

  @doc "The Contact the fake remote party advertises in its 200 OK."
  def remote_contact, do: "<sip:90901@#{@remote_media_ip}:5090>"
end
