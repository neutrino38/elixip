defmodule SIP.Test.Peers.Manual do
  @moduledoc """
  The peer a test drives itself, one message at a time, instead of canning the
  whole flow up front.

  A B2BUA suite asserts on the request the stack forwarded *before* deciding how
  the far end answers it — the assertion is the point of the test — so the
  reaction cannot be a canned scenario installed beforehand. The test waits for
  `{:sip_mockup, {:request_sent, :INVITE, req}}` on the probe, inspects `req`,
  then calls `simulate/3`.

  This peer keeps the last request the stack sent it and builds the answer from
  it, with its own To tag (`SIP.Msg.Ops.generate_from_or_to_tag/0`, drawn per
  instance so two named peers answering a forked INVITE stay distinguishable).

  It inherits `SIP.Test.Peer.default_request/2`, so it answers the OPTIONS
  keepalives (unless `reply_options: false`) and the BYEs on its own. CANCEL is
  honoured with 200 + 487 when it matches the pending INVITE, 481 when there is
  none.
  """
  use SIP.Test.Peer
  require Logger

  alias SIP.Test.Transport.Mockup

  # ── Test-facing API ─────────────────────────────────────────────────────────

  @doc """
  Answer the request in progress with `code` after `after_ms` ms.

  `100` is a bare Trying, `401`/`407` a Digest challenge, `200` an SDP answer on
  an INVITE and a Contact echo on a REGISTER; every other code in 400..699 is a
  plain rejection — a fork test needs a 6xx (RFC 3261 §16.7 stops a hunt on a
  global refusal) as much as a 486.
  """
  @spec simulate(pid(), integer(), non_neg_integer()) :: :ok
  def simulate(t_pid, code, after_ms \\ 100) do
    Mockup.tell_peer(t_pid, {:simulate, code, after_ms})
  end

  @doc """
  Answer the INVITE this peer has already answered and been ACKed for, once more.

  What a callee does with a 2xx it has not seen acknowledged (RFC 3261 §13.3.1.4):
  it sends it again, up to 64*T1, whatever the transport. The stack owes it another
  ACK — from the client transaction alone, since the dialog and the application are
  done with that INVITE.
  """
  @spec retransmit_2xx(pid()) :: :ok
  def retransmit_2xx(t_pid) do
    Mockup.tell_peer(t_pid, :retransmit_2xx)
  end

  @doc """
  Hang up: the BYE this peer sends when the person it stands for goes on-hook,
  delivered inbound like a datagram off the wire.

  Built from the INVITE it answered — its own identity and To tag on From, ours on
  To, our Call-ID — so it lands on the dialog that INVITE established. It is the
  half of the call teardown a canned scenario cannot express: everything there is a
  *response* to a request the stack sent, and a call the far end ends is the other
  direction.
  """
  @spec hangup(pid()) :: :ok
  def hangup(t_pid) do
    Mockup.tell_peer(t_pid, :hangup)
  end

  # ── Peer callbacks ──────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    Map.merge(%{req: nil, acked_req: nil, totag: SIP.Msg.Ops.generate_from_or_to_tag()},
      Map.new(opts))
  end

  @impl true
  def on_request(%{method: method} = req, state) when method in [:INVITE, :REGISTER] do
    {[], %{state | req: req}}
  end

  # The acknowledged INVITE is kept aside for retransmit_2xx/1 to answer once
  # more. It stays in :req as well, so a test that hangs up without asking for a
  # retransmission still answers the call it is in.
  def on_request(%{method: :ACK}, state) do
    case state.req do
      %{method: :INVITE} = invite -> {[], %{state | acked_req: invite}}
      _ -> {[], state}
    end
  end

  # Answering a CANCEL *we* received, i.e. one the stack sent out (a B2BUA
  # cancelling the call attempt it forwarded). Two responses go back: 200 to the
  # CANCEL itself, then 487 to the INVITE it cancels — which is the request the
  # 487 must be built from (RFC 3261 §9.2), not the CANCEL.
  #
  # Both carry a To tag: any response above 100 needs one, and reply_to_request/5
  # raises without it. The CANCEL as sent has no tag on its To (it copies the
  # INVITE's), so the tag has to be supplied here.
  def on_request(%{method: :CANCEL} = req, state) do
    case state.req do
      %{transid: transid} = invite when transid == req.transid ->
        {[reply_as(state.totag, req, 200, "OK", [], 100),
          reply_as(state.totag, invite, 487, nil, [], 200)], state}

      nil ->
        {[reply_as(state.totag, req, 481, "No such transaction", [], 100)], state}

      _ ->
        {[], state}
    end
  end

  def on_request(req, state), do: default_request(req, state)

  @impl true
  def on_command({:simulate, code, _after_ms}, %{req: nil} = state) do
    # Answering before there is anything to answer. Say so and carry on: the test
    # will fail on its own assertion, which is the failure that names the problem.
    Logger.warning(
      module: __MODULE__,
      message: "Asked to simulate a #{code} but no request has been sent yet. Ignoring."
    )

    {[], state}
  end

  def on_command({:simulate, code, after_ms}, state) do
    {[answer(state.req, code, state.totag, after_ms)], state}
  end

  def on_command(:retransmit_2xx, %{acked_req: nil} = state) do
    Logger.warning(
      module: __MODULE__,
      message: "Asked to retransmit a 2xx but no INVITE has been acknowledged yet. Ignoring."
    )

    {[], state}
  end

  def on_command(:retransmit_2xx, state) do
    {[answer(state.acked_req, 200, state.totag, 0)], state}
  end

  def on_command(:hangup, state) do
    case state.acked_req || state.req do
      %{method: :INVITE} = invite ->
        {[{:inject, far_end_bye(invite, state.totag), 0}], state}

      _ ->
        Logger.warning(
          module: __MODULE__,
          message: "Asked to hang up but this peer has answered no INVITE. Ignoring."
        )

        {[], state}
    end
  end

  # ── Internals ───────────────────────────────────────────────────────────────

  # A 100 Trying carries no To tag: none has been assigned yet.
  defp answer(req, 100, _totag, after_ms), do: trying(req, after_ms)

  defp answer(req, code, totag, after_ms) when code in [401, 407] do
    {:inject,
     SIP.Msg.Ops.challenge_request(req, code, "Digest", "elioz.net", "SHA256", [], totag),
     after_ms}
  end

  defp answer(%{method: :INVITE} = req, 200, totag, after_ms) do
    fields = [body: [sdp_answer_body()], contact: remote_contact()]
    reply_as(totag, req, 200, "OK", fields, after_ms)
  end

  defp answer(req, 200, totag, after_ms) do
    reply_as(totag, req, 200, "OK", [contact: req.contact], after_ms)
  end

  defp answer(req, 180, totag, after_ms), do: reply_as(totag, req, 180, "Ringing", [], after_ms)

  defp answer(req, code, totag, after_ms), do: reply_as(totag, req, code, nil, [], after_ms)

  # The BYE that ends the call from this side (RFC 3261 §15.1.1): this peer's
  # identity and tag on From — the To of the INVITE it answered — ours on To with
  # the tag we put there, our Call-ID, and a fresh Via branch, since a BYE is a
  # transaction of its own.
  #
  # The CSeq continues OUR numbering rather than starting a sequence of this peer's
  # own: `SIP.DialogImpl` initialises `cseqin` to 1 instead of to "empty" (RFC 3261
  # §12.2.2), so a first in-dialog request numbered 1 is answered 500 Out of order.
  # This is the numbering every UA seen in traffic uses anyway.
  defp far_end_bye(invite, totag) do
    branch = SIP.Msg.Ops.generate_branch_value()
    [seqno, _method] = invite.cseq
    caller = uri!(invite.from)

    %{
      "Max-Forwards" => "70",
      method: :BYE,
      # A real callee sends it to our Contact; here nothing routes on the
      # Request-URI (a request is matched to its dialog on the tags and the
      # Call-ID), so the caller's own URI is enough and needs no parsed Contact.
      ruri: caller,
      from: SIP.Uri.set_header_param(uri!(invite.to), "tag", totag),
      to: caller,
      useragent: "Mockup-test",
      callid: invite.callid,
      transid: branch,
      cseq: [seqno + 1, :BYE],
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      contentlength: 0
    }
  end

  # The request this peer put aside is the parsed form of what it received, and
  # `SIPMsg.parse/2` leaves From and To as the raw header values they arrived as.
  defp uri!(%SIP.Uri{} = uri), do: uri

  defp uri!(value) when is_binary(value) do
    {:ok, uri} = SIP.Uri.parse(value)
    uri
  end
end
