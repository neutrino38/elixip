defmodule SIP.Test.Peers.NotifyingUAS do
  @moduledoc """
  A notifier: it accepts a SUBSCRIBE and then sends NOTIFYs.

  What it is for, and what no canned peer could do before it: everything a
  watcher has to live with arrives as a **request** from the far end, not as an
  answer to one of ours. A 200 to a SUBSCRIBE says almost nothing; the
  subscription is what the NOTIFYs that follow say it is.

  Options:

    * `granted` — the lifetime it grants, in seconds (default: whatever the
      SUBSCRIBE asked for). A notifier granting less than it was asked is the
      ordinary case, and it is what the watcher must arm its refresh on;
    * `notify_first: true` — the first NOTIFY leaves **before** the 200 to the
      SUBSCRIBE it belongs to. RFC 6665 §4.2.1.2 forbids it and UDP produces it
      anyway, which is the whole point: the watcher's dialog is then still
      registered without a remote tag, and a NOTIFY it cannot match is answered
      481 — after which the notifier gives up and the subscription is
      established on one side only;
    * `event` — the package name it writes in `Event` (default `"dummy"`);
    * `body` — what the first NOTIFY carries (default `"open"`);
    * `reply_delay` / `notify_delay` — in ms.

  Driven at runtime with `Mockup.tell_peer/2`: `{:notify, body}` for one more
  state change, `:terminate` for the final NOTIFY.
  """
  use SIP.Test.Peer
  require Logger

  alias SIP.Test.Transport.Mockup

  @totag "as9f3d1c07"

  # ── Test-facing API ─────────────────────────────────────────────────────────

  @doc "Send one more NOTIFY carrying `body`, as a state change would."
  @spec send_notify(pid(), binary()) :: :ok
  def send_notify(t_pid, body), do: Mockup.tell_peer(t_pid, {:notify_state, body})

  @doc """
  End the subscription: a NOTIFY carrying
  `Subscription-State: terminated;reason=<reason>` and no body.

  This is what actually ends a subscription on the watcher's side — not the 200
  to an un-SUBSCRIBE, which only acknowledges the request.
  """
  @spec terminate(pid(), atom()) :: :ok
  def terminate(t_pid, reason \\ :timeout), do: Mockup.tell_peer(t_pid, {:terminate, reason})

  # ── Peer callbacks ──────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    Map.merge(
      %{
        reply_delay: 50,
        notify_delay: 60,
        event: "dummy",
        body: "open",
        granted: nil,
        notify_first: false,
        sub: nil,
        cseq: 0,
        totag: @totag
      },
      Map.new(opts)
    )
  end

  @impl true
  def on_request(%{method: :SUBSCRIBE} = req, state) do
    granted = granted_expires(req, state)
    state = %{state | sub: req}

    answer = reply_as(state.totag, req, 200, "OK", [expires: granted], state.reply_delay)

    {first_notify, state} =
      if granted > 0 do
        notify_action(state, state.body, :active, granted, state.notify_delay)
      else
        # `Expires: 0` is an un-subscribe: the 200 acknowledges it and the final
        # NOTIFY is what ends it (RFC 6665 §4.4.4).
        notify_action(state, nil, {:terminated, :timeout}, 0, state.notify_delay)
      end

    # The race, on purpose: the NOTIFY overtakes the 200 it belongs to. Ordering
    # is by the delay the transport schedules, so sending it first means giving it
    # the shorter one.
    if state.notify_first do
      {[shift(first_notify, 0), shift(answer, state.reply_delay)], state}
    else
      {[answer, first_notify], state}
    end
  end

  def on_request(req, state), do: default_request(req, state)

  @impl true
  def on_command({:notify_state, body}, %{sub: nil} = state) do
    Logger.warning(
      module: __MODULE__,
      message: "Asked to NOTIFY but no SUBSCRIBE has been accepted yet. Ignoring."
    )

    _ = body
    {[], state}
  end

  def on_command({:notify_state, body}, state) do
    {action, state} = notify_action(state, body, :active, 60, 0)
    {[action], state}
  end

  def on_command({:terminate, reason}, %{sub: nil} = state) do
    _ = reason
    {[], state}
  end

  def on_command({:terminate, reason}, state) do
    {action, state} = notify_action(state, nil, {:terminated, reason}, 0, 0)
    {[action], state}
  end

  # ── Internals ───────────────────────────────────────────────────────────────

  # What this notifier grants: what it was configured to, else what was asked for.
  # Read through the framework's own reading — a peer that parsed `Expires` its own
  # way would be testing its own parser.
  defp granted_expires(req, state) do
    requested = SIP.Msg.Ops.subscription_expires(req, 60)
    if is_integer(state.granted), do: min(state.granted, requested), else: requested
  end

  defp shift({:inject, msg, _after_ms}, after_ms), do: {:inject, msg, after_ms}

  # The NOTIFY as it comes off the wire: this peer's identity and tag on From —
  # the To of the SUBSCRIBE it answered — the watcher's on To with the tag it
  # chose, its Call-ID, and a CSeq sequence of this peer's own (RFC 6665 §4.4.1:
  # a NOTIFY is a new transaction inside the dialog, numbered by whoever sends it).
  defp notify_action(state, body, substate, expires, after_ms) do
    cseq = state.cseq + 1
    branch = SIP.Msg.Ops.generate_branch_value()
    watcher = uri!(state.sub.from)

    req =
      %{
        "Max-Forwards" => "70",
        method: :NOTIFY,
        ruri: watcher,
        from: SIP.Uri.set_header_param(uri!(state.sub.to), "tag", state.totag),
        to: watcher,
        event: state.event,
        subscriptionstate: substate_value(substate, expires),
        useragent: "Mockup-notifier",
        callid: state.sub.callid,
        transid: branch,
        cseq: [cseq, :NOTIFY],
        via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
        contentlength: 0
      }
      |> put_body(body)

    {{:inject, req, after_ms}, %{state | cseq: cseq}}
  end

  defp substate_value(:active, expires),
    do: SIP.Msg.Ops.subscription_state_value(:active, expires: expires)

  defp substate_value({:terminated, reason}, _expires),
    do: SIP.Msg.Ops.subscription_state_value(:terminated, reason: reason)

  defp put_body(req, nil), do: req

  defp put_body(req, body) do
    req
    |> SIP.Msg.Ops.update_sip_msg({:body, body})
    |> Map.put(:contenttype, "text/plain")
  end

  # The SUBSCRIBE this peer put aside is the parsed form of what it received, and
  # `SIPMsg.parse/2` leaves From and To as the raw header values they arrived as.
  defp uri!(%SIP.Uri{} = uri), do: uri

  defp uri!(value) when is_binary(value) do
    {:ok, uri} = SIP.Uri.parse(value)
    uri
  end
end
