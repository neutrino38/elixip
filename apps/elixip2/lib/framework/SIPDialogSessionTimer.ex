defmodule SIP.DialogImpl.SessionTimer do
  @moduledoc """
  RFC 4028 session timers, negotiated and kept by the dialog.

  A session timer is a property of ONE dialog: two UAs agree on an interval and
  on which of them refreshes it with a re-INVITE or an UPDATE. A B2BUA is a UA on
  each of its legs, so each leg negotiates its own timer, with its own peer, and
  nothing about it crosses to the other leg (`SIP.Msg.Ops.strip_session_timer/1`).
  That is why it lives here, beside `SIP.DialogImpl.KeepAlive`, and not in the
  B2BUA.

  Helper module composed into `SIP.DialogImpl`: every function takes the dialog
  state struct and returns an updated one. The timers live in the dialog
  GenServer and fire `{:timeout, tref, :session_expired}`.

  ## The UAS side (RFC 4028 §9)

  Every 2xx this dialog sends to an INVITE or an UPDATE — the one that creates
  the session and every refresh after it — carries the negotiated
  `Session-Expires`, and re-arms the timer:

    * a request asking for less than our `min_se` is refused 422 with our
      `Min-SE`, before the application sees it (`too_small/1`);
    * the interval is the one asked for, capped by our `expires`, never below
      either side's floor; with none asked for, our `expires`;
    * the refresher named in the request is kept. A request naming none leaves
      the choice to us (`refresher` in the configuration), and a peer that does
      not support `timer` cannot refresh at all, so we do;
    * when the peer refreshes and lets the interval lapse, the dialog sends a
      BYE (§10) and ends with `{:dialog_terminated, pid, :session_expired}`.

  ## The UAC side (RFC 4028 §7)

  Every INVITE or UPDATE this dialog sends — the one that creates the call and
  every re-offer after it, relayed or not — carries `Supported: timer`, a
  `Session-Expires` and our `Min-SE` (`decorate_request/2`):

    * before any timer is in force, our `expires`, with `refresher=uac` when we
      want to refresh and no refresher when we leave the choice to the far end;
    * once one is, its interval and its refresher, unchanged (§7.4);
    * the 2xx that answers it states the timer in force from then on, or turns
      it off by stating none (§7.2, `on_uac_response/2`);
    * a 422 sends the request again asking for the far end's `Min-SE`, once,
      without the application seeing it (§7.3, `retry_request/2`).

  ## Refreshing (RFC 4028 §10)

  When the refresher is us, the dialog refreshes at half the interval, on its own:
  the request is the dialog's, and neither it nor its answer reaches the
  application.

    * an UPDATE without a body, unless the far end said it takes none; then a
      re-INVITE re-offering our last description unchanged (`local_sdp`). A 405
      or 501 to the UPDATE switches to the re-INVITE for the rest of the call;
    * deferred while an offer exchange is under way on the dialog — it refreshes
      the session too, and crossing it would earn a 491;
    * a 491 retries after the RFC 3261 §14.1 delay, any other refusal well before
      the far end's deadline;
    * a 408 or no answer at all ends the session with a BYE, a 481 ends it
      without one: either way the application is told `:session_expired`.

  ## Configuration

      config :elixip2, :session_timer,
        enabled: false,     # off: no header is added, no timer is armed
        expires: 1800,      # the interval we ask for or accept, in seconds
        min_se: 90,         # the smallest one we accept (RFC 4028 floor: 90)
        refresher: :local   # who refreshes when the peer leaves us the choice:
                            #   :local (we do) or :remote (the peer does)
  """
  require Logger

  alias SIP.Msg.Ops

  @defaults [enabled: false, expires: 1800, min_se: 90, refresher: :local]

  # RFC 4028 §10: the side that does not refresh sends its BYE "slightly before
  # the session expiration", the RECOMMENDED margin being the minimum of 32 s and
  # one third of the interval.
  @max_margin_ms 32_000

  # When the far end is busy with an offer of its own, how long before we look
  # again. A refresh that would cross it is answered 491 anyway.
  @busy_retry_ms 2_000

  # `method` is the request we refresh with: :UPDATE, or :INVITE for a far end
  # that does not take one. `refresh_tid` is the refresh in flight, ours alone.
  defstruct interval: nil,
            refresher: nil,
            method: :UPDATE,
            tref: nil,
            refresh_tid: nil,
            expired: false

  @doc "The session timer configuration, defaults filled in."
  @spec config() :: keyword()
  def config do
    Keyword.merge(@defaults, Application.get_env(:elixip2, :session_timer, []))
  end

  @doc "True when this node negotiates session timers at all."
  @spec enabled?() :: boolean()
  def enabled?, do: config()[:enabled] == true

  @doc """
  Our `Min-SE` when `req` asks for a session interval below it — the request is
  then answered 422 (RFC 4028 §8.1) — or `nil` when there is nothing to refuse.
  """
  @spec too_small(map()) :: pos_integer() | nil
  def too_small(req) when is_map(req) do
    with true <- enabled?(),
         true <- Map.get(req, :method) in [:INVITE, :UPDATE],
         {seconds, _refresher} <- Ops.session_expires(req),
         min_se = config()[:min_se],
         true <- seconds < min_se do
      min_se
    else
      _ -> nil
    end
  end

  @doc "The fields of a 422: the floor the peer has to ask for next time."
  @spec too_small_fields(pos_integer()) :: keyword()
  def too_small_fields(min_se), do: [{"Min-SE", Integer.to_string(min_se)}]

  @doc """
  Decorate a response this dialog is about to send.

  Returns `{fields, negotiated}`: the response fields with `Session-Expires` (and
  `Require: timer` when the peer supports it) added when `resp_code` is a 2xx to
  an INVITE or an UPDATE of a call, and what was negotiated — to be `arm/2`ed
  once the response actually went out — or `nil` when nothing applies.
  """
  @spec decorate_reply(struct(), map(), integer(), term()) ::
          {term(), %__MODULE__{} | nil}
  def decorate_reply(state, req, resp_code, fields)
      when resp_code in 200..299 and (is_list(fields) or is_nil(fields)) do
    if enabled?() and call_dialog?(state) and Map.get(req, :method) in [:INVITE, :UPDATE] do
      negotiated = %{negotiate_as_uas(req) | method: refresh_method(state.session_timer, req)}
      {(fields || []) ++ uas_fields(req, negotiated), negotiated}
    else
      {fields, nil}
    end
  end

  def decorate_reply(_state, _req, _resp_code, fields), do: {fields, nil}

  # RFC 4028 §9, from the request alone. The refresher is stored from OUR side —
  # :local or :remote — since uac/uas name roles in one transaction, and the next
  # refresh may well come the other way.
  defp negotiate_as_uas(req) do
    cfg = config()
    floor = max(Ops.min_se(req) || 0, cfg[:min_se])

    interval =
      case Ops.session_expires(req) do
        {asked, _refresher} -> max(min(asked, cfg[:expires]), floor)
        nil -> max(cfg[:expires], floor)
      end

    refresher =
      cond do
        not peer_supports_timer?(req) -> :local
        match?({_, :uac}, Ops.session_expires(req)) -> :remote
        match?({_, :uas}, Ops.session_expires(req)) -> :local
        cfg[:refresher] == :remote -> :remote
        true -> :local
      end

    %__MODULE__{interval: interval, refresher: refresher}
  end

  defp uas_fields(req, %__MODULE__{interval: interval, refresher: refresher}) do
    # We answer, so we are the UAS of this transaction: refreshing ourselves is
    # `uas`, leaving it to the peer is `uac`.
    role = if refresher == :local, do: "uas", else: "uac"
    session_expires = {"Session-Expires", "#{interval};refresher=#{role}"}

    # RFC 4028 §9: `Require: timer` tells the UAC the session timer is in force.
    # Mandatory when it is the refresher, and only meaningful to a UAC that
    # supports the extension — one that does not would reject the 2xx.
    if peer_supports_timer?(req),
      do: [session_expires, {"Require", "timer"}],
      else: [session_expires]
  end

  defp peer_supports_timer?(req) do
    "timer" in Ops.supported_extensions(req) or "timer" in Ops.required_extensions(req)
  end

  # ── The UAC side (RFC 4028 §7) ──────────────────────────────────────────────

  @doc """
  Decorate an INVITE or an UPDATE this dialog is about to send: `Supported:
  timer`, a `Session-Expires` and our `Min-SE`.

  The interval is the one in force when there is one — every such request is a
  session refresh (§7.4), and it restates the timer with the refresher unchanged,
  named from our side of THIS transaction: `uac` when we refresh. Before any is in
  force it is our `expires`, with `refresher=uac` when we want to refresh and no
  refresher at all when we leave the choice to the far end (§7.1).

  A request that already carries a `Session-Expires` is left alone: whoever built
  it — a test scenario, typically — has stated the timer it wants. A B2BUA never
  hands one over, since the timer of the other leg is stripped on the way
  (`SIP.Msg.Ops.strip_session_timer/1`).
  """
  @spec decorate_request(struct(), map()) :: map()
  def decorate_request(state, req) do
    if enabled?() and Map.get(req, :method) in [:INVITE, :UPDATE] and call_dialog?(state) and
         Ops.session_expires(req) == nil do
      cfg = config()

      {interval, refresher} =
        case state.session_timer do
          %__MODULE__{interval: interval, refresher: :local} -> {interval, "uac"}
          %__MODULE__{interval: interval, refresher: :remote} -> {interval, "uas"}
          _ -> {cfg[:expires], if(cfg[:refresher] == :local, do: "uac")}
        end

      req
      |> add_timer_tag()
      |> put_session_expires(interval, refresher)
      |> Map.put("Min-SE", Integer.to_string(cfg[:min_se]))
    else
      req
    end
  end

  @doc """
  Read the 2xx to an INVITE or an UPDATE we sent (RFC 4028 §7.2): the timer it
  states is the one in force from now on, the refresher named from the far end's
  side of the transaction (`uas` is the far end). A 2xx stating none turns the
  timer off — mid-call included, as §7.2 says.
  """
  @spec on_uac_response(struct(), map()) :: struct()
  def on_uac_response(state, %{response: code, cseq: [_, method]} = rsp)
      when code in 200..299 and method in [:INVITE, :UPDATE] do
    if enabled?() and call_dialog?(state) do
      case Ops.session_expires(rsp) do
        nil ->
          %{cancel(state) | session_timer: nil}

        {interval, refresher} ->
          # `uac` — or nothing, which §9 does not allow a UAS to send. Refreshing a
          # session nobody said who refreshes costs one UPDATE; assuming the far end
          # does costs the call.
          arm(state, %__MODULE__{
            interval: interval,
            refresher: if(refresher == :uas, do: :remote, else: :local),
            method: refresh_method(state.session_timer, rsp)
          })
      end
    else
      state
    end
  end

  def on_uac_response(state, _rsp), do: state

  @doc """
  The request to send again after a 422 to `req` (RFC 4028 §7.3): the same, asking
  for the far end's `Min-SE` as interval and floor. `:none` when the 422 gives
  nothing to retry with — no `Min-SE`, or one we already asked for, which is what
  keeps a peer answering 422 forever from being asked forever.
  """
  @spec retry_request(map(), map()) :: {:ok, map()} | :none
  def retry_request(req, %{response: 422} = rsp) do
    with true <- enabled?(),
         true <- Map.get(req, :method) in [:INVITE, :UPDATE],
         min_se when is_integer(min_se) <- Ops.min_se(rsp),
         asked = Ops.session_expires(req),
         true <- asked == nil or elem(asked, 0) < min_se do
      refresher =
        case asked do
          {_interval, :uac} -> "uac"
          {_interval, :uas} -> "uas"
          _ -> nil
        end

      {:ok,
       req
       |> put_session_expires(min_se, refresher)
       |> drop_headers(["min-se"])
       |> Map.put("Min-SE", Integer.to_string(min_se))}
    else
      _ -> :none
    end
  end

  def retry_request(_req, _rsp), do: :none

  defp put_session_expires(req, interval, refresher) do
    value =
      if refresher,
        do: "#{interval};refresher=#{refresher}",
        else: Integer.to_string(interval)

    req
    |> drop_headers(["session-expires", "x"])
    |> Map.put("Session-Expires", value)
  end

  defp drop_headers(msg, lowercase_names) do
    msg
    |> Map.keys()
    |> Enum.filter(&(is_binary(&1) and String.downcase(&1) in lowercase_names))
    |> then(&Map.drop(msg, &1))
  end

  # `Supported` is parsed to the `:supported` atom as a list; a request built by
  # hand may carry it as a string. Either way `timer` joins what is there.
  defp add_timer_tag(req) do
    cond do
      "timer" in Ops.supported_extensions(req) ->
        req

      is_list(Map.get(req, :supported)) ->
        Map.update!(req, :supported, &(&1 ++ ["timer"]))

      is_binary(Map.get(req, :supported)) ->
        Map.update!(req, :supported, &(&1 <> ", timer"))

      true ->
        case Enum.find(Map.keys(req), &(is_binary(&1) and String.downcase(&1) == "supported")) do
          nil -> Map.put(req, :supported, ["timer"])
          key -> Map.update!(req, key, &(to_string(&1) <> ", timer"))
        end
    end
  end

  # Which request refreshes: an UPDATE — RFC 4028 §9 RECOMMENDS it: no offer, no
  # ACK, nothing for the media to do — unless the far end says it takes none. It
  # sticks: a message without an Allow says nothing new, and a 405 to our UPDATE
  # (`on_refresh_outcome/3`) is a stronger statement than any Allow.
  defp refresh_method(%__MODULE__{method: :INVITE}, _msg), do: :INVITE

  defp refresh_method(prev, msg) do
    case Ops.allowed_methods(msg) do
      nil -> (prev && prev.method) || :UPDATE
      methods -> if "UPDATE" in methods, do: :UPDATE, else: :INVITE
    end
  end

  @doc """
  Put a negotiated session timer in force, replacing the previous one: every 2xx
  to an INVITE or an UPDATE starts a new interval (RFC 4028 §10).

  When we refresh, the refresh is due at half the interval (§10). When the peer
  does, the dialog waits for it until the margin of §10 before the interval ends.
  """
  @spec arm(struct(), %__MODULE__{} | nil) :: struct()
  def arm(state, nil), do: state

  def arm(state, %__MODULE__{} = negotiated) do
    state = cancel(state)

    Logger.debug(
      dialogpid: "#{inspect(self())}",
      module: __MODULE__,
      message:
        "Session timer: #{negotiated.interval} s, refreshed by the #{negotiated.refresher} side"
    )

    tref =
      case negotiated.refresher do
        :remote ->
          :erlang.start_timer(expiry_ms(negotiated.interval), self(), :session_expired)

        :local ->
          :erlang.start_timer(div(negotiated.interval * 1000, 2), self(), :session_refresh)
      end

    %{state | session_timer: %__MODULE__{negotiated | tref: tref}}
  end

  @doc "Stop the running session timer, if any."
  @spec cancel(struct()) :: struct()
  def cancel(%{session_timer: %__MODULE__{tref: tref} = st} = state) when tref != nil do
    :erlang.cancel_timer(tref)
    %{state | session_timer: %__MODULE__{st | tref: nil}}
  end

  def cancel(state), do: state

  defp expiry_ms(interval) do
    ms = interval * 1000
    ms - min(@max_margin_ms, div(ms, 3))
  end

  @doc """
  The peer's refresh did not come. RFC 4028 §10: the session is over, and a BYE
  says so (`end_session/2`).

  A timer that is no longer the current one — re-armed by a refresh whose message
  crossed it — is ignored.
  """
  def on_expired(%{session_timer: %__MODULE__{tref: tref}} = state, tref) when tref != nil do
    end_session(
      clear_tref(state),
      "Session timer expired: no refresh within #{state.session_timer.interval} s."
    )
  end

  def on_expired(state, _stale_tref), do: {:noreply, state}

  @doc """
  End the session on its timer: a BYE goes out (RFC 4028 §10), the dialog ends on
  that BYE's transaction, and `terminate/2` reports `:session_expired`
  (`expired?/1`). Nothing is done on a dialog already closing.

  Returns the `{:noreply, _}` / `{:stop, _, _}` tuple `handle_info/2` expects.
  """
  def end_session(state, why) do
    if state.state == :established and state.closing_transaction == nil do
      Logger.info(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message: why <> " Sending BYE."
      )

      state = state |> mark_expired() |> SIP.Dialog.Events.ended(:timeout)

      case SIP.DialogImpl.send_in_dialog_request(state, expiry_bye()) do
        # Its answer is ours alone: the application never sent this BYE.
        {{:ok, trans_pid}, state} ->
          {:noreply, internal(state, trans_pid)}

        {:already_closing, state} ->
          {:noreply, state}

        {rc, state} ->
          Logger.warning(
            dialogpid: "#{inspect(self())}",
            module: __MODULE__,
            message: "Could not send the session-expiry BYE: #{inspect(rc)}"
          )

          {:stop, {:shutdown, :session_expired}, state}
      end
    else
      {:noreply, state}
    end
  end

  # ── Refreshing (RFC 4028 §7.4, §10) ─────────────────────────────────────────

  @doc """
  Our refresh is due — on the timer `arm/2` set, or `:now` when the previous
  attempt asked for another at once (an UPDATE refused 405: try a re-INVITE).

  The refresh is a request of the dialog's own: its answer never reaches the
  application. One already in flight, or an offer exchange under way on the
  dialog, defers it — what is under way refreshes the session as well if it
  succeeds, and crossing it would be answered 491.
  """
  def on_refresh_due(%{session_timer: %__MODULE__{tref: tref}} = state, tref) when tref != nil,
    do: refresh(clear_tref(state))

  def on_refresh_due(state, :now), do: refresh(state)
  def on_refresh_due(state, _stale_tref), do: {:noreply, state}

  defp refresh(state) do
    st = state.session_timer

    cond do
      not match?(%__MODULE__{refresher: :local}, st) ->
        {:noreply, state}

      state.state != :established or state.closing_transaction != nil ->
        {:noreply, state}

      st.refresh_tid != nil ->
        {:noreply, state}

      offer_in_progress?(state) ->
        {:noreply, rearm_refresh(state, @busy_retry_ms)}

      true ->
        send_refresh(state, st)
    end
  end

  defp send_refresh(state, st) do
    case refresh_request(state, st.method) do
      nil ->
        # A far end that takes no UPDATE, and nothing of ours to re-offer it: there
        # is no lawful refresh left (an offerless re-INVITE would ask the far end
        # for a new offer, which is a renegotiation, not a refresh).
        Logger.warning(
          dialogpid: "#{inspect(self())}",
          module: __MODULE__,
          message:
            "Session refresh impossible: UPDATE not accepted and no SDP of ours to re-offer"
        )

        {:noreply, state}

      req ->
        case SIP.DialogImpl.send_in_dialog_request(state, req) do
          {{:ok, tid}, state} ->
            Logger.debug(
              dialogpid: "#{inspect(self())}",
              module: __MODULE__,
              message: "Session refresh sent (#{req.method})"
            )

            state = internal(state, tid)

            {:noreply,
             %{state | session_timer: %__MODULE__{state.session_timer | refresh_tid: tid}}}

          {rc, state} ->
            Logger.warning(
              dialogpid: "#{inspect(self())}",
              module: __MODULE__,
              message: "Could not send the session refresh: #{inspect(rc)}"
            )

            {:noreply, rearm_refresh(state, retry_ms(st.interval))}
        end
    end
  end

  @doc """
  What the final response to our refresh means for the session (RFC 4028 §10).
  Called for every final response the dialog sees; only the one answering the
  refresh in flight is read.

    * 2xx — refreshed; `on_uac_response/2`, called next, restates the timer;
    * 491 — our refresh crossed the far end's offer: again, after the RFC 3261
      §14.1 delay;
    * 405 / 501 to an UPDATE — the far end does not take one: a re-INVITE now;
    * 408 / 481 — the far end is gone or knows no such call: the session is over.
      A 481 ends the dialog by itself; a 408 still owes the far end a BYE;
    * anything else — a refusal of this request, not of the session: once more,
      well before the far end's own deadline.
  """
  def on_refresh_outcome(
        %{session_timer: %__MODULE__{refresh_tid: tid} = st} = state,
        %{response: code},
        tid
      )
      when is_pid(tid) and code >= 200 do
    state = %{state | session_timer: %__MODULE__{st | refresh_tid: nil}}

    cond do
      code in 200..299 ->
        state

      code == 491 ->
        rearm_refresh(state, 2_100 + :rand.uniform(1_900))

      code in [405, 501] and st.method == :UPDATE ->
        send(self(), {:session_refresh, :now})
        %{state | session_timer: %__MODULE__{state.session_timer | method: :INVITE}}

      code == 481 ->
        mark_expired(state)

      code == 408 ->
        send(self(), :session_refresh_failed)
        state

      true ->
        rearm_refresh(state, retry_ms(st.interval))
    end
  end

  def on_refresh_outcome(state, _rsp, _tid), do: state

  @doc "Our refresh got no answer, or a 408: the far end is gone."
  def on_refresh_failed(state),
    do: end_session(state, "Session refresh unanswered: the far end is gone.")

  @doc "True when `tid` is the refresh in flight."
  def refresh?(%{session_timer: %__MODULE__{refresh_tid: tid}}, tid) when is_pid(tid), do: true
  def refresh?(_state, _tid), do: false

  @doc "The refresh in flight goes on under another transaction (a 422 retry)."
  def move_refresh(%{session_timer: %__MODULE__{refresh_tid: old} = st} = state, old, new)
      when is_pid(old),
      do: %{state | session_timer: %__MODULE__{st | refresh_tid: new}}

  def move_refresh(state, _old, _new), do: state

  @doc """
  Remember the last session description we sent on this dialog: the offer of a
  re-INVITE refresh for a far end that takes no UPDATE. Sending it unchanged —
  same `o=` version — is a refresh that changes nothing (RFC 3264 §8).
  """
  def note_local_sdp(state, sdp) when is_binary(sdp) and sdp != "",
    do: %{state | local_sdp: sdp}

  def note_local_sdp(state, _no_sdp), do: state

  @doc "The same, read off the fields of a response this dialog sent."
  def note_reply_sdp(state, fields) when is_list(fields) do
    case List.keyfind(fields, :body, 0) do
      {:body, body} -> note_local_sdp(state, Ops.sdp_body(%{body: body}))
      nil -> state
    end
  end

  def note_reply_sdp(state, _fields), do: state

  defp offer_in_progress?(state) do
    Enum.any?(state.transactions, fn {pid, entry} ->
      match?(%{req: %{method: m}} when m in [:INVITE, :UPDATE], entry) and Process.alive?(pid)
    end)
  end

  defp refresh_request(_state, :UPDATE), do: in_dialog_request(:UPDATE)

  defp refresh_request(%{local_sdp: sdp}, :INVITE) when is_binary(sdp) do
    in_dialog_request(:INVITE)
    |> Ops.update_sip_msg({:body, [%{contenttype: "application/sdp", data: sdp}]})
  end

  defp refresh_request(_state, :INVITE), do: nil

  defp rearm_refresh(state, ms) do
    state = cancel(state)
    tref = :erlang.start_timer(ms, self(), :session_refresh)
    %{state | session_timer: %__MODULE__{state.session_timer | tref: tref}}
  end

  # Another try before the far end's own deadline: an eighth of the interval puts
  # it at 5/8, ahead of the 2/3 a far end with a short interval hangs up at (§10).
  defp retry_ms(interval), do: min(30_000, max(500, div(interval * 1000, 8)))

  defp clear_tref(%{session_timer: %__MODULE__{} = st} = state),
    do: %{state | session_timer: %__MODULE__{st | tref: nil}}

  defp mark_expired(%{session_timer: %__MODULE__{} = st} = state),
    do: %{state | session_timer: %__MODULE__{st | expired: true}}

  defp mark_expired(state), do: state

  defp internal(state, tid), do: %{state | internal_trans: MapSet.put(state.internal_trans, tid)}

  @doc "True once this dialog has ended its session on an expired timer."
  @spec expired?(struct()) :: boolean()
  def expired?(%{session_timer: %__MODULE__{expired: expired}}), do: expired
  def expired?(_state), do: false

  defp call_dialog?(%{msg: %{method: :INVITE}}), do: true
  defp call_dialog?(_state), do: false

  # The Reason is the one browsers use for the same event (JsSIP), so either end
  # of a capture reads the same way.
  defp expiry_bye do
    Map.put(in_dialog_request(:BYE), "Reason", "SIP ;cause=408 ;text=\"Session Timer Expired\"")
  end

  # Every addressing field is a placeholder: `send_in_dialog_request/2` fills in
  # Call-ID, CSeq, both identities and their tags, the route set and the remote
  # target, and the transaction stamps our Contact.
  defp in_dialog_request(method) do
    uri = %SIP.Uri{userpart: nil, domain: nil}

    %{
      "Max-Forwards" => "70",
      method: method,
      ruri: uri,
      from: uri,
      to: uri,
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }
  end
end
