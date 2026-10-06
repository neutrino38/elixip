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

  defstruct interval: nil, refresher: nil, tref: nil, expired: false

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
      negotiated = negotiate_as_uas(req)
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

        {interval, :uas} ->
          arm(state, %__MODULE__{interval: interval, refresher: :remote})

        # `uac` — or nothing, which §9 does not allow a UAS to send. Refreshing a
        # session nobody said who refreshes costs one UPDATE; assuming the far end
        # does costs the call.
        {interval, _uac} ->
          arm(state, %__MODULE__{interval: interval, refresher: :local})
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

  @doc """
  Put a negotiated session timer in force, replacing the previous one: every 2xx
  to an INVITE or an UPDATE starts a new interval (RFC 4028 §10).

  When the peer refreshes, the dialog waits for that refresh until the margin of
  §10 before the interval ends.
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
          nil
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
  says so. The dialog ends on that BYE's transaction, and `terminate/2` reports
  `:session_expired` (`expired?/1`).

  Returns the `{:noreply, _}` / `{:stop, _, _}` tuple `handle_info/2` expects. A
  timer that is no longer the current one — re-armed by a refresh whose message
  crossed it — is ignored, and so is one firing on a dialog already closing.
  """
  def on_expired(%{session_timer: %__MODULE__{tref: tref}} = state, tref)
      when tref != nil do
    if state.state == :established and state.closing_transaction == nil do
      Logger.info(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message:
          "Session timer expired: no refresh within #{state.session_timer.interval} s. " <>
            "Sending BYE."
      )

      state =
        %{state | session_timer: %__MODULE__{state.session_timer | tref: nil, expired: true}}
        |> SIP.Dialog.Events.ended(:timeout)

      case SIP.DialogImpl.send_in_dialog_request(state, expiry_bye()) do
        # Its answer is ours alone: the application never sent this BYE.
        {{:ok, trans_pid}, state} ->
          {:noreply, %{state | internal_trans: MapSet.put(state.internal_trans, trans_pid)}}

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

  def on_expired(state, _stale_tref), do: {:noreply, state}

  @doc "True once this dialog has ended its session on an expired timer."
  @spec expired?(struct()) :: boolean()
  def expired?(%{session_timer: %__MODULE__{expired: expired}}), do: expired
  def expired?(_state), do: false

  defp call_dialog?(%{msg: %{method: :INVITE}}), do: true
  defp call_dialog?(_state), do: false

  # Every addressing field is a placeholder: `send_in_dialog_request/2` fills in
  # Call-ID, CSeq, both identities and their tags, the route set and the remote
  # target. The Reason is the one browsers use for the same event (JsSIP), so
  # either end of a capture reads the same way.
  defp expiry_bye do
    uri = %SIP.Uri{userpart: nil, domain: nil}

    %{
      "Max-Forwards" => "70",
      "Reason" => "SIP ;cause=408 ;text=\"Session Timer Expired\"",
      method: :BYE,
      ruri: uri,
      from: uri,
      to: uri,
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }
  end
end
