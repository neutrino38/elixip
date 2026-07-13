defmodule SIP.DialogImpl.KeepAlive do
  @moduledoc """
  OPTIONS keepalive for outbound dialogs (typically REGISTER dialogs).

  Helper module composed into `SIP.DialogImpl`: every function takes the
  dialog state struct and returns an updated one (or a GenServer reply tuple
  for `on_timeout/1`). It owns no process — the timer lives in the dialog
  GenServer and fires `{:timeout, tref, :optionskeepalive}` messages that
  `SIP.DialogImpl.handle_info/2` delegates here.
  """
  require Logger

  # Number of consecutive unanswered OPTIONS keepalives after which the peer is
  # deemed unreachable and the dialog is torn down.
  @max_missed_keepalive 3

  @doc "arm the registration keepalive timer"
  def arm(state = %SIP.DialogImpl{}) do
    if state.keepalivetimer == nil and state.direction == :outbound do
      period = Application.get_env(:elixip2, :optionkeepaliveperiod, 15)

      %SIP.DialogImpl{
        state
        | keepalivetimer: :erlang.start_timer(period * 1000, self(), :optionskeepalive)
      }
    else
      state
    end
  end

  def cancel(state = %SIP.DialogImpl{}) do
    if state.keepalivetimer != nil do
      :erlang.cancel_timer(state.keepalivetimer)
      %SIP.DialogImpl{state | keepalivetimer: nil}
    else
      state
    end
  end

  @doc """
  True when the response answers our own OPTIONS keepalive: the keepalive is
  armed and the response CSeq method is OPTIONS. Used to keep those responses
  dialog-internal instead of forwarding them to the app.
  """
  def response?(%SIP.DialogImpl{keepalivetimer: t}, rsp) when t != nil do
    match?([_, :OPTIONS], rsp.cseq)
  end

  def response?(_state, _rsp), do: false

  @doc """
  Handles the `:optionskeepalive` timer: sends the next keepalive OPTIONS, or
  tears the dialog down once `@max_missed_keepalive` keepalives went
  unanswered. Returns the `{:noreply, _}` / `{:stop, _, _}` tuple expected by
  `handle_info/2`.
  """
  def on_timeout(state = %SIP.DialogImpl{}) do
    if state.missedkeepalive >= @max_missed_keepalive do
      # Peer failed to answer the last @max_missed_keepalive keepalives: consider
      # it unreachable and tear the dialog down. terminate/2 unwraps the
      # {:shutdown, _} reason into {:dialog_terminated, _, :keepalive_timeout}.
      Logger.warning(
        dialogpid: "#{inspect(self())}",
        module: __MODULE__,
        message:
          "Peer unresponsive after #{@max_missed_keepalive} OPTIONS keepalives. Terminating dialog."
      )

      {:stop, {:shutdown, :keepalive_timeout}, state}
    else
      # Clear the fired timer ref so send_keepalive can re-arm a fresh one
      # (arm/1 only arms when keepalivetimer == nil).
      {:noreply, send_keepalive(%SIP.DialogImpl{state | keepalivetimer: nil})}
    end
  end

  def send_keepalive(state = %SIP.DialogImpl{}) do
    msg = %{
      "Accept" => "*/*",
      "Accept-Encoding" => "UTF-8",
      "Accept-Language" => "en",
      "Supported" => "OPTIONS, REGISTER",
      "Max-Forwards" => "70",
      method: :OPTIONS,
      ruri: state.msg.ruri,
      from: state.msg.from,
      to: state.msg.to,
      contact: state.msg.contact,
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }

    case state.state do
      :established ->
        # Send OPTIONS message and count it as pending. The counter is reset to 0
        # when the matching response arrives (see the {:response, ...} handler in
        # SIP.DialogImpl); if it keeps growing, the peer is deemed unreachable and
        # the dialog is torn down (see on_timeout/1).
        {_rc, state} = SIP.DialogImpl.send_in_dialog_request(state, msg)
        state = %SIP.DialogImpl{state | missedkeepalive: state.missedkeepalive + 1}

        # Refresh timer
        arm(state)

      :terminated ->
        # Dialog is dead. Kill timer
        cancel(state)

      _ ->
        state
    end
  end
end
