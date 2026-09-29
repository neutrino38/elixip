defmodule SIP.Dialog.Events do
  @moduledoc """
  The call state of a dialog, read as RFC 4235 reads it, pushed to whoever asked.

  A dialog talks to one process: the application it was created for. Nothing
  else can learn that a call rang, was answered or ended — and the modules that
  want to (call occupancy of an AOR, `docs/design/dialog-state-plan.md`) are not
  the application and must not become it.

  So a dialog **stamped** with a `remote_aor` — the AOR of a served domain its
  far end has been *proven* to be, by the module that proved it — dispatches
  each transition of its call state through `Registry.SIPDialogEvents`. A dialog
  nobody stamped dispatches nothing: on a node relaying trunk-to-trunk traffic
  the cost is one field. Stamping dispatches the current state at once, since
  the inbound stamp arrives from the authentication state, after the INVITE.

  Only INVITE dialogs are read this way; a REGISTER or a SUBSCRIBE has no call
  state to tell.

  The message is `{:sip_dialog, dialog_pid, info}` where `info` is `info/1`'s
  map plus `event`, set on `:terminated` only:

      %{callid, fromtag, totag, direction, method, state, event, remote_aor,
        from, to, ruri, created_at, confirmed_at}

  `state` is `:trying | :proceeding | :early | :confirmed | :terminated` and
  `event` one of RFC 4235 §4.1.4's: `:local_bye`, `:remote_bye`, `:rejected`,
  `:cancelled`, `:timeout`, `:error`. A subscriber that must not miss the end
  of a dialog that crashes monitors its pid: `terminate/2` does not run on a
  kill.
  """

  @registry Registry.SIPDialogEvents
  @key :call_state

  @states [:trying, :proceeding, :early, :confirmed, :terminated]

  @type state :: :trying | :proceeding | :early | :confirmed | :terminated
  @type event :: :local_bye | :remote_bye | :rejected | :cancelled | :timeout | :error | nil

  @doc "The registry name, for `SIP.Dialog.start/0`."
  def registry, do: @registry

  @doc "Receive `{:sip_dialog, pid, info}` for every stamped dialog from now on."
  @spec subscribe() :: :ok
  def subscribe do
    case Registry.register(@registry, @key, nil) do
      {:ok, _} -> :ok
      {:error, {:already_registered, _}} -> :ok
    end
  end

  @spec unsubscribe() :: :ok
  def unsubscribe, do: Registry.unregister(@registry, @key)

  @doc "What a subscriber is told about `state`, the dialog's own state struct."
  def info(state) do
    msg = state.msg || %{}

    %{
      callid: state.callid,
      fromtag: state.fromtag,
      totag: state.totag,
      direction: state.direction,
      method: Map.get(msg, :method),
      state: state.call_state,
      event: state.end_event,
      remote_aor: state.remote_aor,
      from: Map.get(msg, :from),
      to: Map.get(msg, :to),
      ruri: Map.get(msg, :ruri),
      created_at: state.created_at,
      confirmed_at: state.confirmed_at
    }
  end

  @doc """
  Move the dialog's call state to `to` and tell the subscribers.

  A call state only goes forward: a 180 on a re-INVITE does not turn a
  confirmed dialog back into an early one, and a second 2xx does not confirm it
  twice. `:terminated` is always taken, once.
  """
  def transition(state, to) when to in @states do
    if forward?(state.call_state, to) do
      state
      |> Map.put(:call_state, to)
      |> stamp_time(to)
      |> dispatch()
    else
      state
    end
  end

  @doc "Record why the dialog ended, for the `:terminated` push. First reason wins."
  def ended(state, event) when is_atom(event) do
    if state.end_event, do: state, else: Map.put(state, :end_event, event)
  end

  @doc """
  Stamp the dialog with the AOR its far end is proven to be, and push its current
  state so the subscriber starts from where the call is.
  """
  def stamp(state, %SIP.Uri{} = aor) do
    state
    |> Map.put(:remote_aor, aor)
    |> dispatch()
  end

  @doc "Push the current state, if this dialog is one that is being watched."
  def dispatch(state) do
    if state.remote_aor != nil and invite?(state) and Process.whereis(@registry) do
      info = info(state)
      pid = self()

      Registry.dispatch(@registry, @key, fn entries ->
        for {sub, _} <- entries, do: send(sub, {:sip_dialog, pid, info})
      end)
    end

    state
  end

  defp forward?(from, to) do
    Enum.find_index(@states, &(&1 == to)) > Enum.find_index(@states, &(&1 == from))
  end

  defp stamp_time(state, :confirmed), do: Map.put(state, :confirmed_at, DateTime.utc_now())
  defp stamp_time(state, _to), do: state

  defp invite?(%{msg: %{method: :INVITE}}), do: true
  defp invite?(_state), do: false
end
