defmodule SIP.Test.PresenceUAS do
  @moduledoc """
  One scenario instance per inbound presence dialog — what `Elixip.ScenarioUAS`
  will do for `uas :presence` in P6, minus the quota and the counters a test
  suite has no use for.

  A SUBSCRIBE and a PUBLISH both land here and both get an instance of the one
  scenario the test registered: which of the two a scenario serves is decided by
  the states it writes, not by the factory that spawns it.

      SIP.Test.PresenceUAS.serve(MyNotifier)
      SIP.Test.PresenceUAS.serve(MyNotifier, %{granted: 1})

  The scenario to spawn lives in `:persistent_term` rather than in a process of
  its own: `on_new_subscribe/3` runs inside the dialog, and a test fixture that
  can block a dialog is a test fixture that decides timing.
  """

  @behaviour SIP.Session.Presence

  @doc "Serve every inbound SUBSCRIBE and PUBLISH with an instance of `module`."
  @spec serve(module(), map()) :: :ok
  def serve(module, appdata \\ %{}) when is_atom(module) and is_map(appdata) do
    :persistent_term.put({__MODULE__, :scenario}, {module, appdata})
    :ok = SIP.Session.ConfigRegistry.set_presence_processing_module(__MODULE__)
  end

  @impl true
  def on_new_subscribe(dialog_pid, req, _transaction_id), do: spawn_instance(dialog_pid, req)

  @impl true
  def on_new_publish(dialog_pid, req, _transaction_id), do: spawn_instance(dialog_pid, req)

  defp spawn_instance(dialog_pid, req) do
    {module, appdata} = :persistent_term.get({__MODULE__, :scenario})

    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(module,
        dialog_pid: dialog_pid,
        inbound_request: req,
        appdata: appdata
      )

    {:accept, pid}
  end
end
