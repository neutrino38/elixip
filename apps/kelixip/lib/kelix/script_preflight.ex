defmodule Kelix.ScriptPreflight do
  @moduledoc """
  Boot-time proof that every script `domains.toml` refers to is actually servable
  (design §3.2, §5.3): present under `script_dir`, compiling, a valid scenario,
  shutdown-aware, and with its declared `uses_modules` loaded.

  A `:ignore` child like `Kelix.Router` — it runs no process. Its **place** in the
  tree is the whole point: after `Kelix.ModuleSupervisor` (a script's `uses_modules`
  can only be resolved once the modules are loaded, and the modules come from this
  same file, so the snapshot must exist first) and before `Kelix.Listener.Supervisor`
  (nothing may arrive on a config we already know is broken).

  A rejected script **aborts the boot**: the alternative is a server that starts
  fine and then answers every call routed to that domain with a `500`, discovered
  one call at a time — the failure this whole check exists to kill (§5.3 wants the
  contract applied "at boot **and** at every reload"; the reload half is
  `Kelix.Control.reload_domains/0`).

  Nothing to check — no `domains.toml` (elixipp, the test suite, a bare release), or
  a file that enables no function — is a silent `:ignore`.
  """
  require Logger

  @spec child_spec(term) :: Supervisor.child_spec()
  def child_spec(_opts), do: %{id: __MODULE__, start: {__MODULE__, :run, []}, type: :worker}

  @doc """
  Contract-check the current snapshot's scripts. `:ignore` when they all pass,
  `{:error, {:invalid_scripts, message}}` otherwise — which fails this child's start
  and therefore the whole boot.
  """
  @spec run() :: :ignore | {:error, {:invalid_scripts, String.t()}}
  def run() do
    case Kelix.Domains.check_scripts(Kelix.Domains.current()) do
      :ok ->
        :ignore

      {:error, message} ->
        # A release dying during boot flushes no Logger output, so state the reason
        # on stderr for journald too (same as Kelix.Config / Kelix.Domains).
        IO.puts(:stderr, "kelixip: unservable domains.toml — #{message}")
        Logger.error(module: __MODULE__, message: "unservable domains.toml — #{message}")
        {:error, {:invalid_scripts, message}}
    end
  end
end
