defmodule SIP.Auth.Secret do
  @moduledoc """
  Holds the server secret keying the stateless digest nonce (`SIP.Auth.Nonce`).

  **Ephemeral, regenerated at boot**: a restart invalidates in-flight nonces
  (⇒ clients get `stale=true` and replay transparently), which is harmless.
  Designed to become a **shared** secret across nodes for HA (roadmap), so any
  node can validate any node's nonce.

  Two ways it comes up, by design:

    * **supervised** — the kelixip server starts it as a root child, and
      `SIP.Scenario.Runner.bootstrap_stack/0` starts it for `elixipp` / `mix
      scenario`. This is the normal case: one secret for the whole node lifetime.
    * **lazily** — `get/0` starts it (unlinked, so it outlives its accidental
      creator) if nobody did. That keeps a challenge from crashing in a bare unit
      test that never bootstrapped the stack; losing the secret only costs a
      `stale` round trip, so soft-starting it is safe.

  Lives in the shared framework — not in kelixip — because `apps/elixipp` depends
  only on `:elixip2`: the nonce facility must be reachable from both artifacts
  (kelixip design §7.1, decision §16.13).
  """
  use Agent
  require Logger

  @secret_bytes 32

  @spec start_link(keyword) :: Agent.on_start()
  def start_link(opts \\ []) do
    Agent.start_link(fn -> secret(opts) end, name: __MODULE__)
  end

  @doc """
  Start the holder unless it already runs — idempotent, for
  `bootstrap_stack/0` (which is itself re-entrant across test files).
  """
  @spec start(keyword) :: :ok
  def start(opts \\ []) do
    case start_link(opts) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end
  end

  @doc "The current server secret (raw bytes)."
  @spec get() :: binary
  def get() do
    case Process.whereis(__MODULE__) do
      nil -> lazy_get()
      pid -> Agent.get(pid, & &1)
    end
  end

  # Unlinked on purpose: the first caller must not own the node's secret.
  defp lazy_get() do
    case Agent.start(fn -> secret([]) end, name: __MODULE__) do
      {:ok, pid} ->
        Logger.debug(
          module: __MODULE__,
          message: "server secret generated on demand (stack not bootstrapped)"
        )

        Agent.get(pid, & &1)

      {:error, {:already_started, pid}} ->
        Agent.get(pid, & &1)
    end
  end

  defp secret(opts),
    do: Keyword.get(opts, :secret) || :crypto.strong_rand_bytes(@secret_bytes)
end
