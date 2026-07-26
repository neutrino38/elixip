defmodule Kelix.Secret do
  @moduledoc """
  Holds the server secret keying the stateless nonce (design §7.1, §11.1).

  **Ephemeral, regenerated at boot** in basic scope — a restart invalidates
  in-flight nonces (⇒ clients get `stale=true` and replay transparently), which
  is harmless. Designed to become a **shared** secret across nodes for HA
  (roadmap), so any node can validate any node's nonce.
  """
  use Agent

  @secret_bytes 32

  @spec start_link(keyword) :: Agent.on_start()
  def start_link(opts \\ []) do
    secret = Keyword.get(opts, :secret) || :crypto.strong_rand_bytes(@secret_bytes)
    Agent.start_link(fn -> secret end, name: __MODULE__)
  end

  @doc "The current server secret (raw bytes)."
  @spec get() :: binary
  def get(), do: Agent.get(__MODULE__, & &1)
end
