defmodule Kelix.NonceCache do
  @moduledoc """
  Intra-window anti-replay for `qop=auth` (design §7.2): a bounded, per-node
  soft-state cache of `nonce → max nonce-count (nc) seen`, TTL = the nonce
  `max_age`. A request whose `nc` is ≤ the last seen for that nonce is a replay.

  Losing this on restart is harmless: the in-flight nonces then read `stale` and
  the client replays with a fresh one. Entries older than the TTL are swept
  (a nonce is worthless past `max_age` anyway). Clients without `qop` fall back to
  window-only anti-replay (`max_age` + `stale`), so they never reach here.
  """
  use GenServer

  @default_ttl_ms 60_000

  defstruct table: nil, ttl_ms: @default_ttl_ms

  # id follows :name so several caches can coexist under one supervisor (tests).
  @spec child_spec(keyword) :: Supervisor.child_spec()
  def child_spec(opts),
    do: %{id: Keyword.get(opts, :name, __MODULE__), start: {__MODULE__, :start_link, [opts]}}

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @doc """
  Record `nc` for `nonce` if it advances the count. `:ok` (fresh, recorded) or
  `:replay` (nc ≤ a previously seen value for this nonce). `server` targets a
  specific cache (tests use their own instance with a short TTL).
  """
  @spec check_nc(String.t(), non_neg_integer, GenServer.server()) :: :ok | :replay
  def check_nc(nonce, nc, server \\ __MODULE__) when is_binary(nonce) and is_integer(nc),
    do: GenServer.call(server, {:check, nonce, nc})

  @impl true
  def init(opts) do
    ttl_ms = Keyword.get(opts, :ttl_ms, @default_ttl_ms)
    table = :ets.new(:kelix_nonce_nc, [:set, :private])
    Process.send_after(self(), :sweep, ttl_ms)
    {:ok, %__MODULE__{table: table, ttl_ms: ttl_ms}}
  end

  @impl true
  def handle_call({:check, nonce, nc}, _from, state) do
    reply =
      case :ets.lookup(state.table, nonce) do
        [{^nonce, max, _at}] when nc <= max ->
          :replay

        _ ->
          :ets.insert(state.table, {nonce, nc, mono_ms()})
          :ok
      end

    {:reply, reply, state}
  end

  @impl true
  def handle_info(:sweep, state) do
    cutoff = mono_ms() - state.ttl_ms
    # delete entries whose timestamp (3rd element) is older than the cutoff
    :ets.select_delete(state.table, [{{:_, :_, :"$1"}, [{:<, :"$1", cutoff}], [true]}])
    Process.send_after(self(), :sweep, state.ttl_ms)
    {:noreply, state}
  end

  defp mono_ms(), do: System.monotonic_time(:millisecond)
end
