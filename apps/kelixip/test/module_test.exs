defmodule Kelix.ModuleTest do
  # Kelix.Module.safe_call/3 — the non-blocking facade helper (design §8.2).
  use ExUnit.Case, async: false

  # a trivial service: :ping → :pong, {:sleep, ms} → blocks the caller past timeout
  defmodule Svc do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)
    @impl true
    def init(_), do: {:ok, nil}
    @impl true
    def handle_call(:ping, _from, s), do: {:reply, :pong, s}
    def handle_call({:sleep, ms}, _from, s), do: Process.sleep(ms) && {:reply, :slept, s}
  end

  describe "safe_call/3" do
    test "a down service yields {:error, :down} — never raises" do
      assert Kelix.Module.safe_call(Svc, :ping) == {:error, :down}
    end

    test "a running service returns its reply" do
      start_supervised!(Svc)
      assert Kelix.Module.safe_call(Svc, :ping) == :pong
    end

    test "a slow service is bounded and yields {:error, :timeout}" do
      start_supervised!(Svc)
      assert Kelix.Module.safe_call(Svc, {:sleep, 200}, timeout: 20) == {:error, :timeout}
    end

    test "an explicit timeout overrides the default" do
      start_supervised!(Svc)
      # comfortably under the sleep-free ping: succeeds
      assert Kelix.Module.safe_call(Svc, :ping, timeout: 1_000) == :pong
    end
  end
end
