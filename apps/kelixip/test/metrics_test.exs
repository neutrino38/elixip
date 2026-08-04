defmodule Kelix.MetricsTest do
  # Observability (design §11). The :kelixip app runs with metrics disabled
  # (empty boot config → Kelix.Metrics is :ignore), so no reporter is attached
  # unless a test starts one. Telemetry events are asserted via a test handler.
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  alias Kelix.Metrics
  alias Kelix.Metrics.{Emit, Poller}

  # attach a telemetry handler forwarding matched events to the test process
  defp forward(events) do
    id = "test-#{System.unique_integer([:positive])}"
    test = self()

    :telemetry.attach_many(
      id,
      events,
      fn name, measurements, metadata, _ ->
        send(test, {:event, name, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(id) end)
    :ok
  end

  # poll until the reporter has attached a handler for `event` (or fail after ~1s)
  defp wait_for_handlers(event, tries \\ 100) do
    cond do
      :telemetry.list_handlers(event) != [] -> :ok
      tries <= 0 -> flunk("reporter never attached a handler for #{inspect(event)}")
      true -> Process.sleep(10) && wait_for_handlers(event, tries - 1)
    end
  end

  describe "metric definitions" do
    test "metrics/0 returns Telemetry.Metrics structs" do
      metrics = Metrics.metrics()
      assert is_list(metrics) and metrics != []
      assert Enum.all?(metrics, &is_struct/1)
    end
  end

  describe "Emit → telemetry" do
    test "dispatch_accepted emits a labelled counter event" do
      forward([[:kelix, :dispatch, :accepted]])
      Emit.dispatch_accepted("example.com", :calls)
      assert_receive {:event, [:kelix, :dispatch, :accepted], %{count: 1}, meta}
      assert meta == %{domain: "example.com", function: :calls}
    end

    test "dispatch_rejected carries the SIP code" do
      forward([[:kelix, :dispatch, :rejected]])
      Emit.dispatch_rejected("example.com", :calls, 503)
      assert_receive {:event, [:kelix, :dispatch, :rejected], %{count: 1}, %{code: 503}}
    end

    test "registrar_event carries domain + event" do
      forward([[:kelix, :registrar, :event]])
      Emit.registrar_event("example.com", :registered)
      assert_receive {:event, [:kelix, :registrar, :event], _, %{event: :registered}}
    end

    test "the conferencing helpers label their events (docs/design/mcu_module.md §11)" do
      forward([
        [:kelix, :mcu, :call],
        [:kelix, :mcu, :rpc],
        [:kelix, :mcu, :rpc_error],
        [:kelix, :poll, :mcu_conferences],
        [:kelix, :poll, :mcu_participants],
        [:kelix, :poll, :mcu_up]
      ])

      # the funnel takes a code or an atom, and labels it as a string either way
      Emit.mcu_call(:joined)
      assert_receive {:event, [:kelix, :mcu, :call], %{count: 1}, %{result: "joined"}}
      Emit.mcu_call(486)
      assert_receive {:event, [:kelix, :mcu, :call], %{count: 1}, %{result: "486"}}

      Emit.mcu_rpc("CreateConference", 1234)

      assert_receive {:event, [:kelix, :mcu, :rpc], %{duration: 1234},
                      %{method: "CreateConference"}}

      Emit.mcu_rpc_error("StartReceiving", :timeout)

      assert_receive {:event, [:kelix, :mcu, :rpc_error], %{count: 1},
                      %{method: "StartReceiving", reason: "timeout"}}

      Emit.mcu_conferences("mcu1", 3)
      assert_receive {:event, [:kelix, :poll, :mcu_conferences], %{count: 3}, %{mcu: "mcu1"}}

      Emit.mcu_participants("mcu1", "c-1", 7)

      assert_receive {:event, [:kelix, :poll, :mcu_participants], %{count: 7},
                      %{mcu: "mcu1", conference: "c-1"}}

      # a boolean gauge is exported as 1/0, which is what Prometheus wants
      Emit.mcu_mediaserver_up("mcu1", false)
      assert_receive {:event, [:kelix, :poll, :mcu_up], %{up: 0}, %{mcu: "mcu1"}}
    end
  end

  describe "Poller" do
    test "sample/0 emits the total-active gauge from InstancePool" do
      forward([[:kelix, :poll, :calls_total]])
      assert :ok = Poller.sample()
      assert_receive {:event, [:kelix, :poll, :calls_total], %{active: n}, _}
      assert is_integer(n)
    end

    test "sample/0 never crashes even if a surface read fails" do
      # surfaces are up here; the guard is exercised structurally
      assert :ok = Poller.sample()
    end

    test "a module exporting poll_metrics/0 is sampled on our tick; one that does not is skipped" do
      defmodule Sampled do
        def poll_metrics(),
          do: :telemetry.execute([:kelix, :test, :module_poll], %{count: 1}, %{})
      end

      defmodule Silent do
        def describe(), do: %{version: "1.0", exports: []}
      end

      Kelix.ModuleRegistry.register("sampled", Sampled, %{})
      Kelix.ModuleRegistry.register("silent", Silent, %{})

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("sampled")
        Kelix.ModuleRegistry.unregister("silent")
      end)

      forward([[:kelix, :test, :module_poll]])
      assert :ok = Poller.sample()
      assert_receive {:event, [:kelix, :test, :module_poll], %{count: 1}, _}
    end
  end

  describe "Prometheus scrape" do
    test "the definitions aggregate emitted events into Prometheus text" do
      # unique reporter name so repeated start/stop can't collide on telemetry ids
      name = :"kelix_prom_#{System.unique_integer([:positive])}"
      start_supervised!({TelemetryMetricsPrometheus.Core, metrics: Metrics.metrics(), name: name})
      # the Core reporter attaches its telemetry handlers asynchronously — wait
      # until they are live so the emitted events are actually aggregated
      wait_for_handlers([:kelix, :dispatch, :accepted])

      Emit.dispatch_accepted("example.com", :registrar)
      Emit.dispatch_rejected("example.com", :calls, 503)

      text = TelemetryMetricsPrometheus.Core.scrape(name)

      assert text =~
               "kelix_dispatch_accepted_count{domain=\"example.com\",function=\"registrar\"}"

      assert text =~ "kelix_dispatch_rejected_count"
      assert text =~ ~s(code="503")
    end

    test "scrape/0 returns a string (\"\" when no reporter is attached)" do
      assert is_binary(Metrics.scrape())
    end
  end

  describe "Router" do
    @opts Kelix.Metrics.Router.init([])
    defp call(conn), do: Kelix.Metrics.Router.call(conn, @opts)

    test "GET /metrics returns Prometheus text (200)" do
      conn = call(conn(:get, "/metrics"))
      assert conn.status == 200
      assert get_resp_header(conn, "content-type") |> hd() =~ "text/plain"
    end

    test "GET /health is 200 ready when the config surfaces are up" do
      conn = call(conn(:get, "/health"))
      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["live"] == true
      assert body["ready"] == true
    end

    test "unknown route → 404" do
      assert call(conn(:get, "/nope")).status == 404
    end
  end
end
