defmodule Kelix.Mod.SiloTest do
  @moduledoc """
  The Silo above its storage (chat-basic-plan C6): configuration, retention,
  quotas, and the flush end to end — each device a `SIP.Test.Transport.Mockup`
  instance of its own (`;unittest=bob-phone`…) behind a peer answering each
  MESSAGE as the test says. The storage is the in-memory store, which honours
  the contract the SQL one is tested against.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mod.Silo
  alias Kelix.Test.SiloMemoryStore, as: Memory
  alias SIP.Test.Transport.Mockup

  @test_name :silo_test

  # ── Fixtures ────────────────────────────────────────────────────────────────

  defmodule Device do
    @moduledoc """
    A device answering its n-th MESSAGE with `codes[n]`, else `code`; after
    `delays[n]` ms, else at once. Reports every MESSAGE to the test.
    """
    use SIP.Test.Peer

    @impl true
    def init(opts), do: opts |> Map.new() |> Map.put_new(:seen, 0)

    @impl true
    def on_request(%{method: :MESSAGE} = req, state) do
      n = state.seen + 1
      send(:silo_test, {:device_got, state.name, req})
      code = Map.get(Map.get(state, :codes, %{}), n, Map.get(state, :code, 200))
      delay = Map.get(Map.get(state, :delays, %{}), n, 0)
      {[reply(req, code, "Answer", [], delay)], %{state | seen: n}}
    end

    def on_request(req, state), do: default_request(req, state)
  end

  setup_all do
    :ok = SIP.Scenario.start_stack()
    :ok
  end

  setup context do
    Process.register(self(), @test_name)
    {:ok, store} = Memory.start_link(schema: Map.get(context, :schema, :ok))

    start_supervised!({Task.Supervisor, name: Kelix.Mod.Silo.Tasks})

    opts = [
      store: Memory,
      handle: store,
      defaults: Map.merge(defaults(), Map.get(context, :defaults, %{})),
      lease: 5,
      page_timeout: 3,
      retry_ms: 50,
      sweep_ms: 3_600_000
    ]

    if context[:no_service] do
      %{store: store, opts: opts}
    else
      start_supervised!(%{id: Silo, start: {Silo, :start_link, [opts]}})
      %{store: store, opts: opts}
    end
  end

  defp defaults,
    do: %{retention: 600, max_retention: 3_600, max_messages: 20, max_bytes: 10_000}

  defp ctx, do: %SIP.Context{domain: "unit.test"}

  defp uri(s) do
    {:ok, u} = SIP.Uri.parse(s)
    u
  end

  defp message(body, extra \\ %{}) do
    Map.merge(
      %{
        "Subject" => "weekend",
        "X-Not-Kept" => "dropped",
        method: :MESSAGE,
        ruri: uri("sip:bob@unit.test"),
        from: "\"Alice\" <sip:alice@unit.test>;tag=a1",
        to: "<sip:bob@unit.test>",
        contenttype: "text/plain;charset=UTF-8",
        body: body
      },
      extra
    )
  end

  # A device of Bob's: its Mockup instance, its peer, and the Contact it
  # registers with. `from` changes the address, as a re-registration from a
  # new network does, keeping the instance ID.
  defp device(name, opts \\ [], from \\ nil) do
    host = from || "#{name}.unit.test"
    contact = "<sip:bob@#{host};unittest=bob-#{name}>;+sip.instance=\"<urn:uuid:#{name}>\""

    :ok =
      Mockup.set_peer(
        Mockup.instance!("sip:bob@#{host};unittest=bob-#{name}"),
        Device,
        [name: name] ++ opts
      )

    contact
  end

  defp register(contacts) do
    %{
      method: :REGISTER,
      ruri: uri("sip:unit.test"),
      to: "<sip:bob@unit.test>",
      from: "<sip:bob@unit.test>;tag=r1",
      contact: Enum.map(List.wrap(contacts), &uri/1),
      expires: "600"
    }
  end

  defp store!(body, opts \\ []) do
    assert {:stored, %{id: id}} = Silo.store(ctx(), message(body), opts)
    id
  end

  defp received(name, n, timeout \\ 3_000) do
    for _ <- 1..n//1 do
      assert_receive {:device_got, ^name, req}, timeout
      req
    end
  end

  defp bodies(reqs), do: Enum.map(reqs, &SIP.Msg.Ops.body_string/1)

  # ── Configuration ──────────────────────────────────────────────────────────

  describe "validate_config/1" do
    @block %{
      "driver" => "postgres",
      "host" => "db.example.net",
      "database" => "kelixip_silo",
      "username" => "silo",
      "lease" => 120,
      "defaults" => %{"retention" => 3_600, "max_retention" => 86_400, "max_messages" => 50}
    }

    test "a complete block" do
      assert Silo.validate_config(@block) == :ok
    end

    test "a typo, in the block or in its defaults, is refused" do
      assert {:error, msg} = Silo.validate_config(Map.put(@block, "retenion", 1))
      assert msg =~ "retenion"

      assert {:error, msg} = Silo.validate_config(put_in(@block, ["defaults", "max_mesages"], 1))
      assert msg =~ "max_mesages"
    end

    test "a default retention above the cap is refused" do
      block = put_in(@block, ["defaults", "retention"], 100_000)
      assert {:error, msg} = Silo.validate_config(block)
      assert msg =~ "max_retention"
    end

    test "the account is required, and a cleartext link confirmed" do
      assert {:error, msg} = Silo.validate_config(Map.delete(@block, "username"))
      assert msg =~ "username"

      assert {:error, msg} = Silo.validate_config(Map.put(@block, "ssl", false))
      assert msg =~ "CLEARTEXT"
    end
  end

  describe "granted_retention/3 and within_quota/3" do
    test "the sender's lifetime, else the script's, else the default — capped" do
      d = defaults()

      assert Silo.granted_retention(message("x", %{expires: "120"}), [retention: 30], d) ==
               {:ok, 120}

      assert Silo.granted_retention(message("x"), [retention: 30], d) == {:ok, 30}
      assert Silo.granted_retention(message("x"), [], d) == {:ok, 600}
      assert Silo.granted_retention(message("x", %{expires: "999999"}), [], d) == {:ok, 3_600}
    end

    test "a content the sender gave no lifetime is not kept" do
      assert Silo.granted_retention(message("x", %{expires: "0"}), [], defaults()) ==
               {:error, :expired}
    end

    test "count and size, each against its own bound" do
      d = defaults()
      assert Silo.within_quota(%{count: 19, bytes: 0}, 10, d) == :ok
      assert Silo.within_quota(%{count: 20, bytes: 0}, 10, d) == {:error, :quota}
      assert Silo.within_quota(%{count: 0, bytes: 9_995}, 10, d) == {:error, :quota}
    end
  end

  # ── store/3 ────────────────────────────────────────────────────────────────

  describe "store/3" do
    test "keeps what delivery rebuilds from, and nothing else", %{store: store} do
      assert {:stored, %{id: id, expires_in: 600}} =
               Silo.store(ctx(), message("Rendez-vous jeudi"), served: ["urn:uuid:desk"])

      {:ok, [m], 0} = Memory.claim(store, "unit.test", "bob", "t", now(), now() + 10)
      assert m.id == id
      assert m.body == "Rendez-vous jeudi"
      assert m.sender == "\"Alice\" <sip:alice@unit.test>;tag=a1"
      assert m.headers == %{"Subject" => "weekend"}
      assert m.served == ["urn:uuid:desk"]
    end

    @tag defaults: %{max_messages: 2}
    test "past the AOR's quota: :quota, and the script picks the code" do
      store!("one")
      store!("two")
      assert Silo.store(ctx(), message("three")) == {:error, :quota}
      # another AOR is not affected
      assert {:stored, _} = Silo.store(ctx(), message("x", %{ruri: uri("sip:carol@unit.test")}))
    end

    test "a store that does not answer is :down", %{store: store} do
      Memory.set_down(store, true)
      assert Silo.store(ctx(), message("x")) == {:error, :down}
    end

    test "a Request-URI naming no user is :no_aor" do
      assert Silo.store(ctx(), message("x", %{ruri: uri("sip:unit.test")})) == {:error, :no_aor}
    end
  end

  # ── flush/2 ────────────────────────────────────────────────────────────────

  describe "flush/2" do
    test "the message reaches the device that registers, rebuilt, dated at its arrival" do
      phone = device(:phone)
      store!("Rendez-vous jeudi")

      assert Silo.flush(ctx(), register(phone)) == :ok
      [req] = received(:phone, 1)

      assert SIP.Msg.Ops.body_string(req) == "Rendez-vous jeudi"
      assert SIP.Msg.Ops.address_of_record(req, :from) == "alice@unit.test"
      assert SIP.Msg.Ops.address_of_record(req, :to) == "bob@unit.test"
      assert req.ruri.domain == "phone.unit.test"
      assert req["Subject"] == "weekend"
      refute Map.has_key?(req, "X-Not-Kept")

      {:ok, date} = Map.fetch(req, "Date")
      assert date =~ ~r/^\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/
    end

    test "served once per device: not again from a new address, but to a new device" do
      store!("m1")
      assert Silo.flush(ctx(), register(device(:phone))) == :ok
      received(:phone, 1)
      wait_idle()

      # the phone again, from another network, same +sip.instance
      assert Silo.flush(ctx(), register(device(:phone, [], "192.0.2.99"))) == :ok
      refute_receive {:device_got, :phone, _}, 300

      assert Silo.flush(ctx(), register(device(:desk))) == :ok
      assert bodies(received(:desk, 1)) == ["m1"]
    end

    test "ten messages reach the device in order, even when one is answered slowly" do
      for n <- 1..10, do: store!("m#{n}")
      phone = device(:phone, delays: %{3 => 400})

      assert Silo.flush(ctx(), register(phone)) == :ok
      assert bodies(received(:phone, 10)) == Enum.map(1..10, &"m#{&1}")
    end

    test "a 480 stops the device's queue; the next flush resumes at that message, in order" do
      for n <- 1..10, do: store!("m#{n}")

      assert Silo.flush(ctx(), register(device(:phone, codes: %{4 => 480}))) == :ok
      assert bodies(received(:phone, 4)) == ["m1", "m2", "m3", "m4"]
      refute_receive {:device_got, :phone, _}, 300
      wait_idle()

      assert Silo.flush(ctx(), register(device(:phone))) == :ok
      assert bodies(received(:phone, 7)) == Enum.map(4..10, &"m#{&1}")
    end

    test "a refusal is an answer: the device is not served the message again" do
      store!("m1")
      assert Silo.flush(ctx(), register(device(:phone, code: 603))) == :ok
      received(:phone, 1)
      wait_idle()

      assert Silo.flush(ctx(), register(device(:phone))) == :ok
      refute_receive {:device_got, :phone, _}, 300
    end

    test "two flushes of one AOR at once deliver each message once per device" do
      for n <- 1..3, do: store!("m#{n}")
      phone = device(:phone, delays: %{1 => 200})
      desk = device(:desk)

      assert Silo.flush(ctx(), register(phone)) == :ok
      assert Silo.flush(ctx(), register(phone)) == :ok
      assert Silo.flush(ctx(), register(desk)) == :ok

      assert bodies(received(:phone, 3)) == ["m1", "m2", "m3"]
      assert bodies(received(:desk, 3)) == ["m1", "m2", "m3"]
      refute_receive {:device_got, _, _}, 600
    end

    test "an un-registration flushes nothing" do
      store!("m1")
      assert Silo.flush(ctx(), %{register(device(:phone)) | expires: "0"}) == :ok
      refute_receive {:device_got, :phone, _}, 300
    end

    test "counters: what this node did" do
      store!("m1")
      assert Silo.flush(ctx(), register(device(:phone))) == :ok
      received(:phone, 1)
      wait_idle()

      assert %{schema: :ok, stored: 1, delivered: 1} = Silo.status()
    end
  end

  # ── The sweep, the control surface, the schema ────────────────────────────

  describe "sweep" do
    test "what expired is deleted; what no device received is counted, per domain", %{
      store: store
    } do
      :telemetry.attach(
        "silo-test",
        [:kelix, :silo, :expired_undelivered],
        fn _event, measure, meta, pid ->
          send(pid, {:undelivered, measure.count, meta.domain})
        end,
        self()
      )

      on_exit(fn -> :telemetry.detach("silo-test") end)

      id = store!("served")
      :ok = Memory.serve(store, id, "urn:uuid:phone", now())
      store!("never")

      assert {:ok, %{expired: 2, undelivered: 1}} =
               Kelix.Mod.Silo.Sweep.run(Memory, store, now() + 601)

      assert_receive {:undelivered, 1, "unit.test"}
    end
  end

  describe "control" do
    test "list shows metadata only, purge empties the queue" do
      store!("secret words")

      assert {:ok, [row]} = Silo.handle_control("list", %{"aor" => "Bob@unit.test"})
      assert row.sender =~ "alice@unit.test"
      assert row.size == 12
      refute inspect(row) =~ "secret"

      assert {:ok, %{purged: 1}} = Silo.handle_control("purge", %{"args" => ["bob@unit.test"]})
      assert {:ok, []} = Silo.handle_control("list", %{"aor" => "bob@unit.test"})
    end

    test "an AOR that is not user@domain is refused" do
      assert {:error, msg} = Silo.handle_control("list", %{"aor" => "bob"})
      assert msg =~ "user@domain"
    end
  end

  describe "the schema" do
    @tag schema: :missing, no_service: true
    test "missing tables stop the module", %{opts: opts} do
      Process.flag(:trap_exit, true)
      assert {:error, {:schema, :missing}} = Silo.start_link(opts)
    end

    @tag schema: {:stale, 7}, no_service: true
    test "another version stops it too", %{opts: opts} do
      Process.flag(:trap_exit, true)
      assert {:error, {:schema, {:stale, 7}}} = Silo.start_link(opts)
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # Every flush started so far has released its batch.
  defp wait_idle do
    Enum.each(Task.Supervisor.children(Kelix.Mod.Silo.Tasks), fn pid ->
      ref = Process.monitor(pid)
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 10_000
    end)
  end

  defp now, do: System.os_time(:second)
end
