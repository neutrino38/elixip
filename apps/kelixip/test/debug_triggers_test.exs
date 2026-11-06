defmodule Kelix.DebugTriggersTest do
  # Kelix.DebugTriggers on its own: one store per test, against a parsed
  # domains.toml snapshot (debug-triggers-plan.md, T2).
  use ExUnit.Case, async: true

  alias Kelix.{DebugTriggers, Domains}

  @toml """
  [[domain]]
  name = "example.com"

  [domain.registrar]
  script = "reg.exs"

  [[domain.call]]
  pattern = "XXXX"
  script = "call.exs"

  [[domain.call]]
  default = true
  script = "call.exs"

  [[domain]]
  name = "acme.org"

  [[domain.call]]
  default = true
  script = "other.exs"
  """

  setup context do
    {:ok, snapshot} = Domains.parse(@toml)
    dir = Path.join(System.tmp_dir!(), "kelix-dt-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    path = Path.join(dir, "debug_triggers.json")
    name = :"dt_#{System.unique_integer([:positive])}"

    server =
      if context[:no_store],
        do: nil,
        else: store(name: name, path: path, snapshot: fn -> snapshot end)

    %{server: server, name: name, path: path, dir: dir, snapshot: snapshot}
  end

  defp store(opts) do
    opts = Keyword.put_new(opts, :max_runs, 10)
    start_supervised!({DebugTriggers, opts}, id: make_ref())
  end

  defp uri(s) do
    {:ok, u} = SIP.Uri.parse(s)
    u
  end

  defp invite(from, to, ip \\ {192, 0, 2, 7}) do
    %{
      method: :INVITE,
      from: "<sip:#{from}@example.com>;tag=1",
      to: "<sip:#{to}@example.com>",
      ruri: %{
        uri("sip:#{to}@example.com")
        | destip: ip,
          destport: 5060,
          tp_module: SIP.Transport.UDP
      }
    }
  end

  describe "parse_duration/1" do
    test "units, a month being 30 days" do
      assert DebugTriggers.parse_duration("30m") == {:ok, 1_800}
      assert DebugTriggers.parse_duration("2h") == {:ok, 7_200}
      assert DebugTriggers.parse_duration("7d") == {:ok, 604_800}
      assert DebugTriggers.parse_duration("3mo") == {:ok, 7_776_000}
      assert DebugTriggers.parse_duration(" 2 H ") == {:ok, 7_200}
      assert DebugTriggers.parse_duration(90) == {:ok, 90}
    end

    test "refused: zero, no unit, junk, beyond 12 months" do
      for bad <- ["0h", "2", "2w", "", "h", 0, -5, nil, "13mo"],
          do: assert({:error, {:bad_duration, _}} = DebugTriggers.parse_duration(bad))

      assert {:ok, _} = DebugTriggers.parse_duration("12mo")
    end
  end

  describe "set/5" do
    test "a rule, read back with what is left of it", %{server: s} do
      assert {:ok, rule} =
               DebugTriggers.set("example.com", "call.exs", %{count: 5, duration: "2h"}, "ops", s)

      assert %{total: 5, remaining: 5, filter: nil, created_by: "ops"} = rule
      assert rule.seconds_left in 7_190..7_200
      assert {:ok, ^rule} = DebugTriggers.get("example.com", "call.exs", s)
      assert [^rule] = DebugTriggers.list(s)
    end

    test "one rule per {domain, script}: a second one replaces the first", %{server: s} do
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", %{count: 5, duration: "2h"}, nil, s)
      spec = %{count: 2, duration: "1d", filter: %{"caller" => "1001"}}
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", spec, nil, s)

      assert [%{total: 2, filter: %{caller: "1001"}}] = DebugTriggers.list(s)
    end

    test "the domain must exist and serve the script", %{server: s} do
      spec = %{count: 1, duration: "1h"}

      assert DebugTriggers.set("nope.org", "call.exs", spec, nil, s) ==
               {:error, {:unknown_domain, "nope.org"}}

      assert DebugTriggers.set("example.com", "other.exs", spec, nil, s) ==
               {:error, {:unknown_script, "other.exs"}}

      assert {:ok, _} = DebugTriggers.set("example.com", "reg.exs", spec, nil, s)
    end

    test "count: 1 to max_runs", %{server: s} do
      for n <- [0, 11, nil, "3"] do
        assert {:error, {:bad_count, ^n, 10}} =
                 DebugTriggers.set("example.com", "call.exs", %{count: n, duration: "1h"}, nil, s)
      end
    end

    test "filters: at most one, a known key, a non-empty value, a valid source", %{server: s} do
      for bad <- [
            %{caller: "1", callee: "2"},
            %{from: "1"},
            %{caller: "  "},
            %{caller: 42},
            %{source: "10.0.0.0/33"},
            %{source: "not-an-ip"},
            "caller=1"
          ] do
        assert {:error, {:bad_filter, _}} =
                 DebugTriggers.set(
                   "example.com",
                   "call.exs",
                   %{count: 1, duration: "1h", filter: bad},
                   nil,
                   s
                 ),
               "accepted #{inspect(bad)}"
      end

      for good <- [%{source: "10.1.0.0/16"}, %{source: "192.0.2.7"}, %{source: "fd00::/8"}, %{}] do
        assert {:ok, _} =
                 DebugTriggers.set(
                   "example.com",
                   "call.exs",
                   %{count: 1, duration: "1h", filter: good},
                   nil,
                   s
                 )
      end
    end

    test "remove", %{server: s} do
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", %{count: 1, duration: "1h"}, nil, s)
      assert DebugTriggers.remove("example.com", "call.exs", "ops", s) == :ok
      assert DebugTriggers.remove("example.com", "call.exs", "ops", s) == {:error, :not_found}
      assert DebugTriggers.get("example.com", "call.exs", s) == {:error, :not_found}
    end
  end

  describe "claim/4" do
    test "N runs, then the rule ends: exhausted", %{server: s, name: name} do
      DebugTriggers.subscribe(self(), s)
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", %{count: 2, duration: "1h"}, nil, s)
      req = invite("1001", "1002")

      assert {:journal, %{remaining: 1}} =
               DebugTriggers.claim("example.com", "call.exs", req, name)

      assert_receive {:kelix_debug_triggers, {:upsert, %{remaining: 1}}}

      assert {:journal, %{remaining: 0}} =
               DebugTriggers.claim("example.com", "call.exs", req, name)

      assert_receive {:kelix_debug_triggers, {:remove, {"example.com", "call.exs"}, :exhausted}}

      assert DebugTriggers.claim("example.com", "call.exs", req, name) == :no
      assert DebugTriggers.list(s) == []
    end

    test "another script, another domain: nothing", %{server: s, name: name} do
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", %{count: 2, duration: "1h"}, nil, s)
      req = invite("1001", "1002")
      assert DebugTriggers.claim("example.com", "reg.exs", req, name) == :no
      assert DebugTriggers.claim("acme.org", "call.exs", req, name) == :no
      assert [%{remaining: 2}] = DebugTriggers.list(s)
    end

    test "concurrent claims never exceed N", %{server: s, name: name} do
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", %{count: 7, duration: "1h"}, nil, s)
      req = invite("1001", "1002")

      journaled =
        1..50
        |> Task.async_stream(
          fn _ -> DebugTriggers.claim("example.com", "call.exs", req, name) end,
          max_concurrency: 50
        )
        |> Enum.count(&match?({:ok, {:journal, _}}, &1))

      assert journaled == 7
    end

    test "caller: From or P-Asserted-Identity, case-insensitively", %{server: s, name: name} do
      spec = %{count: 5, duration: "1h", filter: %{caller: "Alice"}}
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", spec, nil, s)

      assert {:journal, _} =
               DebugTriggers.claim("example.com", "call.exs", invite("alice", "x"), name)

      pai = Map.put(invite("anonymous", "x"), "P-Asserted-Identity", "<sip:alice@example.com>")
      assert {:journal, _} = DebugTriggers.claim("example.com", "call.exs", pai, name)

      assert DebugTriggers.claim("example.com", "call.exs", invite("bob", "alice"), name) == :no
      assert [%{remaining: 3}] = DebugTriggers.list(s)
    end

    test "callee: To or Request-URI", %{server: s, name: name} do
      spec = %{count: 5, duration: "1h", filter: %{callee: "1002"}}
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", spec, nil, s)

      assert {:journal, _} =
               DebugTriggers.claim("example.com", "call.exs", invite("x", "1002"), name)

      retargeted = %{invite("x", "bob") | to: "<sip:1002@example.com>"}
      assert {:journal, _} = DebugTriggers.claim("example.com", "call.exs", retargeted, name)

      assert DebugTriggers.claim("example.com", "call.exs", invite("1002", "y"), name) == :no
    end

    test "source: the address the request came from", %{server: s, name: name} do
      spec = %{count: 5, duration: "1h", filter: %{source: "10.1.0.0/16"}}
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", spec, nil, s)

      inside = invite("a", "b", {10, 1, 42, 3})
      outside = invite("a", "b", {10, 2, 0, 1})
      assert {:journal, _} = DebugTriggers.claim("example.com", "call.exs", inside, name)
      assert DebugTriggers.claim("example.com", "call.exs", outside, name) == :no
    end

    test "a run without request only matches a rule without filter", %{server: s, name: name} do
      {:ok, _} =
        DebugTriggers.set(
          "example.com",
          "call.exs",
          %{count: 5, duration: "1h", filter: %{caller: "a"}},
          nil,
          s
        )

      {:ok, _} = DebugTriggers.set("example.com", "reg.exs", %{count: 5, duration: "1h"}, nil, s)

      assert DebugTriggers.claim("example.com", "call.exs", nil, name) == :no
      assert {:journal, _} = DebugTriggers.claim("example.com", "reg.exs", nil, name)
    end

    test "by pid too, and a missing store answers :no", %{server: s} do
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", %{count: 5, duration: "1h"}, nil, s)
      assert {:journal, _} = DebugTriggers.claim("example.com", "call.exs", nil, s)
      assert DebugTriggers.claim("example.com", "call.exs", nil, :no_such_store) == :no
    end

    test "the window closes: expired", %{server: s, name: name} do
      DebugTriggers.subscribe(self(), s)
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", %{count: 5, duration: 1}, nil, s)

      assert_receive {:kelix_debug_triggers, {:remove, {"example.com", "call.exs"}, :expired}},
                     2_500

      assert DebugTriggers.claim("example.com", "call.exs", nil, name) == :no
    end
  end

  describe "prune/2" do
    test "a rule whose domain no longer serves its script is removed", ctx do
      s = ctx.server
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", %{count: 1, duration: "1h"}, nil, s)
      {:ok, _} = DebugTriggers.set("example.com", "reg.exs", %{count: 1, duration: "1h"}, nil, s)
      DebugTriggers.subscribe(self(), s)

      {:ok, smaller} =
        Domains.parse(
          ~s([[domain]]\nname = "example.com"\n[domain.registrar]\nscript = "reg.exs")
        )

      assert DebugTriggers.prune(smaller, s) == [{"example.com", "call.exs"}]
      assert_receive {:kelix_debug_triggers, {:remove, {"example.com", "call.exs"}, :orphan}}
      assert [%{script: "reg.exs"}] = DebugTriggers.list(s)

      {:ok, empty} = Domains.parse("")
      assert DebugTriggers.prune(empty, s) == [{"example.com", "reg.exs"}]
      assert DebugTriggers.list(s) == []
    end
  end

  describe "the state file" do
    test "survives a restart, counter included", ctx do
      s = ctx.server
      spec = %{count: 3, duration: "1d", filter: %{source: "10.1.0.0/16"}}
      {:ok, _} = DebugTriggers.set("example.com", "call.exs", spec, "ops", s)

      {:journal, _} =
        DebugTriggers.claim("example.com", "call.exs", invite("a", "b", {10, 1, 0, 1}), s)

      assert {:ok, %File.Stat{mode: mode}} = File.stat(ctx.path)
      assert Bitwise.band(mode, 0o777) == 0o640

      [before] = DebugTriggers.list(s)
      again = store(path: ctx.path, name: nil, snapshot: fn -> ctx.snapshot end)
      assert [restored] = DebugTriggers.list(again)

      assert Map.delete(restored, :seconds_left) == Map.delete(before, :seconds_left)
      assert restored.remaining == 2

      assert {:journal, _} =
               DebugTriggers.claim(
                 "example.com",
                 "call.exs",
                 invite("a", "b", {10, 1, 0, 1}),
                 again
               )
    end

    @tag :no_store
    test "a rule that expired while the node was down is dropped at boot", ctx do
      past = DateTime.utc_now() |> DateTime.add(-60) |> DateTime.to_iso8601()
      future = DateTime.utc_now() |> DateTime.add(3_600) |> DateTime.to_iso8601()

      rule = fn script, expires ->
        %{
          "domain" => "example.com",
          "script" => script,
          "total" => 2,
          "remaining" => 2,
          "filter" => nil,
          "created_at" => past,
          "expires_at" => expires,
          "created_by" => nil
        }
      end

      File.write!(
        ctx.path,
        Jason.encode!(%{
          "version" => 1,
          "rules" => [rule.("call.exs", past), rule.("reg.exs", future)]
        })
      )

      s = store(path: ctx.path, name: nil, snapshot: fn -> ctx.snapshot end)
      assert [%{script: "reg.exs"}] = DebugTriggers.list(s)

      assert %{"rules" => [%{"script" => "reg.exs"}]} =
               ctx.path |> File.read!() |> Jason.decode!()
    end

    @tag :no_store
    test "an unreadable file is moved aside, and the node starts without rules", ctx do
      File.write!(ctx.path, "{not json")
      s = store(path: ctx.path, name: nil, snapshot: fn -> ctx.snapshot end)

      assert DebugTriggers.list(s) == []
      assert File.read!(ctx.path <> ".corrupt") == "{not json"
      refute File.exists?(ctx.path)
    end

    @tag :no_store
    test "a file that cannot be written refuses set and remove, and changes nothing", ctx do
      path = Path.join([ctx.dir, "missing-dir", "debug_triggers.json"])
      s = store(path: path, name: nil, snapshot: fn -> ctx.snapshot end)

      assert {:error, {:write_failed, %{path: ^path}}} =
               DebugTriggers.set("example.com", "call.exs", %{count: 1, duration: "1h"}, nil, s)

      assert DebugTriggers.list(s) == []
    end

    @tag :no_store
    test "without a path, memory only", ctx do
      s = store(path: nil, name: nil, snapshot: fn -> ctx.snapshot end)

      assert {:ok, _} =
               DebugTriggers.set("example.com", "call.exs", %{count: 1, duration: "1h"}, nil, s)

      refute File.exists?(ctx.path)
    end
  end
end
