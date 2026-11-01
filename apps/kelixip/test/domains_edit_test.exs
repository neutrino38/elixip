defmodule Kelix.Domains.EditTest do
  use ExUnit.Case, async: true

  alias Kelix.Domains.Edit

  defp rule(pattern, script), do: %{"pattern" => pattern, "script" => script}
  defp default(script), do: %{"default" => true, "script" => script}

  @calls %{
    "name" => "d.example",
    "call" => [
      %{"pattern" => "1XXX", "script" => "a.exs"},
      %{"pattern" => "2XXX", "script" => "b.exs"},
      %{"default" => true, "script" => "z.exs"}
    ]
  }

  defp scripts(table, key), do: Enum.map(table[key], & &1["script"])

  describe "new/2" do
    test "a name, and the aliases and max_calls given, typed" do
      assert Edit.new("d.example", %{}) == {:ok, %{"name" => "d.example"}}

      assert Edit.new("d.example", %{"aliases" => "a.example,b.example", "max_calls" => "5"}) ==
               {:ok,
                %{
                  "name" => "d.example",
                  "aliases" => ["a.example", "b.example"],
                  "max_calls" => 5
                }}

      assert {:ok, %{"aliases" => ["a.example"]}} =
               Edit.new("d.example", %{"aliases" => ["a.example"]})
    end

    test "refuses an unknown argument or a value of the wrong type" do
      assert {:error, {:invalid, "unknown argument(s): bogus"}} =
               Edit.new("d.example", %{"bogus" => 1})

      assert {:error, {:invalid, "`max_calls` must be a positive integer"}} =
               Edit.new("d.example", %{"max_calls" => "0"})
    end
  end

  describe "the domain's own keys and its aliases" do
    test "set changes only what it is given; none removes" do
      t = %{"name" => "d.example", "max_calls" => 3}
      assert Edit.change(t, {:set, %{"max_calls" => 7}}) == {:ok, %{t | "max_calls" => 7}}
      assert Edit.change(t, {:set, %{"max_calls" => "none"}}) == {:ok, %{"name" => "d.example"}}
      assert Edit.change(t, {:set, %{}}) == {:ok, t}
    end

    test "alias add and remove, case-insensitively" do
      t = %{"name" => "d.example", "aliases" => ["a.example"]}

      assert {:ok, %{"aliases" => ["a.example", "b.example"]}} =
               Edit.change(t, {:alias_add, "b.example"})

      assert Edit.change(t, {:alias_add, "A.example"}) == {:error, :exists}
      assert Edit.change(t, {:alias_remove, "A.EXAMPLE"}) == {:ok, %{"name" => "d.example"}}
      assert Edit.change(t, {:alias_remove, "c.example"}) == {:error, :not_found}
    end
  end

  describe "registrar" do
    test "set creates or merges the block; none removes a key; remove drops it" do
      t = %{"name" => "d.example"}
      {:ok, t} = Edit.change(t, {:registrar_set, %{"script" => "r.exs", "min_expires" => "60"}})
      assert t["registrar"] == %{"script" => "r.exs", "min_expires" => 60}

      {:ok, t} = Edit.change(t, {:registrar_set, %{"default_expires" => 600}})

      assert t["registrar"] == %{
               "script" => "r.exs",
               "min_expires" => 60,
               "default_expires" => 600
             }

      {:ok, t} = Edit.change(t, {:registrar_set, %{"min_expires" => "none"}})
      assert t["registrar"] == %{"script" => "r.exs", "default_expires" => 600}

      assert Edit.change(t, :registrar_remove) == {:ok, %{"name" => "d.example"}}
      assert Edit.change(%{"name" => "d.example"}, :registrar_remove) == {:error, :not_found}
    end
  end

  describe "presence" do
    test "add, set and remove a package, named case-insensitively" do
      t = %{"name" => "d.example"}
      {:ok, t} = Edit.change(t, {:presence_add, "presence", %{"subscribe" => "s.exs"}})
      assert t["presence"] == [%{"event-package" => "presence", "subscribe" => "s.exs"}]

      assert Edit.change(t, {:presence_add, "Presence", %{"subscribe" => "x.exs"}}) ==
               {:error, :exists}

      {:ok, t} = Edit.change(t, {:presence_set, "PRESENCE", %{"publish" => "p.exs"}})
      assert hd(t["presence"])["publish"] == "p.exs"

      {:ok, t} = Edit.change(t, {:presence_set, "presence", %{"publish" => "none"}})
      refute Map.has_key?(hd(t["presence"]), "publish")

      assert Edit.change(t, {:presence_set, "dialog", %{}}) == {:error, :not_found}
      assert Edit.change(t, {:presence_remove, "presence"}) == {:ok, %{"name" => "d.example"}}
      assert Edit.change(t, {:presence_remove, "dialog"}) == {:error, :not_found}
    end

    test "the first subscribe rule command writes the shorthand out as a list" do
      t = %{
        "name" => "d.example",
        "presence" => [%{"event-package" => "presence", "subscribe" => "s.exs"}]
      }

      assert Edit.rules(t, {:subscribe, "presence"}) == [default("s.exs")]

      {:ok, t} =
        Edit.change(t, {:rule_add, {:subscribe, "presence"}, "rls", %{"script" => "rls.exs"}})

      assert hd(t["presence"])["subscribe"] == [rule("rls", "rls.exs"), default("s.exs")]
    end
  end

  describe "rules" do
    test "add goes before the catch-all, or at the number given" do
      {:ok, t} = Edit.change(@calls, {:rule_add, :call, "3XXX", %{"script" => "c.exs"}})
      assert scripts(t, "call") == ["a.exs", "b.exs", "c.exs", "z.exs"]

      {:ok, t} =
        Edit.change(@calls, {:rule_add, :call, "0X", %{"script" => "c.exs", "at" => "1"}})

      assert scripts(t, "call") == ["c.exs", "a.exs", "b.exs", "z.exs"]

      {:ok, t} = Edit.change(%{"name" => "d"}, {:rule_add, :call, "1X", %{"script" => "c.exs"}})
      assert t["call"] == [rule("1X", "c.exs")]

      assert {:error, {:invalid, "`at` must be a rule number from 1 to 4"}} =
               Edit.change(@calls, {:rule_add, :call, "0X", %{"script" => "c.exs", "at" => 9}})

      assert {:error, {:invalid, _}} =
               Edit.change(@calls, {:rule_add, :call, "", %{"script" => "c.exs"}})

      assert {:error, {:invalid, "unknown argument(s): idle_timeout"}} =
               Edit.change(@calls, {:rule_add, :call, "0X", %{"idle_timeout" => 5}})
    end

    test "update changes the keys given; a pattern can become the catch-all and back" do
      {:ok, t} = Edit.change(@calls, {:rule_update, :call, 2, %{"script" => "bb.exs"}})
      assert Enum.at(t["call"], 1) == rule("2XXX", "bb.exs")

      {:ok, t} = Edit.change(@calls, {:rule_update, :call, "3", %{"pattern" => "default"}})
      assert List.last(t["call"]) == default("z.exs")

      {:ok, t} = Edit.change(@calls, {:rule_update, :call, 3, %{"pattern" => "9X"}})
      assert List.last(t["call"]) == rule("9X", "z.exs")
    end

    test "move and remove; a number out of range is not found" do
      {:ok, t} = Edit.change(@calls, {:rule_move, :call, 2, "1"})
      assert scripts(t, "call") == ["b.exs", "a.exs", "z.exs"]

      {:ok, t} = Edit.change(@calls, {:rule_remove, :call, 1})
      assert scripts(t, "call") == ["b.exs", "z.exs"]

      assert Edit.change(@calls, {:rule_remove, :call, 4}) == {:error, :not_found}
      assert Edit.change(@calls, {:rule_update, :call, 0, %{}}) == {:error, :not_found}
      assert {:error, {:invalid, _}} = Edit.change(@calls, {:rule_remove, :call, "two"})
      assert {:error, {:invalid, _}} = Edit.change(@calls, {:rule_move, :call, 1, 4})

      {:ok, t} =
        Edit.change(%{"name" => "d", "call" => [default("z.exs")]}, {:rule_remove, :call, 1})

      refute Map.has_key?(t, "call")
    end

    test "chat rules carry idle_timeout" do
      {:ok, t} =
        Edit.change(
          %{"name" => "d"},
          {:rule_add, :chat, "default", %{"script" => "c.exs", "idle_timeout" => "60"}}
        )

      assert t["chat"] == [%{"default" => true, "script" => "c.exs", "idle_timeout" => 60}]
    end

    test "the options keepalive entry is not a rule, and is set apart" do
      t = %{
        "name" => "d",
        "options" => [rule("conf-.", "o.exs"), %{"keepalive" => true, "script" => "k.exs"}]
      }

      assert Edit.rules(t, :options) == [rule("conf-.", "o.exs")]

      {:ok, t2} = Edit.change(t, {:rule_remove, :options, 1})
      assert t2["options"] == [%{"keepalive" => true, "script" => "k.exs"}]

      {:ok, t2} = Edit.change(t, {:keepalive_set, "k2.exs"})
      assert Edit.rules(t2, :options) == [rule("conf-.", "o.exs")]
      assert Enum.count(t2["options"], &Map.has_key?(&1, "keepalive")) == 1

      {:ok, t2} = Edit.change(t, :keepalive_remove)
      assert t2["options"] == [rule("conf-.", "o.exs")]
      assert Edit.change(t2, :keepalive_remove) == {:error, :not_found}
    end
  end
end

defmodule Kelix.Domains.EditControlTest do
  # async: false — Kelix.Domains and the script registry are singletons.
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias Kelix.{Control, Domains}

  setup do
    %{path: path} =
      Kelix.Test.Fixtures.serve_domains("""
      [[domain]]
      name = "d.example"
      """)

    Kelix.Test.Fixtures.with_script_dir(Path.join(__DIR__, "support/scripts"))
    prev = Application.get_env(:kelixip, :domains_path)
    Application.put_env(:kelixip, :domains_path, path)

    on_exit(fn ->
      if prev,
        do: Application.put_env(:kelixip, :domains_path, prev),
        else: Application.delete_env(:kelixip, :domains_path)
    end)

    %{path: path}
  end

  defp add(pattern, attrs \\ %{}, opts \\ []) do
    attrs = Map.put(attrs, "script", "domain_waiter.exs")

    {result, _log} =
      with_log(fn -> Control.add_rule("d.example", :call, pattern, attrs, opts) end)

    result
  end

  defp patterns(), do: Enum.map(hd(Domains.current().domains).dial_plan, &(&1.raw || "default"))

  test "add answers the number the rule took, and the router has it" do
    assert {:ok, %{at: 1}} = add("default")
    assert {:ok, %{at: 1}} = add("1XXX")
    assert {:ok, %{at: 2}} = add("2XXX")
    assert patterns() == ["1XXX", "2XXX", "default"]
  end

  test "a catch-all moved off the end is refused, and nothing is written", %{path: path} do
    {:ok, _} = add("1XXX")
    {:ok, _} = add("default")
    before = File.read!(path)

    assert {:error, {:invalid, msg}} = Control.move_rule("d.example", :call, 2, 1)
    assert msg =~ "catch-all"
    assert File.read!(path) == before
  end

  test "--version catches a rule inserted before the one addressed" do
    {:ok, _} = add("1XXX")
    {:ok, _} = add("2XXX")
    seen = Domains.current().version

    # another admin inserts a rule at the top: rule 2 is now 1XXX, no longer 2XXX
    {:ok, %{at: 1}} = add("0X", %{"at" => 1})

    assert Control.remove_rule("d.example", :call, 2, version: seen) == {:error, :conflict}
    assert patterns() == ["0X", "1XXX", "2XXX"]
  end

  test "several edits, then the file read back gives the same snapshot", %{path: path} do
    capture_log(fn ->
      {:ok, _} = Control.add_alias("d.example", "e.example")
      {:ok, _} = Control.set_domain("d.example", %{"max_calls" => "4"})
      {:ok, _} = Control.set_registrar("d.example", %{"script" => "domain_waiter.exs"})
      {:ok, _} = Control.set_keepalive("d.example", "domain_waiter.exs")
    end)

    {:ok, _} = add("1XXX")

    {:ok, read_back} = Domains.parse(File.read!(path))
    assert read_back.source == Domains.current().source
    assert hd(read_back.domains).aliases == ["e.example"]
    assert hd(read_back.domains).options_keepalive == "domain_waiter.exs"
  end

  test "an unknown domain, an alias, or a rule it does not have is not found" do
    assert Control.remove_rule("nowhere.example", :call, 1) == {:error, :not_found}
    assert Control.remove_rule("d.example", :call, 1) == {:error, :not_found}
    capture_log(fn -> {:ok, _} = Control.add_alias("d.example", "e.example") end)
    assert Control.remove_rule("e.example", :call, 1) == {:error, :not_found}
  end
end
