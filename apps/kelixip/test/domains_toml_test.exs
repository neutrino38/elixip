defmodule Kelix.Domains.TomlTest do
  use ExUnit.Case, async: true

  alias Kelix.Domains
  alias Kelix.Domains.Toml, as: Encoder

  # The shipped example with its TOML lines uncommented: every block type the
  # schema has, as an operator would write it. Lines commented twice stay
  # commented, as does the prose.
  @example Path.expand("../../../packaging/config/domains.toml.example", __DIR__)
           |> File.read!()
           |> String.split("\n")
           |> Enum.map_join("\n", fn line ->
             if Regex.match?(~r/^#\s*(\[\[?[a-z.-]+\]\]?\s*$|[a-z_-]+\s*=)/, line),
               do: String.replace_prefix(line, "#", ""),
               else: line
           end)

  defp round_trip(text) do
    map = Toml.decode!(text)
    {:ok, encoded} = Encoder.encode(map)
    {map, encoded}
  end

  describe "the shipped example" do
    test "is a real config once uncommented" do
      assert {:ok, snap} = Domains.parse(@example)
      assert Enum.map(snap.domains, & &1.name) == ["example.com", "sip.linphone.org"]
      assert Map.has_key?(snap.modules, "registrar")
    end

    test "reads back as the same data and the same snapshot" do
      {map, encoded} = round_trip(@example)
      assert Toml.decode!(encoded) == map

      {:ok, before} = Domains.parse(@example)
      {:ok, after_} = Domains.parse(encoded)
      assert after_.source == before.source
      assert after_.modules == before.modules

      for {a, b} <- Enum.zip(before.domains, after_.domains) do
        assert a.name == b.name
        assert a.aliases == b.aliases
        assert a.max_calls == b.max_calls
        assert a.registrar == b.registrar
        assert a.options_keepalive == b.options_keepalive

        assert Enum.map(a.dial_plan, &{&1.raw, &1.script}) ==
                 Enum.map(b.dial_plan, &{&1.raw, &1.script})

        assert Enum.map(a.options, &{&1.raw, &1.script}) ==
                 Enum.map(b.options, &{&1.raw, &1.script})

        assert Enum.map(a.chat, &{&1.raw, &1.script, &1.idle_timeout}) ==
                 Enum.map(b.chat, &{&1.raw, &1.script, &1.idle_timeout})

        assert Enum.map(a.presence, &{&1.event_package, &1.publish, length(&1.subscribe)}) ==
                 Enum.map(b.presence, &{&1.event_package, &1.publish, length(&1.subscribe)})
      end
    end

    test "encoding is stable" do
      {_map, encoded} = round_trip(@example)
      {_map, again} = round_trip(encoded)
      assert again == encoded
    end

    test "starts with the generated header" do
      {_map, encoded} = round_trip(@example)
      assert encoded =~ ~r/\A# domains.toml — /
      assert encoded =~ "/usr/share/doc/kelixip/domains.toml.example"
    end
  end

  describe "layout" do
    test "nested arrays of tables keep their order under the right parent" do
      text = """
      [[domain]]
      name = "a.example"

        [[domain.presence]]
        event-package = "presence"

          [[domain.presence.subscribe]]
          pattern = "rls"
          script  = "presence-rls.exs"

          [[domain.presence.subscribe]]
          default = true
          script  = "presence-subscribe.exs"

        [[domain.presence]]
        event-package = "dialog"
        subscribe     = "dialog-subscribe.exs"
      """

      {map, encoded} = round_trip(text)
      assert Toml.decode!(encoded) == map
      assert encoded =~ "\n    [[domain.presence.subscribe]]\n    pattern = \"rls\"\n"

      [d] = Toml.decode!(encoded)["domain"]
      assert Enum.map(d["presence"], & &1["event-package"]) == ["presence", "dialog"]

      assert Enum.map(hd(d["presence"])["subscribe"], & &1["script"]) ==
               ["presence-rls.exs", "presence-subscribe.exs"]
    end

    test "domains keep their order, and known keys come in schema order" do
      map = %{
        "domain" => [
          %{"name" => "z.example"},
          %{"max_calls" => 5, "aliases" => ["b2"], "name" => "b.example"},
          %{"name" => "a.example", "registrar" => %{"script" => "registrar.exs"}}
        ]
      }

      {:ok, encoded} = Encoder.encode(map)

      assert Enum.map(Toml.decode!(encoded)["domain"], & &1["name"]) ==
               ["z.example", "b.example", "a.example"]

      assert encoded =~ ~s(name = "b.example"\naliases = ["b2"]\nmax_calls = 5\n)
      assert encoded =~ ~s(\n  [domain.registrar]\n  script = "registrar.exs"\n)
    end

    test "[module.registrar] is kept as is, without an empty [module] header" do
      map = %{
        "domain" => [%{"name" => "a.example"}],
        "module" => %{"registrar" => %{"max_contacts_per_aor" => 10, "min_expires" => 60}}
      }

      {:ok, encoded} = Encoder.encode(map)
      assert Toml.decode!(encoded) == map
      assert encoded =~ "[module.registrar]"
      refute encoded =~ "[module]\n"
    end

    test "empty values survive: an empty table, an empty list, no domain at all" do
      for map <- [
            %{},
            %{"domain" => []},
            %{"domain" => [%{"name" => "a.example", "aliases" => [], "registrar" => %{}}]}
          ] do
        assert {:ok, encoded} = Encoder.encode(map)
        assert Toml.decode!(encoded) == map
      end
    end
  end

  describe "strings" do
    test "quotes, backslashes, control characters and non-ASCII read back intact" do
      for s <- [
            ~s(with "quotes"),
            "back\\slash",
            "line\nbreak\ttab\rcr",
            "bell\a nul\0 del\x7F bs\b ff\f",
            "accents é ü — 日本",
            "# not a comment",
            "a = b"
          ] do
        map = %{"domain" => [%{"name" => "a.example", "registrar" => %{"script" => s}}]}
        assert {:ok, encoded} = Encoder.encode(map)
        assert Toml.decode!(encoded) == map
      end
    end

    test "a key that is not bare is quoted" do
      map = %{"module" => %{"odd key.x" => %{"value" => 1}, "ok" => %{"wé" => "x"}}}
      assert {:ok, encoded} = Encoder.encode(map)
      assert Toml.decode!(encoded) == map
    end
  end

  describe "refusals" do
    test "a type outside the schema is refused, naming where it is" do
      assert {:error, msg} = Encoder.encode(%{"module" => %{"registrar" => %{"ratio" => 0.5}}})
      assert msg =~ "module.registrar.ratio"

      assert {:error, _} = Encoder.encode(%{"domain" => [%{"name" => nil}]})
      assert {:error, _} = Encoder.encode(%{"domain" => [%{"name" => :atom}]})
      assert {:error, _} = Encoder.encode(%{"domain" => [%{"name" => "a"}, "b"]})
      assert {:error, _} = Encoder.encode(%{"domain" => [%{name: "a"}]})
      assert {:error, _} = Encoder.encode(%{"domain" => [%{"name" => <<0xFF>>}]})
    end
  end
end
