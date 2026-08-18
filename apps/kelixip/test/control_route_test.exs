defmodule Kelix.Control.RouteTest do
  # The pure routing algebra behind FW-4 (docs/design/DESIGN-KELIXIP.md#7-the-module-system).
  use ExUnit.Case, async: true

  alias Kelix.Control.Route

  defp cmd(name, rest), do: %{name: name, args: [], rest: rest, rw: :r, help: ""}

  describe "methods/1 and template/1" do
    test "a bare method, a method list, and the pre-FW-4 fallback" do
      assert Route.methods(cmd("a", {:post, "/a"})) == [:post]
      assert Route.methods(cmd("a", {[:put, :patch], "/a"})) == [:put, :patch]
      # a command that declares no rest at all still routes at its flat id
      assert Route.methods(%{name: "a"}) == [:post]
      assert Route.template(%{name: "a"}) == "/a"
    end

    test "unknown methods are dropped rather than routed" do
      assert Route.methods(cmd("a", {[:put, :teleport], "/a"})) == [:put]
    end
  end

  describe "segments/1 + match/2" do
    test "literals must match, params capture" do
      segs = Route.segments("/conferences/:uid/participants/:part_id")

      assert Route.match(segs, ["conferences", "c-1", "participants", "7"]) ==
               {:ok, %{"uid" => "c-1", "part_id" => "7"}}

      assert Route.match(segs, ["conferences", "c-1", "mosaics", "7"]) == :error
      # a shorter or longer path is not a match
      assert Route.match(segs, ["conferences", "c-1", "participants"]) == :error
    end

    test "a template with no param matches exactly" do
      assert Route.match(Route.segments("/conferences"), ["conferences"]) == {:ok, %{}}
      assert Route.match(Route.segments("/conferences"), ["conference"]) == :error
    end
  end

  describe "specificity/1" do
    test "orders most-literal-first" do
      literal = Route.specificity(Route.segments("/conferences/list"))
      param = Route.specificity(Route.segments("/conferences/:uid"))
      assert literal < param
    end
  end

  describe "check_conflicts/1" do
    test "a literal facing a param is decidable, not a conflict" do
      commands = [cmd("a", {:get, "/conferences/list"}), cmd("b", {:get, "/conferences/:uid"})]
      assert Route.check_conflicts(commands) == :ok
    end

    test "two params in the same position on the same method are refused" do
      commands = [cmd("a", {:get, "/conferences/:uid"}), cmd("b", {:get, "/conferences/:did"})]
      assert {:error, {:ambiguous_templates, "a", "b"}} = Route.check_conflicts(commands)
    end

    test "the same template on different methods is fine" do
      commands = [cmd("a", {:get, "/conferences/:uid"}), cmd("b", {:delete, "/conferences/:uid"})]
      assert Route.check_conflicts(commands) == :ok
    end

    test "an overlapping method list is a conflict" do
      commands = [
        cmd("a", {[:put, :patch], "/conferences/:uid"}),
        cmd("b", {[:patch], "/conferences/:x"})
      ]

      assert {:error, {:ambiguous_templates, _, _}} = Route.check_conflicts(commands)
    end

    test "different lengths never conflict" do
      commands = [cmd("a", {:get, "/conferences"}), cmd("b", {:get, "/conferences/:uid"})]
      assert Route.check_conflicts(commands) == :ok
    end
  end

  describe "render/2" do
    test "fills params from an atom- or string-keyed result map" do
      assert Route.render("/conferences/:uid", %{uid: "c-1"}) == {:ok, "/conferences/c-1"}
      assert Route.render("/conferences/:uid", %{"uid" => "c-1"}) == {:ok, "/conferences/c-1"}
      assert Route.render("/conferences", %{}) == {:ok, "/conferences"}
    end

    test "a missing param yields :error (no Location pointing nowhere)" do
      assert Route.render("/conferences/:uid", %{did: "8001"}) == :error
    end
  end
end
