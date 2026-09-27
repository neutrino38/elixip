defmodule SIP.Test.EventPackageRegistry do
  # The table lives in :persistent_term, so it is node-wide: two tests writing
  # it concurrently would decide each other's outcome.
  use ExUnit.Case, async: false

  @moduledoc """
  The `name -> module` table of `SIP.EventPackage`: what answers **489 Bad Event**
  and what composes `Allow-Events`.

  The four rules of docs/design/DESIGN-PRESENCE.md, "Who registers a package",
  one describe block each. The one that is not a convenience is the last:
  collisions are decided **at registration**, so module start order never silently
  decides SIP behaviour.
  """

  alias SIP.Test.EventPackages.Dummy

  # A provided package, as the library's own would be: same name as the rival
  # below, so an override can be told from a collision.
  defmodule Provided do
    @behaviour SIP.EventPackage
    @impl true
    def name, do: "overridable"
    @impl true
    def default_expires, do: 3600
    @impl true
    def min_expires, do: 60
    @impl true
    def max_expires, do: 7200
    @impl true
    def content_types, do: ["application/pidf+xml"]
    @impl true
    def parse(_ct, body), do: {:ok, body}
    @impl true
    def serialize(_ct, state), do: {:ok, state}
  end

  defmodule Operator do
    @behaviour SIP.EventPackage
    @impl true
    def name, do: "overridable"
    @impl true
    def default_expires, do: 600
    @impl true
    def min_expires, do: 60
    @impl true
    def max_expires, do: 7200
    @impl true
    def content_types, do: ["application/pidf+xml"]
    @impl true
    def parse(_ct, body), do: {:ok, body}
    @impl true
    def serialize(_ct, state), do: {:ok, state}
  end

  defmodule SecondOperator do
    @behaviour SIP.EventPackage
    @impl true
    def name, do: "overridable"
    @impl true
    def default_expires, do: 900
    @impl true
    def min_expires, do: 60
    @impl true
    def max_expires, do: 7200
    @impl true
    def content_types, do: ["text/plain"]
    @impl true
    def parse(_ct, body), do: {:ok, body}
    @impl true
    def serialize(_ct, state), do: {:ok, state}
  end

  # Half a package: it answers its name and nothing else.
  defmodule NotAPackage do
    def name, do: "impostor"
  end

  setup do
    before = SIP.EventPackage.registered()

    on_exit(fn ->
      Enum.each(SIP.EventPackage.names(), &SIP.EventPackage.unregister/1)

      Enum.each(before, fn {_name, %{module: module, origin: origin}} ->
        SIP.EventPackage.register(module, origin: origin)
      end)
    end)

    Enum.each(SIP.EventPackage.names(), &SIP.EventPackage.unregister/1)
    :ok
  end

  describe "the table" do
    test "a package registers, is looked up, and disappears on unregister" do
      assert SIP.EventPackage.lookup("dummy") == :error

      assert :ok = SIP.EventPackage.register(Dummy)
      assert SIP.EventPackage.lookup("dummy") == {:ok, Dummy}
      assert SIP.EventPackage.names() == ["dummy"]

      assert :ok = SIP.EventPackage.unregister("dummy")
      assert SIP.EventPackage.lookup("dummy") == :error
      assert SIP.EventPackage.names() == []
    end

    test "the name is matched case-insensitively, as Event is" do
      :ok = SIP.EventPackage.register(Dummy)
      assert SIP.EventPackage.lookup("DUMMY") == {:ok, Dummy}
      assert SIP.EventPackage.lookup("Dummy") == {:ok, Dummy}
    end

    test "a module may unregister itself by module name" do
      :ok = SIP.EventPackage.register(Dummy)
      assert :ok = SIP.EventPackage.unregister(Dummy)
      assert SIP.EventPackage.lookup("dummy") == :error
    end

    test "names/0 answers what the node knows, sorted" do
      :ok = SIP.EventPackage.register(Provided, origin: :builtin)
      :ok = SIP.EventPackage.register(Dummy)
      assert SIP.EventPackage.names() == ["dummy", "overridable"]
    end
  end

  describe "an unknown package is a run-time 489, never a boot refusal" do
    test "looking one up answers :error and raises nothing" do
      assert SIP.EventPackage.lookup("dialog") == :error
      assert SIP.EventPackage.lookup("") == :error
    end
  end

  describe "register/2 is idempotent and paired with unregister/1" do
    test "registering the same module twice is a no-op" do
      assert :ok = SIP.EventPackage.register(Dummy)
      assert :ok = SIP.EventPackage.register(Dummy)
      assert SIP.EventPackage.lookup("dummy") == {:ok, Dummy}
      assert SIP.EventPackage.names() == ["dummy"]
    end

    test "unregistering a name nobody claims is still :ok" do
      assert :ok = SIP.EventPackage.unregister("never-registered")
    end

    test "a module that is not a package is refused, and the table is untouched" do
      assert {:error, {:not_an_event_package, NotAPackage}} =
               SIP.EventPackage.register(NotAPackage)

      assert SIP.EventPackage.lookup("impostor") == :error
    end
  end

  describe "collisions are decided at registration" do
    test "a third party overrides a provided package, with a warning naming both" do
      :ok = SIP.EventPackage.register(Provided, origin: :builtin)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert :ok = SIP.EventPackage.register(Operator)
        end)

      assert SIP.EventPackage.lookup("overridable") == {:ok, Operator}
      assert log =~ inspect(Operator)
      assert log =~ inspect(Provided)
    end

    test "a second third party claiming the same name is refused" do
      :ok = SIP.EventPackage.register(Provided, origin: :builtin)
      :ok = SIP.EventPackage.register(Operator)

      assert {:error, {:already_registered, Operator}} =
               SIP.EventPackage.register(SecondOperator)

      assert SIP.EventPackage.lookup("overridable") == {:ok, Operator}
    end

    test "a provided package does not take back a name a third party overrode" do
      :ok = SIP.EventPackage.register(Provided, origin: :builtin)
      :ok = SIP.EventPackage.register(Operator)

      assert {:error, {:already_registered, Operator}} =
               SIP.EventPackage.register(Provided, origin: :builtin)

      assert SIP.EventPackage.lookup("overridable") == {:ok, Operator}
    end

    test "two provided packages claiming one name: the second is refused" do
      :ok = SIP.EventPackage.register(Provided, origin: :builtin)

      assert {:error, {:already_registered, Provided}} =
               SIP.EventPackage.register(Operator, origin: :builtin)
    end

    test "the third party's override survives its own re-registration (a hot reload)" do
      :ok = SIP.EventPackage.register(Provided, origin: :builtin)
      :ok = SIP.EventPackage.register(Operator)
      assert :ok = SIP.EventPackage.register(Operator)
      assert SIP.EventPackage.lookup("overridable") == {:ok, Operator}
    end

    test "a module removed drops its entry, and the name is claimable again" do
      :ok = SIP.EventPackage.register(Provided, origin: :builtin)
      :ok = SIP.EventPackage.register(Operator)
      :ok = SIP.EventPackage.unregister(Operator)

      assert SIP.EventPackage.lookup("overridable") == :error
      assert :ok = SIP.EventPackage.register(SecondOperator)
      assert SIP.EventPackage.lookup("overridable") == {:ok, SecondOperator}
    end
  end

  describe "the dummy package" do
    test "carries a text/plain document, which is what makes P3 testable with no PIDF" do
      assert Dummy.content_types() == ["text/plain"]
      assert Dummy.parse("text/plain", "open") == {:ok, "open"}
      assert {:error, {:unsupported_content_type, _}} = Dummy.parse("application/pidf+xml", "")
      assert Dummy.serialize("text/plain", "open") == {:ok, "open"}
      assert Dummy.min_expires() <= Dummy.default_expires()
      assert Dummy.default_expires() <= Dummy.max_expires()
    end
  end
end
