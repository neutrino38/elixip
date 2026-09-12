defmodule SIP.Test.FSL.ContextTest do
  @moduledoc """
  `FSL.Context` on its own: the six fields it owns, the accessors restricted to
  them, and the generic macros bound to whatever a binding calls its context
  variable.

  These tests name no SIP module — `%FSL.Context{}` and a scenario-shaped module
  of their own are enough — which is the point: they follow the code into the
  package (extraction plan §5.1).
  """
  use ExUnit.Case, async: true

  describe "the six fields" do
    test "fields/0 is the list a binding splices into its defstruct" do
      assert FSL.Context.fields() == [
               lasterr: :ok,
               errorreason: "",
               currentstate: nil,
               laststate: nil,
               parent_pid: nil,
               appdata: %{}
             ]

      assert FSL.Context.keys() == [
               :lasterr,
               :errorreason,
               :currentstate,
               :laststate,
               :parent_pid,
               :appdata
             ]
    end

    test "%FSL.Context{} is exactly those fields" do
      assert Map.from_struct(%FSL.Context{}) == Map.new(FSL.Context.fields())
    end
  end

  describe "put/3 and get/2" do
    test "write and read each field" do
      me = self()

      ctx =
        %FSL.Context{}
        |> FSL.Context.put(:currentstate, :waiting)
        |> FSL.Context.put(:laststate, :initial_state)
        |> FSL.Context.put(:errorreason, "boom")
        |> FSL.Context.put(:lasterr, {:error, :simulated})
        |> FSL.Context.put(:parent_pid, me)
        |> FSL.Context.put(:appdata, %{a: 1})

      assert FSL.Context.get(ctx, :currentstate) == :waiting
      assert FSL.Context.get(ctx, :laststate) == :initial_state
      assert FSL.Context.get(ctx, :errorreason) == "boom"
      assert FSL.Context.get(ctx, :lasterr) == {:error, :simulated}
      assert FSL.Context.get(ctx, :parent_pid) == me
      assert FSL.Context.get(ctx, :appdata) == %{a: 1}
    end

    test "put/2 applies a keyword list in order" do
      ctx = FSL.Context.put(%FSL.Context{}, currentstate: :a, laststate: :b)
      assert ctx.currentstate == :a
      assert ctx.laststate == :b
      assert FSL.Context.put(%FSL.Context{}, []) == %FSL.Context{}
    end

    # Restricted on purpose: a context property that is not the FSM's belongs to
    # the binding, and writing it here would bypass whatever the binding
    # validates about it.
    test "refuse a key that is not one of the six" do
      assert_raise ArgumentError, ~r/writes only/, fn ->
        FSL.Context.put(%FSL.Context{}, :username, "alice")
      end

      assert_raise ArgumentError, ~r/reads only/, fn ->
        FSL.Context.get(%FSL.Context{}, :username)
      end
    end

    test "refuse a value the FSM's own invariants rule out" do
      # A state name is an atom; a failure reason is a string; a parent is a pid
      # or nothing at all.
      for {key, bad} <- [currentstate: "waiting", laststate: 42, errorreason: :boom] do
        assert_raise ArgumentError, ~r/is not a valid/, fn ->
          FSL.Context.put(%FSL.Context{}, key, bad)
        end
      end

      assert_raise ArgumentError, ~r/is not a valid/, fn ->
        FSL.Context.put(%FSL.Context{}, :parent_pid, :not_a_pid)
      end

      # `nil` is a parent: it says this FSM runs standalone, which is what makes
      # the parent notifications no-ops rather than a case at each call site.
      assert FSL.Context.put(%FSL.Context{}, :parent_pid, nil).parent_pid == nil
    end

    # `lasterr` is the one field a binding writes and FSL reads, so it takes any
    # term: it carries whatever a verb failed with.
    test "lasterr takes any term" do
      for value <- [:ok, {:error, :timeout}, 503, "nope", %{code: 488}] do
        assert FSL.Context.put(%FSL.Context{}, :lasterr, value).lasterr == value
      end
    end
  end

  describe "appdata" do
    test "round-trips any key, including a tuple" do
      ctx =
        %FSL.Context{}
        |> FSL.Context.appdata_set(:count, 3)
        |> FSL.Context.appdata_set({:sbb, SomeBlock}, %{realm: "example.com"})

      assert FSL.Context.appdata_get(ctx, :count) == 3
      assert FSL.Context.appdata_get(ctx, {:sbb, SomeBlock}) == %{realm: "example.com"}
      assert FSL.Context.appdata_get(ctx, :absent) == nil
    end
  end

  describe "check_struct!/1" do
    # The claim `use FSL.Context` makes: a binding that forgot the six fields
    # fails to compile, rather than crashing on its first transition.
    test "accepts a struct built from fields/0" do
      assert FSL.Context.check_struct!(FSL.Context) == :ok
      assert FSL.Context.check_struct!(SIP.Context) == :ok
    end

    test "refuses one that dropped a field, or redefined its default" do
      assert_raise CompileError, ~r/must splice in/, fn ->
        Code.compile_string("""
        defmodule Bad.NoFsmFields do
          @after_compile FSL.Context
          defstruct username: nil
        end
        """)
      end

      assert_raise CompileError, ~r/must splice in/, fn ->
        Code.compile_string("""
        defmodule Bad.WrongDefault do
          @after_compile FSL.Context
          defstruct Keyword.put(FSL.Context.fields(), :lasterr, :nope)
        end
        """)
      end
    end
  end

  describe "the generic macros" do
    # A binding names its own context variable. This one is not SIP's, which is
    # the whole test: the language does not know how many bindings there are.
    defmodule Machine do
      defstruct FSL.Context.fields() ++ [colour: nil]
      @after_compile FSL.Context

      defmacro __using__(_opts) do
        quote do
          use FSL.Context, ctx_var: :bot_ctx
        end
      end
    end

    defmodule Bot do
      use Machine

      def walk(var!(bot_ctx)) do
        _ = var!(bot_ctx)
        ctx_set(:currentstate, :greeting)
        appdata_set(:greeted, true)
        ctx_set_multiple(laststate: :initial_state, errorreason: "none")

        {ctx_get(:currentstate), appdata_get(:greeted), var!(bot_ctx)}
      end
    end

    test "bind the context variable the binding named, and thread it through" do
      assert {:greeting, true, ctx} = Bot.walk(%Machine{colour: "blue"})

      assert ctx.currentstate == :greeting
      assert ctx.laststate == :initial_state
      assert ctx.errorreason == "none"
      assert ctx.appdata == %{greeted: true}
      # The binding's own fields travel untouched.
      assert ctx.colour == "blue"
    end

    test "a scenario of the default binding reads fsl_ctx" do
      defmodule Plain do
        use FSL.Context

        def walk(var!(fsl_ctx)) do
          _ = var!(fsl_ctx)
          appdata_set(:seen, 1)
          {appdata_get(:seen), var!(fsl_ctx)}
        end
      end

      assert {1, %FSL.Context{appdata: %{seen: 1}}} = Plain.walk(%FSL.Context{})
    end
  end
end
