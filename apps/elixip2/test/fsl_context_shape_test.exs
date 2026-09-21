defmodule SIP.Test.FSL.ContextShape do
  @moduledoc """
  The exact shape of `%SIP.Context{}` — its full key set and every default,
  asserted as one literal.

  This is the guard on step 2 of the context migration
  (finite-state-language/elixir/docs/extraction-plan.md §4.1): `SIP.Context`
  becomes `defstruct FSL.Context.fields() ++ [the SIP fields]`, and that step is
  a no-op only if the resulting struct is byte-identical. Nothing else in the
  suite would notice a field silently gaining a different default, or a field
  quietly disappearing from a `defstruct` split in two.

  The second test names the six fields the extraction calls FSL's own — the FSM's
  bookkeeping, as opposed to the SIP session's identity. It is written as a
  partition of the key set, so moving a field to the wrong half fails here rather
  than at the first transition of a scenario.
  """
  use ExUnit.Case, async: true

  # Deliberately spelled out rather than computed. A test that derives the
  # expected shape from the struct it checks pins nothing.
  @expected %{
    username: nil,
    authusername: nil,
    displayname: nil,
    domain: nil,
    ha1: nil,
    ha1b: nil,
    algorithm: "MD5",
    ftag: nil,
    debug: false,
    dialogpid: nil,
    parent_pid: nil,
    lasterr: :ok,
    errorreason: "",
    mediaservermodule: nil,
    mediaserverpid: nil,
    currentstate: nil,
    laststate: nil,
    asserted_identity: nil,
    appdata: %{}
  }

  # The FSM's own state (§4.1 of the extraction plan). `lasterr` is the one a
  # protocol binding writes and FSL reads; the other five are FSL's alone.
  @fsm_fields [:lasterr, :errorreason, :currentstate, :laststate, :parent_pid, :appdata]

  test "every key of %SIP.Context{}, with its default" do
    assert Map.from_struct(%SIP.Context{}) == @expected
  end

  test "the key set is exactly the FSM half plus the SIP half" do
    keys = %SIP.Context{} |> Map.from_struct() |> Map.keys() |> Enum.sort()

    sip_fields = [
      :username,
      :authusername,
      :displayname,
      :domain,
      :ha1,
      :ha1b,
      :algorithm,
      :ftag,
      :debug,
      :dialogpid,
      :mediaservermodule,
      :mediaserverpid,
      :asserted_identity
    ]

    assert keys == Enum.sort(@fsm_fields ++ sip_fields)
    # No overlap: a field belongs to one half or the other, never to both.
    assert @fsm_fields -- sip_fields == @fsm_fields
  end

  test "the FSM fields keep the defaults FSL will inherit" do
    ctx = %SIP.Context{}

    assert ctx.lasterr == :ok
    assert ctx.errorreason == ""
    assert ctx.currentstate == nil
    assert ctx.laststate == nil
    assert ctx.parent_pid == nil
    assert ctx.appdata == %{}
  end

  # The unspaced names are what deployed kelixip scripts read off the struct
  # (`sip_ctx.lasterr`), and a struct field takes no deprecated alias: renaming
  # them at extraction time would be a node that does not start. Pinned so the
  # temptation fails a test rather than a customer.
  test "the FSM field names are the unspaced ones, not the Elixir-style ones" do
    keys = %SIP.Context{} |> Map.from_struct() |> Map.keys()

    for name <- @fsm_fields, do: assert(name in keys)

    for renamed <- [:last_error, :error_reason, :current_state, :last_state] do
      refute renamed in keys
    end
  end

  describe "set/3 and get/2 on the FSM fields" do
    # These four clauses move into FSL.Context (§4.1, step 3), with
    # SIP.Context.set/3 delegating. Both spellings must keep working.
    test "the FSM fields round-trip through the SIP.Context accessors" do
      ctx =
        %SIP.Context{}
        |> SIP.Context.set(:currentstate, :waiting)
        |> SIP.Context.set(:laststate, :initial_state)
        |> SIP.Context.set(:errorreason, "boom")
        |> SIP.Context.set(:lasterr, {:error, :simulated})

      assert SIP.Context.get(ctx, :currentstate) == :waiting
      assert SIP.Context.get(ctx, :laststate) == :initial_state
      assert SIP.Context.get(ctx, :errorreason) == "boom"
      assert SIP.Context.get(ctx, :lasterr) == {:error, :simulated}
    end

    test "appdata_get/2 and appdata_set/3 are the generic slot" do
      ctx = SIP.Context.appdata_set(%SIP.Context{}, :anything, %{a: 1})
      assert SIP.Context.appdata_get(ctx, :anything) == %{a: 1}
      # An unknown atom read through get/2 falls through to appdata.
      assert SIP.Context.get(ctx, :anything) == %{a: 1}
    end
  end

  describe "set/3 on :username" do
    test "the first write mints the From tag" do
      ctx = SIP.Context.set(%SIP.Context{}, :username, "alice")

      assert ctx.username == "alice"
      assert is_binary(ctx.ftag)
    end

    # The `if` that minted the tag had no `else`, so the second write evaluated
    # to nil and the `Map.put` that followed raised a BadMapError — inside
    # whatever state wrote it. A scenario that takes its account from a backend
    # after a `config` default does exactly this.
    test "a second write keeps the tag and does not raise" do
      ctx = SIP.Context.set(%SIP.Context{}, :username, "alice")
      ctx2 = SIP.Context.set(ctx, :username, "bob")

      assert ctx2.username == "bob"
      assert ctx2.ftag == ctx.ftag
    end
  end
end
