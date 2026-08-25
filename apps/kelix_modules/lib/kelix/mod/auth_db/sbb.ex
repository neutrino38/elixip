defmodule Kelix.Mod.AuthDb.SBB do
  @moduledoc """
  The service building blocks `auth_db` publishes.

  A kelixip module publishes two kinds of thing: functions a script calls for a
  **decision**, and blocks a script enters for a **sequence**
  (`docs/design/DESIGN-SBB.md#74-a-kelixip-module-publishes-its-blocks`).
  `Kelix.Mod.AuthDb.authenticate/3` is the decision; `authenticate/1` here is the
  sequence around it — challenge, wait, verify, challenge again — which every
  script gating a request on a digest was copying verbatim.

  A script takes it by `use`-ing the module, not this face:

      defmodule MyScript do
        use SIP.Scenario
        use Kelix.Mod.AuthDb

        uas(:invite)
        config(uses_modules: [:auth_db])

        state authenticate_caller do
          AuthDb.SBB.authenticate()

          on_events do
            {:auth, :authenticated, %{user: user}} ->
              goto(place_call, "authenticated as \#{user}")

            {:auth, :cancelled, _} ->
              scenario_success("caller cancelled the challenged call")

            {:auth, :caller_gone, %{reason: reason}} ->
              scenario_success("caller gave up: \#{inspect(reason)}")

            {:auth, :timeout, _} ->
              scenario_success("no credentials came back")

            {:auth, :refused, %{attempts: n}} ->
              scenario_success("gave up on this sender after \#{n} attempts")
          end
        end
      end

  The `AuthDb.` prefix is what a reader wants — *which module* provides the verb.
  Aliasing `SBB` instead would collide the moment a script uses two modules that
  both publish blocks, and a script using `registrar` and `auth_db` together is
  the ordinary case.

  See `Kelix.Mod.AuthDb.SBB.Authenticate` for what the block answers.
  """

  @doc """
  Authenticate the sender of the request being served, and hand back what the
  digest proved.

  Options are `sbb_fsm/2`'s, plus these, named plainly at the call site —
  `authenticate(realm: "example.com")` — or under `args:`:

    * `:realm` — the realm to require, defaulting to `sip_ctx.domain`. For an
      INVITE that is the *caller's* domain and not the R-URI's; a node serving
      one domain is right either way (`Kelix.Mod.AuthDb.authenticate/3`);
    * `:code` — 407 (default) or 401. A UA expects the server that routes its
      calls to challenge as a proxy, and many will not retry a 401 on an INVITE;
      a scenario that really is the registrar of the AOR passes 401;
    * `:max_attempts` — how many *rejected* attempts to answer before giving up
      on the sender, 3 by default, `:infinity` to answer forever within the
      block's own deadline.
  """
  defmacro authenticate(opts \\ []) do
    quote do
      sbb_fsm(Kelix.Mod.AuthDb.SBB.Authenticate, unquote(opts))
    end
  end
end
