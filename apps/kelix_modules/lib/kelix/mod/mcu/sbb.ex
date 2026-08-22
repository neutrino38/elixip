defmodule Kelix.Mod.Mcu.SBB do
  @moduledoc """
  The service building blocks `mcu` publishes.

  A kelixip module publishes two kinds of thing: functions a script calls for a
  **decision**, and blocks a script enters for a **sequence**
  (`docs/design/DESIGN-SBB.md#74-a-kelixip-module-publishes-its-blocks`).
  `Kelix.Mod.Mcu.admit/4` is the decision; `conference/1` here is the sequence
  that follows it — the leg's whole life in the mix, which both reference scripts
  were copying, and had already copied differently.

  A script takes it by `use`-ing the module, not this face:

      defmodule MyScript do
        use SIP.Scenario
        use SIP.Session.CallUAS
        use Kelix.Mod.Mcu

        uas(:invite)
        config(uses_modules: [:mcu])

        state in_conference do
          Mcu.SBB.conference()

          on_events do
            {:conference, :renegotiation, %{method: method}} ->
              reply_invite_with_sdp(200, media: :tc, webrtc: :if_offered)
              goto(loop, "\#{method} renegotiated")

            {:conference, :caller_hung_up, _} -> scenario_success("BYE")
            {:conference, :idle_timeout, _}   -> scenario_failure("idle timeout")
          end
        end
      end

  The `Mcu.` prefix is what a reader wants — *which module* provides the verb.
  Aliasing `SBB` instead would collide the moment a script uses two modules that
  both publish blocks.

  `Mcu.SBB.conference()` has one neighbour worth naming: `Kelix.Mod.Mcu.conference/1`,
  the lookup that returns a conference row. They do not collide — one is
  `Mcu.conference(uid)`, the other `Mcu.SBB.conference()`, and the `SBB.` segment
  is what tells a reader that the second enters an FSM. That pair is the reason
  the macro is not published on `Kelix.Mod.Mcu` itself.

  See `Kelix.Mod.Mcu.SBB.Conference` for what the block answers.
  """

  @doc """
  Hold this leg in the mix until something happens the script has a policy for.

  Entered where a script writes `goto(in_call)` today: the call is answered, and
  this takes over from the ACK that puts the leg in the mix to whatever ends it.
  The block never composes a response to an offer — that answer, its media set
  and its error mapping stay with the script — which is why it takes no `media:`
  and no `webrtc:`.

  Options are `sbb_fsm/2`'s, plus one `args` key:

    * `:idle_timeout` — the G3 backstop against a leg that goes silent, in ms
      (2 h by default). **Idle**, not a budget: every event the block consumes
      re-arms it, so it is not a maximum call duration.

  `{:conference, :renegotiation, _}` and `{:conference, :message, _}` hand the
  call back **whole** — nothing answered, nothing released — so the script acts
  and re-enters with `goto(loop, …)`. Every other outcome means the leg is out.
  """
  defmacro conference(opts \\ []) do
    quote do
      sbb_fsm(Kelix.Mod.Mcu.SBB.Conference, unquote(opts))
    end
  end
end
