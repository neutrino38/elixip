defmodule SIP.SBB do
  @moduledoc """
  Declare a **service building block**: a reusable fragment of a call flow,
  written in FSL, that a scenario enters with `sbb_fsm/2` and that talks back
  through service-level events.

      defmodule SBB.Cancelling do
        use SIP.SBB

        @sbb_timeout 32_000
        @sbb_timeout_event {:cancel, :never_concluded}

        state initial_state do
          on_events do
            {:outbound, {487, _resp, _trans, _dlg}} -> sbb_return({:cancel, :confirmed})
            {:outbound, {200, _resp, _trans, _dlg}} -> sbb_return({:cancel, :answered})
          end
        end
      end

  A block is the same language as a scenario — same `state`, same `on_events`,
  same session macros — with two differences:

    * it gains `sbb_return/1`, `sbb_data_get/1` and `sbb_data_set/2`;
    * it has **no `run/1`**, so it can never be mistaken for the scenario of the
      `.exs` file that declares it.

  It runs in the calling scenario's own process, on that scenario's dialogs and
  mailbox: a block observes and acts on the host's call, which is what separates
  it from `spawn_fsm/2` and its independent child. Terminals written inside a
  block (`scenario_failure`, `scenario_aborted`) keep their ordinary meaning and
  tear down the host too.

  Design: `docs/design/service-building-block-design.md`; specification and
  catalogue: `docs/design/service-building-block.md`.
  """

  defmacro __using__(_opts) do
    quote do
      # Defaults for the completion bound every block carries (S7). 32 s is
      # timer B, the limit a silent callee leaves.
      @sbb_timeout 32_000
      @sbb_timeout_event {:sbb_timeout, __MODULE__}

      use SIP.Scenario, kind: :sbb
    end
  end
end
