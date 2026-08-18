defmodule SIP.SBB do
  @moduledoc """
  Declare a **service building block**: a reusable fragment of a call flow,
  written in FSL, that a scenario enters with `sbb_fsm/2` and that talks back
  through service-level events.

      defmodule MyApp.Cancelling do
        use SIP.SBB

        @sbb_namespace :cancel
        @sbb_returns [
          confirmed: "the callee answered the CANCEL with a 487 — %{}",
          answered: "the callee picked up before the CANCEL arrived — %{code}"
        ]

        @sbb_timeout 32_000

        state initial_state do
          on_events do
            {:outbound, {487, _resp, _trans, _dlg}} ->
              sbb_return({:cancel, :confirmed, %{}})

            {:outbound, {200, _resp, _trans, _dlg}} ->
              sbb_return({:cancel, :answered, %{code: 200}})
          end
        end
      end

  ## What a block returns

  Every block returns **`{namespace, outcome, data}`** — the namespace it
  declares, an outcome atom, and a map. The shape is fixed so that a block can
  learn to report one more thing without breaking a host that matches it: a new
  key in `data` is invisible to whoever does not read it, where a fifth tuple
  element would be a compile error in every scenario (S13).

  `@sbb_returns` is the vocabulary itself, and it is not decoration:
  `sbb_return/1` refuses an outcome that is not declared, at compile time, so a
  typo cannot become a host waiting silently on its `after` for an event that
  will never be sent. It defaults to the block's last name segment, downcased.

  When the block is bounded (the default), `:timeout` is added to the vocabulary
  for free and `{namespace, :timeout, %{block: module}}` is what the host
  receives on expiry, unless `@sbb_timeout_event` says otherwise.

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

      # The vocabulary. The namespace defaults to the block's last name segment,
      # underscored — `MyApp.Cancelling` gives `:cancelling` — which is right for
      # a block named after what it does, and overridden by one line when it is
      # not: `SBB.Call.Establish` and `SBB.Call.Bridge` speak `:call` and
      # `:bridge`, after the verb the scenario writes, not after their own name.
      @sbb_namespace __MODULE__
                     |> Module.split()
                     |> List.last()
                     |> Macro.underscore()
                     |> String.to_atom()

      # Outcome -> what it means. Declaring it is what lets sbb_return/1 reject a
      # typo at compile time, and what a host can be told it has not handled.
      @sbb_returns []

      # Overrides the `{namespace, :timeout, %{block: module}}` the mechanism
      # sends on expiry. Rarely needed: the default already follows the contract.
      @sbb_timeout_event nil

      use SIP.Scenario, kind: :sbb
    end
  end
end
