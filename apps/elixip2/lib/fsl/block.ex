defmodule FSL.Block do
  @moduledoc """
  Declare a **service building block**: a reusable fragment of a flow, written in
  FSL, that a machine enters with `sbb_fsm/2` and that talks back through
  service-level events.

  A block is the **subroutine** of the language: a machine calls it from a state,
  it runs a machine of its own in the caller's process, and it hands control back
  by posting one event. `sbb_fsm/2` and everything below is FSL's — nothing here
  knows a protocol — while a binding wraps it in a facade the way `SIP.SBB`
  wraps it, so a SIP block gets the SIP verbs along with the mechanism.

      defmodule MyApp.Confirming do
        use FSL.Block

        @sbb_namespace :confirm
        @sbb_returns [
          accepted: "the far end agreed — %{}",
          declined: "it said no — %{reason}"
        ]

        @sbb_args [prompt: "what to ask"]
        @sbb_timeout 30_000

        state initial_state do
          notify_parent({:asking, sbb_data_get(:prompt)})
          goto waiting
        end

        state waiting do
          on_events do
            {:parent_msg, :yes} -> sbb_return({:confirm, :accepted, %{}})
            {:parent_msg, {:no, why}} -> sbb_return({:confirm, :declined, %{reason: why}})
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

  ## What a block takes

  `@sbb_args` declares the keys a caller may seed the sandbox with, and it is no
  more decoration than `@sbb_returns`: a call site names them plainly —
  `authenticate(realm: "example.com")`, `call(peer: peer)` — and a key no block
  declares raises instead of becoming a sandbox entry nobody reads. `args: %{…}`
  is the same thing spelled as a map, and both may be mixed.

  ## What a block is, exactly

  The same language as any machine — same `state`, same `on_events`, and whatever
  verbs the binding brought — with two differences:

    * it gains `sbb_return/1`, `sbb_data_get/1` and `sbb_data_set/2`;
    * it has **no `run/1`**, so it can never be mistaken for the machine of the
      `.exs` file that declares it. `FSL.Loader` picks the first module exporting
      `run/1`, and a block declared above the machine in the same file would
      otherwise be loaded and run *as* that machine.

  It runs in the **calling machine's own process**, on that machine's own
  mailbox and resources: a block observes and acts on what its host is doing,
  which is what separates it from `spawn_fsm/2` and its independent child.
  Terminals written inside a block (`scenario_failure`, `scenario_aborted`) keep
  their ordinary meaning and tear the host down too.

  `:ctx_var` and `:host` are passed through to `FSL.Machine`, so a binding's
  facade declares them once for its blocks as it does for its machines.

  Design: `docs/design/DESIGN-SBB.md`.
  """

  defmacro __using__(opts) do
    quote do
      # The completion bound every block carries (S7): a block that never
      # returns would leave its host waiting on an `after` for a subroutine that
      # is not coming. 32 s is inherited from SIP's timer B — the limit a silent
      # callee leaves — and is as good a default as any for a bound that exists
      # to be overridden per block and per call site.
      @sbb_timeout 32_000

      # The vocabulary. The namespace defaults to the block's last name segment,
      # underscored — `MyApp.Confirming` gives `:confirming` — which is right for
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

      # The `args` keys a caller may name at the call site, read inside the block
      # with `sbb_data_get/1`. Declaring them is what lets `sbb_fsm/2` accept them
      # written plainly — `authenticate(realm: "example.com")` — and refuse a key
      # the block does not read. Keys the block only writes for itself
      # (`sbb_data_set/2`) are scratch and do not belong here.
      @sbb_args []

      # Overrides the `{namespace, :timeout, %{block: module}}` the mechanism
      # sends on expiry. Rarely needed: the default already follows the contract.
      @sbb_timeout_event nil

      use FSL.Machine, unquote(Keyword.put(opts, :kind, :sbb))
    end
  end
end
