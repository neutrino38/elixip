defmodule SIP.SBB do
  @moduledoc """
  Declare a **SIP** service building block: a reusable fragment of a call flow,
  written in FSL, that a scenario enters with `sbb_fsm/2` and that talks back
  through service-level events.

      defmodule MyApp.Cancelling do
        use SIP.SBB

        @sbb_namespace :cancel
        @sbb_returns [confirmed: "the callee answered the CANCEL with a 487 — %{}"]

        state initial_state do
          on_events do
            {:outbound, {487, _resp, _trans, _dlg}} ->
              sbb_return({:cancel, :confirmed, %{}})
          end
        end
      end

  `FSL.Block` with the SIP verbs, exactly as `SIP.Scenario` is `FSL.Machine` with
  the SIP verbs — and for the same reason: a block observes and acts on its
  host's call, so it speaks the same language *and* the same protocol. What a
  block is, what it returns and what it takes are documented on `FSL.Block`.

  The mixins come first for the reason `SIP.Scenario` gives: the context variable
  has to be recorded before a `state` is expanded.
  """

  defmacro __using__(_opts) do
    quote do
      use SIP.Session.CallUAC
      use SIP.Session.Media
      use SIP.Session.B2bua

      use FSL.Block, host: SIP.FSL.Host, ctx_var: :sip_ctx
    end
  end
end
