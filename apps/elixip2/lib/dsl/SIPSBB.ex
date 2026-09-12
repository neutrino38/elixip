defmodule SIP.SBB do
  @moduledoc """
  Declare a **SIP** service building block: a reusable fragment of a call flow,
  written in FSL, that a scenario enters with `sbb_fsm/2` and that talks back
  through service-level events.

      defmodule MyApp.Cancelling do
        use SIP.SBB

        @sbb_namespace :cancel
        @sbb_returns [
          confirmed: "the callee answered the CANCEL with a 487 — %{}",
          answered: "the callee picked up before the CANCEL arrived — %{code}"
        ]

        state initial_state do
          on_events do
            {:outbound, {487, _resp, _trans, _dlg}} ->
              sbb_return({:cancel, :confirmed, %{}})

            {:outbound, {200, _resp, _trans, _dlg}} ->
              sbb_return({:cancel, :answered, %{code: 200}})
          end
        end
      end

  `FSL.Block` with the SIP verbs, exactly as `SIP.Scenario` is `FSL.Machine` with
  the SIP verbs — and for the same reason: a block runs in its host's process and
  acts on its host's call, so it speaks the same language *and* the same
  protocol. The example above matches a SIP response and needs `b2bua_*` and
  `reply_*` to be in scope, which is what this facade brings and what a bare
  `use FSL.Block` would not.

  The mechanism itself is **not** SIP's and is not here: what a block is, what it
  returns, what it takes, the sandbox, the completion bound and the
  `{namespace, outcome, data}` contract are all `FSL.Block` and `FSL.Machine`.
  `SBB.Call` (`dsl/sbb/call.ex`) is the other thing that is SIP's — a *concrete*
  call-flow block written in FSL, a consumer of the mechanism rather than part of
  it, which is why the extraction leaves it here (plan §9).

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
