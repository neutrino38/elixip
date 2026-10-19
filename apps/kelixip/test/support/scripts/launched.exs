# A script started by `Kelix.Control.run_script/3`: no SIP request behind it, so it
# is no UAS. It hands what it was asked to do (`run_args`) and the domain it runs on
# to the process registered as `:kelix_launch_test`, then waits to be stopped.
defmodule KelixTest.Launched do
  use SIP.Scenario

  state initial_state do
    send(
      :kelix_launch_test,
      {:launched, SIP.Context.appdata_get(sip_ctx, :run_args), sip_ctx.domain, sip_ctx.dialogpid}
    )

    on_events do
      {:scenario_ctl, :shutdown, _reason} -> scenario_aborted("shutdown")
    after
      30_000 -> scenario_success("timeout")
    end
  end

  on_shutdown do
    scenario_aborted("shutdown")
  end
end
