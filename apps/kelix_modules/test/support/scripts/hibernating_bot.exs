# A long-lived bot (chat-basic-plan, C3d): asks its question on the first
# MESSAGE, then hibernates — at once, or when the connection it came in on
# drops. Woken, it resumes at `awaiting_answer` with `step` as it kept it.
# Answers nothing (the dialog pid is a fake); reports to the test process.
defmodule KelixModTest.HibernatingBot do
  use SIP.Scenario
  uas(:message)

  state initial_state do
    on_events do
      {:MESSAGE, req, _trans, _dlg} ->
        appdata_set(:step, 2)

        case SIP.Msg.Ops.body_string(req) do
          "hibernate now" -> goto(set_aside)
          "keep a pid" -> goto(keep_a_pid)
          _other -> goto(serving)
        end
    after
      5_000 -> scenario_failure("no MESSAGE")
    end
  end

  state serving do
    on_events do
      {:conversation, :transport_down} -> goto(set_aside)
    after
      5_000 -> scenario_failure("never set aside")
    end
  end

  state set_aside do
    hibernate(resume: :awaiting_answer, keep: [:step], ttl: 60)
  end

  state keep_a_pid do
    appdata_set(:owner, self())
    hibernate(resume: :awaiting_answer, keep: [:step, :owner])
  end

  state awaiting_answer do
    on_events do
      {:MESSAGE, _req, _trans, _dlg} ->
        send(:kelix_conversation_test, {:woken, self(), appdata_get(:step)})
        scenario_success("answered")
    after
      5_000 -> scenario_failure("no answer")
    end
  end

  on_shutdown do
    scenario_aborted("shutdown")
  end
end
