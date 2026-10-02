# A chat script serving a conversation: takes every MESSAGE it is handed and
# stays, until the conversation goes idle (the SIP host's injected clause ends
# it) or it is shut down. Answers nothing — the dialog pid is a fake — and tells
# the test process, when one is registered, which MESSAGE reached which instance.
defmodule KelixTest.Chatter do
  use SIP.Scenario
  uas(:message)

  state initial_state do
    on_events do
      {:MESSAGE, req, _trans, _dlg} ->
        if sink = Process.whereis(:kelix_conversations_test),
          do: send(sink, {:chatter, self(), req.callid})

        stay("message")
    after
      30_000 -> scenario_success("timeout")
    end
  end

  on_shutdown do
    scenario_aborted("shutdown")
  end
end
