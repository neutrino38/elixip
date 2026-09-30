defmodule UAS.Page do
  @moduledoc """
  Built-in page-mode server (RFC 3428), compiled into the app and bundled into
  the `elixipp` escript: answers each out-of-dialog MESSAGE it receives with a
  chosen code, and reports what it received — its kind, its sender, its type
  and size, **never its text** (chat-basic-plan, C1b). Run it by module name:

      elixipp --listen udp:5070 UAS.Page
      elixipp --listen udp:5070 --code 480 UAS.Page     # a device that is not there
      elixipp --listen udp:5070 --code 415 UAS.Page     # one that refuses the type

  `--code` sets `page_code` (200 by default). One instance runs per MESSAGE.

  The editable, file-loadable copy lives in `scenarios/uas_page.exs` (module
  `UAS.PageExample`); this is the canonical bundled version.
  """
  use SIP.Scenario

  uas(:message)

  config(page_code: 200)

  # The {:MESSAGE, …} event is already queued by the dialog layer.
  state initial_state do
    goto(next)
  end

  state wait_message do
    on_events do
      {:MESSAGE, req, _trans_pid, _dialog_pid} ->
        reply_message(appdata_get(:page_code))

        scenario_success("#{appdata_get(:page_code)} to #{SIP.Msg.Ops.page_summary(req)}")
    after
      5_000 -> scenario_failure("no MESSAGE received")
    end
  end
end
