# Receive a file in chat the way Linphone does (docs/design/DESIGN-CHAT-MEDIA.md
# §2.7): read the RCS XML of the MESSAGE — bare, in CPIM, or beside a caption —
# answer it, download the file and check its size against the XML's.
# (chat-media-plan, S1). Pair it with uac_file_message.exs:
#
#     elixipp --listen udp:5070 apps/elixip2/scenarios/uas_file_message.exs
#
# A MESSAGE naming no file gets a 415, as Linphone's 415 to a type it cannot
# show. One instance runs per MESSAGE.
defmodule UAS.FileMessageExample do
  use SIP.Scenario

  uas(:message)

  # The {:MESSAGE, …} event is already queued by the dialog layer.
  state initial_state do
    goto(wait_message)
  end

  state wait_message do
    on_events do
      {:MESSAGE, req, _trans_pid, _dialog_pid} ->
        case file_info(req) do
          {:ok, info} ->
            reply_message(200)
            appdata_set(:file, info)
            download_file(info, :download)
            goto(downloading, "#{info.name}, #{info.size} octets announced")

          {:error, reason} ->
            reply_message(415)
            scenario_failure("not a file message: #{inspect(reason)}")
        end
    after
      5_000 -> scenario_failure("no MESSAGE received")
    end
  end

  state downloading do
    on_events do
      {:download, {:ok, data}} ->
        if byte_size(data) == appdata_get(:file).size,
          do: scenario_success("#{appdata_get(:file).name}: #{byte_size(data)} octets"),
          else:
            scenario_failure("#{byte_size(data)} octets, #{appdata_get(:file).size} announced")

      {:download, {:error, reason}} ->
        scenario_failure("download failed: #{inspect(reason)}")
    end
  end
end
