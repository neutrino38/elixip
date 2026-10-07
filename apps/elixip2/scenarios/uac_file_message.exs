# Send a file in chat the way Linphone does (docs/design/DESIGN-CHAT-MEDIA.md §2):
# upload it to the HTTP store with the account's SIP credentials, then page the
# RCS XML naming it. The node's own way to test a store without a Linphone
# (chat-media-plan, S1). Run it against uas_file_message.exs:
#
#     elixipp --listen udp:5070 apps/elixip2/scenarios/uas_file_message.exs
#     elixipp --to sip:bob@127.0.0.1:5070 apps/elixip2/scenarios/uac_file_message.exs
#
# The defaults are the store rehearsal's (packaging/fhft/rehearsal/): its URL,
# and alice@unit.test, password "secret". `ft_file` is the file to send; its
# type is read from its extension, a `.mka` being a voice message.
defmodule UAC.FileMessageExample do
  use SIP.Scenario

  config(
    username: "alice",
    authusername: "alice",
    displayname: "Alice",
    domain: "unit.test",
    passwd: "secret",
    page_to: "sip:bob@unit.test",
    ft_url: "http://localhost:8089/files/hft.php",
    ft_file: "apps/elixip2/test/fixtures/photo.jpg"
  )

  state initial_state do
    upload_file(appdata_get(:ft_url), appdata_get(:ft_file), :upload)
    goto(uploading)
  end

  state uploading do
    on_events do
      {:upload, {:ok, info}} ->
        appdata_set(:file, info)
        appdata_set(:challenged, false)
        send_file_page(appdata_get(:page_to), info)
        goto(paging, "stored at #{info.url}")

      {:upload, {:error, reason}} ->
        scenario_failure("upload refused: #{inspect(reason)}")
    end
  end

  # A 401 or 407 to the page is answered once, as uac_page.exs does.
  state paging do
    on_events do
      {:page, :answered, %{code: code, response: rsp}} when code in [401, 407] ->
        if appdata_get(:challenged) do
          scenario_failure("page challenged twice: #{code}")
        else
          appdata_set(:challenged, true)
          send_file_page(appdata_get(:page_to), appdata_get(:file), auth: rsp)
          stay("#{code}, answering the challenge")
        end

      {:page, :answered, %{code: code}} when code in [200, 202] ->
        scenario_success("file paged, #{code}")

      {:page, :answered, %{code: code}} ->
        scenario_failure("page refused: #{code}")

      {:page, :failed, %{reason: reason}} ->
        scenario_failure("page not answered: #{inspect(reason)}")
    after
      40_000 -> scenario_failure("page: no answer")
    end
  end
end
