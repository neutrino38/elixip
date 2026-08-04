defmodule SIP.Session.MediaErrorMappingTest do
  # `on_media_error` as a per-cause function (docs/design/mcu_module.md §6.5): the
  # causes are not equivalent to the caller — an unusable offer is a 488 (retrying it
  # is pointless), a media-server failure a 500 (ours, and a retry may work) — so one
  # code for both tells the peer the wrong thing about what to do next.
  use ExUnit.Case, async: false

  defmodule MockDialog do
    use GenServer

    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, _req, code, reason, _fields}, _from, test) do
      send(test, {:replied, code, reason})
      {:reply, :ok, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
  end

  # An adapter whose offer processing always fails, with the reason under test.
  defmodule FailingMS do
    def connect(_url), do: {:ok, self()}
    def disconnect(_pid, _opts), do: :ok
    def create_peer_connection(_server, _sink, _opts), do: {:ok, self()}
    def set_remote_offer(_conn, _sdp), do: {:error, Application.get_env(:elixip2, :test_ms_error)}
  end

  @offer "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 8\r\n"

  defp reply_with(reason, on_media_error) do
    Application.put_env(:elixip2, :test_ms_error, reason)
    on_exit(fn -> Application.delete_env(:elixip2, :test_ms_error) end)

    {:ok, dialog} = MockDialog.start_link(self())

    ctx =
      %SIP.Context{domain: "example.com", username: "8001", dialogpid: dialog}
      |> SIP.Context.appdata_set(:mediaserver_instance, module: FailingMS, url: "http://mcu/")
      |> SIP.Session.Media.use_mediaserver()
      |> SIP.Context.appdata_set(:last_uas_req, %{
        method: :INVITE,
        body: @offer,
        contenttype: "application/sdp"
      })

    ctx = SIP.Session.CallUAS.do_reply_invite_with_sdp(ctx, 200, on_media_error: on_media_error)
    assert {:media_error, ^reason} = ctx.lasterr
  end

  test "a function maps each cause to its own response" do
    mapper = fn
      :no_common_codec -> {488, "Not Acceptable Here"}
      _other -> {500, "Server Internal Error"}
    end

    reply_with(:no_common_codec, mapper)
    assert_receive {:replied, 488, "Not Acceptable Here"}

    reply_with(:rpc_error, mapper)
    assert_receive {:replied, 500, "Server Internal Error"}
  end

  test "the fixed-pair form still applies to every cause" do
    reply_with(:no_common_codec, {488, "Not Acceptable Here"})
    assert_receive {:replied, 488, "Not Acceptable Here"}

    reply_with(:rpc_error, {488, "Not Acceptable Here"})
    assert_receive {:replied, 488, "Not Acceptable Here"}
  end

  test "the default is 500 when nothing is declared" do
    Application.put_env(:elixip2, :test_ms_error, :boom)
    on_exit(fn -> Application.delete_env(:elixip2, :test_ms_error) end)

    {:ok, dialog} = MockDialog.start_link(self())

    ctx =
      %SIP.Context{domain: "example.com", username: "8001", dialogpid: dialog}
      |> SIP.Context.appdata_set(:mediaserver_instance, module: FailingMS, url: "http://mcu/")
      |> SIP.Session.Media.use_mediaserver()
      |> SIP.Context.appdata_set(:last_uas_req, %{
        method: :INVITE,
        body: @offer,
        contenttype: "application/sdp"
      })

    SIP.Session.CallUAS.do_reply_invite_with_sdp(ctx, 200, [])
    assert_receive {:replied, 500, "Media Server Error"}
  end

  test "a mapper returning nonsense falls back to 500 rather than raising on the failure path" do
    reply_with(:no_common_codec, fn _reason -> :whatever end)
    assert_receive {:replied, 500, "Media Server Error"}
  end
end
