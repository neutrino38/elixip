defmodule SIP.Session.MediaConnOptsTest do
  # FW-1 (docs/design/mcu_module.md §10): a scenario must be able to pass an adapter
  # the context of *this* call — which conference this leg joins, say — without the
  # media macros knowing what it means. The extras travel in the context appdata
  # (`:media_conn_opts`) and are merged into create_peer_connection/3's opts.
  use ExUnit.Case, async: false

  # A stand-in adapter that reports the opts it was handed.
  defmodule ReportingMS do
    def connect(_url), do: {:ok, self()}
    def disconnect(_pid, _opts), do: :ok

    def create_peer_connection(_server, sink, opts) do
      send(sink, {:conn_opts, opts})
      {:ok, spawn(fn -> Process.sleep(:infinity) end)}
    end

    def set_remote_offer(_conn, _sdp), do: {:ok, "v=0\r\n"}
  end

  defp connected_ctx(extras) do
    %SIP.Context{}
    |> SIP.Context.appdata_set(:mediaserver_instance, module: ReportingMS, url: "http://mcu/")
    |> SIP.Session.Media.use_mediaserver()
    |> then(fn ctx ->
      if extras, do: SIP.Context.appdata_set(ctx, :media_conn_opts, extras), else: ctx
    end)
  end

  describe "extra_conn_opts/1" do
    test "reads a keyword list or a map, and tolerates neither being set" do
      assert SIP.Session.Media.extra_conn_opts(%SIP.Context{}) == []

      ctx = SIP.Context.appdata_set(%SIP.Context{}, :media_conn_opts, conference: "c-1")
      assert SIP.Session.Media.extra_conn_opts(ctx) == [conference: "c-1"]

      ctx = SIP.Context.appdata_set(%SIP.Context{}, :media_conn_opts, %{conference: "c-1"})
      assert SIP.Session.Media.extra_conn_opts(ctx) == [conference: "c-1"]

      # a malformed value is ignored rather than crashing the call
      ctx = SIP.Context.appdata_set(%SIP.Context{}, :media_conn_opts, "nonsense")
      assert SIP.Session.Media.extra_conn_opts(ctx) == []
    end
  end

  describe "merging into create_peer_connection/3" do
    test "the extras reach the adapter alongside the macro's own opts" do
      ctx = connected_ctx(conference: "c-3f9a", participant: "alice@example.com")

      {_ctx, {:ok, _answer}} =
        SIP.Session.Media.get_sdp_answer(ctx, "v=0\r\n", webrtc: :no, media: :audio)

      assert_receive {:conn_opts, opts}
      assert Keyword.get(opts, :conference) == "c-3f9a"
      assert Keyword.get(opts, :participant) == "alice@example.com"
      # …and the macro's own options are untouched
      assert Keyword.get(opts, :media) == :audio
      assert Keyword.get(opts, :webrtc_support) == :no
    end

    test "an adapter that knows none of the extras is unaffected (additive by design)" do
      ctx = connected_ctx(nil)

      {_ctx, {:ok, _answer}} =
        SIP.Session.Media.get_sdp_answer(ctx, "v=0\r\n", webrtc: :no, media: :audio)

      assert_receive {:conn_opts, opts}
      assert Keyword.keys(opts) |> Enum.sort() == [:media, :webrtc_support]
    end

    test "the macro's keys win over an extra of the same name" do
      # Keyword.get/3 finds the first occurrence, and the macro's opts come first:
      # `reply_invite_with_sdp(200, media: …)` is the documented way to choose the
      # medias, so it must not be overridable behind the script's back.
      ctx = connected_ctx(media: :video)

      {_ctx, {:ok, _answer}} =
        SIP.Session.Media.get_sdp_answer(ctx, "v=0\r\n", webrtc: :no, media: :audio)

      assert_receive {:conn_opts, opts}
      assert Keyword.get(opts, :media) == :audio
    end
  end
end
