defmodule MediaServerTest do
  use ExUnit.Case, async: true

  describe "media_list/1" do
    test "kind atoms expand to their media list" do
      assert MediaServer.media_list(:audio) == [:audio]
      assert MediaServer.media_list(:video) == [:video]
      assert MediaServer.media_list(:text) == [:text]
      assert MediaServer.media_list(:audio_video) == [:audio, :video]

      for kind <- [:audio_video_text, :total_conversation, :tc] do
        assert MediaServer.media_list(kind) == [:audio, :video, :text]
      end
    end

    test "an explicit list selects exactly those medias, in order" do
      assert MediaServer.media_list([:audio, :video, :text]) == [:audio, :video, :text]
      assert MediaServer.media_list([:audio, :text]) == [:audio, :text]
      assert MediaServer.media_list([:text, :audio]) == [:text, :audio]
    end

    test "kind atoms are expanded in place inside a list" do
      assert MediaServer.media_list([:tc]) == [:audio, :video, :text]
      assert MediaServer.media_list([:audio_video, :text]) == [:audio, :video, :text]
    end

    test "duplicates are dropped while order is preserved" do
      assert MediaServer.media_list([:audio_video, :audio, :text]) == [:audio, :video, :text]
      assert MediaServer.media_list([:audio, :audio]) == [:audio]
    end

    test "an unknown selection raises ArgumentError" do
      assert_raise ArgumentError, ~r/unknown media selection/, fn ->
        MediaServer.media_list(:bogus)
      end

      assert_raise ArgumentError, ~r/unknown media selection/, fn ->
        MediaServer.media_list([:audio, :bogus])
      end
    end
  end
end
