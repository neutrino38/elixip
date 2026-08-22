defmodule Kelix.Mod.Mcu.ConfigTest do
  # The [module.mcu] block (docs/design/DESIGN-MCU.md#3-architecture). Validation is where a
  # typo must die: the alternative is a conference that quietly runs on a default.
  use ExUnit.Case, async: true

  alias Kelix.Mod.Mcu.Config

  defp parse!(block) do
    {:ok, config} = Config.parse(block)
    config
  end

  describe "defaults" do
    test "an empty block yields the documented defaults" do
      config = parse!(%{})

      assert config.vad == 1
      assert config.rate == 32_000
      assert config.medias == [:audio, :video, :text]
      assert config.dtmf == true
      assert config.max_participants == 20
      assert config.destroy_when_empty == false
      assert config.auto_layout == true

      # no codec list and no fmtp: the media server arbitrates (P8a, §16.3)
      refute Map.has_key?(config, :audio_codecs)
      assert config.video == %{size: 6, fps: 30, bitrate: 1500, intra_period: 300}

      # Shorter than what the caller waits (`call_timeout_ms`, 5 s): the per-RPC
      # timeout has to fire first, or a slow server turns a call into an exit.
      assert config.xmlrpc_timeout_ms == 2_000
      assert config.xmlrpc_timeout_ms < config.call_timeout_ms
      assert config.gc_orphans == true
      # no range configured ⇒ `did` is mandatory on create (§8.4)
      assert config.did_range == nil
    end

    # One bitrate per node, whichever media path carries the call: an omitted
    # `video_bitrate` is the node's `[mediaserver] video_bitrate`, which the
    # point-to-point adapter also encodes and answers `b=AS:` with.
    test "video_bitrate follows the node's [mediaserver] video_bitrate" do
      assert parse!(%{}).video.bitrate == Kelix.Config.current().mediaserver_video_bitrate
      assert parse!(%{"video_bitrate" => 900}).video.bitrate == 900
    end
  end

  describe "preferred_video_codec (§8.4)" do
    test "no preference by default — the caller's order decides" do
      assert parse!(%{}).preferred_video_codec == nil
    end

    test "a name is accepted case-insensitively and stored as the codec tables spell it" do
      assert parse!(%{"preferred_video_codec" => "h264"}).preferred_video_codec == "H264"
      assert parse!(%{"preferred_video_codec" => "VP8"}).preferred_video_codec == "VP8"
      assert parse!(%{"preferred_video_codec" => "av1"}).preferred_video_codec == "AV1"
    end

    test "`none` is a preference refused, not a name to resolve" do
      assert parse!(%{"preferred_video_codec" => "none"}).preferred_video_codec == nil
    end

    # A codec name nothing can turn into a payload type would sit in the config doing
    # nothing at all, which is the failure mode the retired lists were removed for.
    test "an unknown codec is a boot-time error naming the vocabulary" do
      assert {:error, message} = Config.parse(%{"preferred_video_codec" => "h265"})
      assert message =~ "preferred_video_codec"
      assert message =~ "H264"
    end
  end

  describe "the enum keys take a name (§8.3.7)" do
    test "vad, layout_comp and video_size accept what the CLI renders" do
      config = parse!(%{"vad" => "full", "layout_comp" => "2x2", "video_size" => "vga"})

      assert config.vad == 2
      assert config.layout_comp == 1
      assert config.video.size == 2
    end

    test "the wire id still works, and `none`/`1x1` are not mistaken for absent" do
      config = parse!(%{"vad" => 0, "layout_comp" => 0, "video_size" => 1})

      assert config.vad == 0
      assert config.layout_comp == 0
      assert config.video.size == 1

      config = parse!(%{"vad" => "none", "layout_comp" => "1x1"})
      assert config.vad == 0
      assert config.layout_comp == 0
    end

    test "a typo is a boot-time error naming the key and the vocabulary" do
      assert {:error, msg} = Config.parse(%{"layout_comp" => "2+2"})
      assert msg =~ ~s(layout_comp: unknown mosaic "2+2")
      assert msg =~ "one of 1x1, 2x2"

      assert {:error, msg} = Config.parse(%{"video_size" => "4k"})
      assert msg =~ "video_size: unknown video size"

      assert {:error, msg} = Config.parse(%{"vad" => "loud"})
      assert msg =~ "vad: unknown vad mode"
    end
  end

  describe "rejection" do
    test "an unknown key" do
      assert {:error, msg} = Config.parse(%{"max_participant" => 5})
      assert msg =~ "unknown key(s): max_participant"
    end

    test "a non-integer where an integer is expected" do
      assert {:error, msg} = Config.parse(%{"rate" => "32000"})
      assert msg =~ "rate must be a non-negative integer"
    end

    test "a rate the mixer refuses (AudioMixer::Init, decision 5)" do
      assert {:error, msg} = Config.parse(%{"rate" => 44_100})
      assert msg =~ "rate must be one of"
      assert {:ok, _} = Config.parse(%{"rate" => 48_000})
    end

    test "a vad outside 0..2" do
      assert {:error, _} = Config.parse(%{"vad" => 3})
    end

    test "a non-boolean flag" do
      assert {:error, msg} = Config.parse(%{"auto_layout" => "yes"})
      assert msg =~ "auto_layout must be a boolean"
    end

    test "a non-string where a string is expected" do
      assert {:error, msg} = Config.parse(%{"record_dir" => 42})
      assert msg =~ "record_dir must be a string"
    end

    test "a malformed range" do
      assert {:error, msg} = Config.parse(%{"did_range" => "8000..8099"})
      assert msg =~ ~s(did_range must look like "8000-8099")

      assert {:error, msg} = Config.parse(%{"did_ranges" => %{"a.com" => "9000"}})
      assert msg =~ "did_ranges.a.com"
    end

    test "an inverted range" do
      assert {:error, _} = Config.parse(%{"did_range" => "8099-8000"})
    end

    test "a block that is not a table" do
      assert {:error, "block must be a table"} = Config.parse("nope")
    end
  end

  # P8a: the codec lists are gone, and what replaces them are two policy keys.
  describe "the policy the codec lists used to encode (§8.4)" do
    test "`medias` says which m= sections a conference answers" do
      assert parse!(%{"medias" => ["audio", "text"]}).medias == [:audio, :text]
      assert {:error, msg} = Config.parse(%{"medias" => ["audio", "slides"]})
      assert msg =~ "unknown media(s) slides"
    end

    test "`dtmf` is its own switch, on by default" do
      assert parse!(%{}).dtmf == true
      assert parse!(%{"dtmf" => false}).dtmf == false
      assert {:error, msg} = Config.parse(%{"dtmf" => "no"})
      assert msg =~ "dtmf must be a boolean"
    end
  end

  # §8.4: an RPM-installed node has these in /etc/kelixip/config.toml. Refusing them
  # would turn an upgrade into a node that does not boot, so they are accepted, ignored
  # and warned about — and become an error in the release after.
  describe "the retired codec keys are tolerated for one release" do
    test "they are accepted, they change nothing, and they say so" do
      block = %{
        "audio_codecs" => ["PCMA", "TELEPHONE-EVENT"],
        "video_codecs" => ["H264"],
        "text_codecs" => [],
        "video_fmtp" => "profile-level-id=42801f"
      }

      log = ExUnit.CaptureLog.capture_log(fn -> assert {:ok, _config} = Config.parse(block) end)

      # every one of them is named, with its replacement
      assert log =~ "`audio_codecs` is no longer honoured"
      assert log =~ "`dtmf = false`"
      assert log =~ "`video_codecs` is no longer honoured"
      assert log =~ "`text_codecs` is no longer honoured"
      assert log =~ "`video_fmtp` is no longer honoured"

      config = parse!(block)
      # `text_codecs = []` no longer turns text off — `medias` does, and it is untouched
      assert config.medias == [:audio, :video, :text]
      # nor does an audio list without TELEPHONE-EVENT turn DTMF off any more
      assert config.dtmf == true
      refute Map.has_key?(config.video, :fmtp)
    end

    test "a value of the wrong type is not even looked at" do
      assert {:ok, _config} = Config.parse(%{"audio_codecs" => "PCMA"})
    end
  end

  describe "ranges" do
    test "range_for/2 prefers the per-domain range, falls back to the block-wide one" do
      config =
        parse!(%{
          "did_range" => "8000-8099",
          "did_ranges" => %{"lab.example.com" => "9000-9099"}
        })

      assert Config.range_for(config, "lab.example.com") == {9000, 9099}
      assert Config.range_for(config, "example.com") == {8000, 8099}
    end

    test "no range at all" do
      assert Config.range_for(parse!(%{}), "example.com") == nil
    end
  end

  describe "the media servers moved to [mediaserver.pool.*]" do
    # The block is refused rather than ignored: an operator upgrading a node that
    # worked would otherwise get a module with no media server at all, and discover
    # it on the first call.
    test "the old sub-block is refused, with the migration in the message" do
      assert {:error, msg} =
               Config.parse(%{"mediaserver" => %{"mcu1" => %{"url" => "http://x:8080"}}})

      assert msg =~ "[mediaserver.pool.<name>]"
      assert msg =~ "rtp_ip"
    end

    test "so is a bare `mediaserver` key" do
      assert {:error, msg} = Config.parse(%{"mediaserver" => "http://x:8080"})
      assert msg =~ "[mediaserver.pool.<name>]"
    end

    test "and the block carries no media server list any more" do
      refute Map.has_key?(parse!(%{}), :mcus)
    end
  end

  test "validate_config/1 is exactly parse/1's verdict" do
    assert Kelix.Mod.Mcu.validate_config(%{"vad" => 2}) == :ok
    assert {:error, _} = Kelix.Mod.Mcu.validate_config(%{"vad" => 9})
    assert {:error, _} = Kelix.Mod.Mcu.validate_config("nope")
  end

  # The [module.mcu] block the packages ship is commented out, so nothing would ever
  # tell us it stopped parsing: an operator uncommenting it is the first one to find
  # out, at boot, on their node. Uncomment it here and hand it to the real parser —
  # a renamed key or a value the vocabulary no longer knows fails in CI instead (P6,
  # §13).
  test "the [module.mcu] block shipped in packaging/config/config.toml still parses" do
    path = Path.expand("../../../packaging/config/config.toml", __DIR__)

    uncommented =
      path
      |> File.read!()
      |> String.split("\n")
      |> Enum.drop_while(&(not String.starts_with?(&1, "#[module.mcu]")))
      |> Enum.take_while(&(&1 != ""))
      # the header and the `#key = value` lines; the prose comments in between are
      # not TOML and an operator does not uncomment them either
      |> Enum.filter(&Regex.match?(~r/^#(\[module\.mcu\]|[a-z_]+ *=)/, &1))
      |> Enum.map_join("\n", &String.trim_leading(&1, "#"))

    assert uncommented =~ "[module.mcu]", "the sample block is gone from #{path}"

    {:ok, toml} = Toml.decode(uncommented)
    config = parse!(toml["module"]["mcu"])

    # a couple of values, so the test also proves it was the sample that parsed
    assert config.did_range == {8000, 8099}
    assert config.record_dir =~ "/"
  end

  describe "medias (§8.4, P8a)" do
    test "names which m= sections a conference answers" do
      assert {:ok, config} = Config.parse(%{"medias" => ["audio", "text"]})
      assert config.medias == [:audio, :text]
    end

    test "an unknown media names the vocabulary" do
      assert {:error, msg} = Config.parse(%{"medias" => ["audio", "hologram"]})
      assert msg =~ "hologram"
      assert msg =~ "audio, video or text"
    end

    test "an empty list is refused: a conference that answers nothing is a mistake" do
      assert {:error, msg} = Config.parse(%{"medias" => []})
      assert msg =~ "at least one"
    end
  end

  describe "the collaboration channel (§20.8)" do
    test "closed by default, opened by naming the kinds" do
      assert {:ok, closed} = Config.parse(%{})
      assert closed.message_kinds == []
      assert closed.message_rate == 5
      assert closed.message_max_bytes == 1024
      assert closed.message_queue_max == 100

      assert {:ok, open} = Config.parse(%{"message_kinds" => ["hand.raised"]})
      assert open.message_kinds == ["hand.raised"]
    end

    test "a kind is a lower-case dotted token — anything else is refused by name" do
      assert {:error, msg} = Config.parse(%{"message_kinds" => ["Hand Raised"]})
      assert msg =~ "Hand Raised"
      assert msg =~ "hand.raised"

      assert {:error, msg} = Config.parse(%{"message_kinds" => [42]})
      assert msg =~ "42"

      assert {:error, msg} = Config.parse(%{"message_kinds" => "hand.raised"})
      assert msg =~ "must be a list"
    end

    test "the bounds are integers" do
      assert {:error, msg} = Config.parse(%{"message_rate" => "fast"})
      assert msg =~ "message_rate"

      assert {:error, _} = Config.parse(%{"message_max_bytes" => -1})
      assert {:ok, config} = Config.parse(%{"message_rate" => 1, "message_max_bytes" => 64})
      assert config.message_rate == 1
      assert config.message_max_bytes == 64
    end
  end
end
