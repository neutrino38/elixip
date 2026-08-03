defmodule Kelix.Mod.Mcu.ConfigTest do
  # The [module.mcu] block (docs/design/mcu_module.md §8.4). Validation is where a
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
      assert config.audio_codecs == ["OPUS", "G722", "PCMA", "PCMU"]
      assert config.dtmf == true
      assert config.video_codecs == ["H264"]
      assert config.max_participants == 20
      assert config.destroy_when_empty == false
      assert config.auto_layout == true

      assert config.video == %{
               size: 6,
               fps: 15,
               bitrate: 1024,
               intra_period: 300,
               fmtp: "profile-level-id=42e01f;packetization-mode=1"
             }

      assert config.xmlrpc_timeout_ms == 10_000
      assert config.gc_orphans == true
      # no range configured ⇒ `did` is mandatory on create (§8.4)
      assert config.did_range == nil
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
      assert {:error, msg} = Config.parse(%{"video_fmtp" => 42})
      assert msg =~ "video_fmtp must be a string"
    end

    test "a codec the SDP layer cannot emit" do
      assert {:error, msg} = Config.parse(%{"audio_codecs" => ["OPUS", "SPEEX"]})
      assert msg =~ "unknown audio codec(s): SPEEX"

      assert {:error, msg} = Config.parse(%{"video_codecs" => ["H265"]})
      assert msg =~ "unknown video_codecs: H265"
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

  describe "codecs" do
    test "TELEPHONE-EVENT is a flag on the audio media, not a mixer codec" do
      config = parse!(%{"audio_codecs" => ["PCMA", "TELEPHONE-EVENT"]})
      assert config.audio_codecs == ["PCMA"]
      assert config.dtmf == true
    end

    test "no TELEPHONE-EVENT means no telephone-event offered" do
      config = parse!(%{"audio_codecs" => ["PCMA"]})
      assert config.dtmf == false
    end

    test "names are case-insensitive" do
      assert parse!(%{"audio_codecs" => ["opus"]}).audio_codecs == ["OPUS"]
    end

    # The H.264 profile the answer states when the offer states none (§6.3). It is a
    # stopgap for L4, so it is tunable without a rebuild — and switchable off.
    test "video_fmtp overrides the announced H.264 profile, and can be emptied" do
      assert parse!(%{"video_fmtp" => "profile-level-id=42801f"}).video.fmtp ==
               "profile-level-id=42801f"

      assert parse!(%{"video_fmtp" => ""}).video.fmtp == ""
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
end
