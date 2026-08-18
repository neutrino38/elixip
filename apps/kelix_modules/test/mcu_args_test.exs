defmodule Kelix.Mod.Mcu.ArgsTest do
  # Arg normalisation: the same command must see the same map from REST and from
  # kelictl (docs/design/mcu_module.md §8.3.6).
  use ExUnit.Case, async: true

  alias Kelix.Mod.Mcu.Args

  describe "normalize/1" do
    test "a REST body passes through" do
      assert Args.normalize(%{"domain" => "example.com", "vad" => 1}) ==
               %{"domain" => "example.com", "vad" => 1}
    end

    test "CLI k=v tokens become the same map" do
      assert Args.normalize(%{"args" => ["domain=example.com", "name=Weekly"]}) ==
               %{"domain" => "example.com", "name" => "Weekly"}
    end

    test "CLI values are typed by their syntax" do
      args = Args.normalize(%{"args" => ["vad=1", "force=true", "off=false", "name=8001"]})

      assert args["vad"] == 1
      assert args["force"] == true
      assert args["off"] == false
      # a numeric-looking name is still an integer here; the getter that wants a
      # string accepts it and stringifies (a DID typed as a number)
      assert args["name"] == 8001
      assert {:ok, "8001"} = Args.string(args, "name")
    end

    test "a JSON value is decoded, which is what makes layout='{…}' work" do
      args = Args.normalize(%{"args" => [~s(layout={"comp":1,"size":6}), ~s(codecs=["PCMA"])]})

      assert args["layout"] == %{"comp" => 1, "size" => 6}
      assert args["codecs"] == ["PCMA"]
    end

    test "a bare token is a flag" do
      assert Args.normalize(%{"args" => ["force"]}) == %{"force" => true}
    end

    test "broken JSON stays a string rather than failing the whole command" do
      assert Args.normalize(%{"args" => ["layout={oops"]}) == %{"layout" => "{oops"}
    end

    test "path/query params merged by the frontal survive alongside CLI tokens" do
      assert Args.normalize(%{"uid" => "c-1", "args" => ["force=true"]}) ==
               %{"uid" => "c-1", "force" => true}
    end
  end

  describe "guards" do
    test "reject_unknown/2 names the offending arguments" do
      assert :ok = Args.reject_unknown(%{"domain" => "x"}, ~w(domain name))

      assert {:error, msg} = Args.reject_unknown(%{"max_participant" => 5}, ~w(max_participants))
      assert msg =~ "unknown argument(s): max_participant"
    end

    test "reject_readonly/2 refuses a server-owned field (§8.3.3 PUT semantics)" do
      assert :ok = Args.reject_readonly(%{"name" => "x"}, ~w(uid conf_id))

      assert {:error, msg} = Args.reject_readonly(%{"conf_id" => 42}, ~w(uid conf_id))
      assert msg =~ "read-only field(s): conf_id"
    end
  end

  describe "getters" do
    test "required_string/2" do
      assert {:ok, "example.com"} = Args.required_string(%{"domain" => "example.com"}, "domain")
      assert {:error, "domain is required"} = Args.required_string(%{}, "domain")
      assert {:error, msg} = Args.required_string(%{"domain" => 1}, "domain")
      assert msg =~ "must be a string"
    end

    test "int/4 enforces the allowed set" do
      assert {:ok, 2} = Args.int(%{"vad" => 2}, "vad", nil, [0, 1, 2])
      assert {:ok, nil} = Args.int(%{}, "vad", nil, [0, 1, 2])
      assert {:error, _} = Args.int(%{"vad" => 7}, "vad", nil, [0, 1, 2])
      assert {:error, _} = Args.int(%{"vad" => "2"}, "vad", nil, [0, 1, 2])
      assert {:error, _} = Args.int(%{"n" => -1}, "n", nil)
    end

    test "bool/3" do
      assert {:ok, true} = Args.bool(%{"force" => true}, "force", false)
      assert {:ok, false} = Args.bool(%{}, "force", false)
      assert {:error, _} = Args.bool(%{"force" => "yes"}, "force", false)
    end

    test "sub_map/4 merges over the default and refuses unknown fields" do
      default = %{size: 6, fps: 15, bitrate: 1500, intra_period: 300}

      assert {:ok, merged} =
               Args.sub_map(%{"video" => %{"fps" => 25}}, "video", default, [
                 :size,
                 :fps,
                 :bitrate,
                 :intra_period
               ])

      # a partial update keeps the rest of the profile
      assert merged == %{default | fps: 25}

      assert {:ok, ^default} = Args.sub_map(%{}, "video", default, [:size, :fps])

      assert {:error, msg} =
               Args.sub_map(%{"video" => %{"framerate" => 25}}, "video", default, [:fps])

      assert msg =~ "video: unknown field(s): framerate"

      assert {:error, msg} =
               Args.sub_map(%{"video" => %{"fps" => "25"}}, "video", default, [:fps])

      assert msg =~ "video.fps must be an integer"
    end
  end
end
