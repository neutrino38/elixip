defmodule Kelix.Mod.Mcu.Config do
  @moduledoc """
  The validated `[module.mcu]` block (design `docs/design/mcu_module.md` §8.4).

  `parse/1` is the single reading of the TOML block: it is what
  `Kelix.Mod.Mcu.validate_config/1` runs (so a typo is a boot-time config error,
  never a silent default) **and** what the running module holds, so validation and
  behaviour can never drift apart.

  What lives here rather than in the module: the **DID allocation ranges**
  (`did_range` / `did_ranges`, §5.3).

  What is deliberately **not** here: the media servers. They are declared once, in
  `[mediaserver.pool.<name>]`, and the module opens one control channel per entry
  (§8.4) — a conference is still pinned to one of them, but where the list is
  *declared* is not what pins it.

  And no longer here either: the **codec lists**. `audio_codecs`, `video_codecs`,
  `text_codecs` and `video_fmtp` are gone with P8a — the offer is the menu and the
  media server arbitrates (§16.3, §6.3.2). What they were really encoding survives as
  two keys that say it directly: `medias` (which `m=` sections a conference answers)
  and `dtmf` (whether telephone-event is proposed at all). The four are still
  *accepted* for one release, ignored with a warning naming the replacement, because
  an RPM-installed node has them in `/etc/kelixip/config.toml` and refusing them
  outright turns an upgrade into a node that will not boot (§8.4).
  """

  require Logger

  alias Kelix.Mod.Mcu.Vocabulary

  @type range :: {pos_integer, pos_integer}

  @type t :: %__MODULE__{}

  defstruct vad: 1,
            rate: 32_000,
            # Which m= sections a conference answers at all (§8.4). Codec NAMES are the
            # media server's business since P8a; this is a deployment policy — an
            # audio-only conference is a product decision, not a codec capability, and
            # dropping `text` here is what `text_codecs = []` used to mean.
            medias: [:audio, :video, :text],
            # Whether telephone-event is proposed on audio (§6.3.2). Also a policy and
            # not a codec: it is an RFC 4733 stream the mixer never encodes, and it is
            # what `TELEPHONE-EVENT` in the old `audio_codecs` list was really saying.
            dtmf: true,
            max_participants: 20,
            destroy_when_empty: false,
            auto_layout: true,
            layout_comp: 1,
            # The inline video profile, copied into every conference at create time:
            # what the mixer encodes towards every leg. There is no `fmtp` here any
            # more — what the answer advertises for H.264 is what the media server
            # reported it accepted (§6.3 rule 9), and announcing a profile the encoder
            # was not configured with is the drift that key invited.
            video: %{size: 6, fps: 15, bitrate: 1024, intra_period: 300},
            did_range: nil,
            did_ranges: %{},
            # Recording and images (§8.3.8). Paths on the **media server's**
            # filesystem: the module resolves a validated basename under them and
            # never lets a client send a path of its own. No default — a directory
            # guessed for a host we cannot see would fail inside the server, one
            # recording at a time, so an unset key is a clear refusal instead.
            record_dir: nil,
            image_dir: nil,
            # Drawn in every empty mosaic slot of every conference, unless the
            # conference names its own `logo`.
            logo_file: nil,
            xmlrpc_timeout_ms: 10_000,
            call_timeout_ms: 5_000,
            shutdown_grace_ms: 5_000,
            rtp_timeout_ms: 10_000,
            gc_orphans: true

  # AudioMixer::Init refuses anything else (§15, decision 5)
  @rates [8000, 16_000, 32_000, 48_000]

  # `vad`, `layout_comp` and `video_size` accept a human name as well as the wire id
  # (`layout_comp = "2x2"`, `video_size = "vga"`, `vad = "full"`, §8.3.7), decoded by
  # the same `Vocabulary` the control commands and the CLI labels use. They are
  # therefore **not** in @int_keys: a name is not a malformed integer.
  @int_keys ~w(rate max_participants video_fps video_bitrate
               video_intra_period xmlrpc_timeout_ms call_timeout_ms shutdown_grace_ms
               rtp_timeout_ms)
  @bool_keys ~w(dtmf destroy_when_empty auto_layout gc_orphans)
  @string_keys ~w(record_dir image_dir logo_file)

  # The keys P8a retired, with what replaces each. Accepted for one release and
  # ignored with a warning (§8.4): they sit in the config file of every node this
  # release upgrades, and a node that refuses to boot is a worse migration than a
  # node that says what it stopped honouring. Reject them in the release after.
  @retired_keys %{
    "audio_codecs" =>
      "the media server decides which codecs it accepts; use `dtmf = false` to stop " <>
        "proposing telephone-event and `medias` to turn a media off",
    "video_codecs" => "the media server decides which codecs it accepts; see `medias`",
    "text_codecs" =>
      "the media server decides which codecs it accepts; drop \"text\" from `medias` " <>
        "to turn text off",
    "video_fmtp" => "the H.264 profile answered is the one the media server reported it accepted"
  }

  @keys ~w(module call_timeout_ms vad rate medias dtmf
           max_participants destroy_when_empty auto_layout layout_comp did_range
           did_ranges video_size video_fps video_bitrate video_intra_period
           xmlrpc_timeout_ms shutdown_grace_ms rtp_timeout_ms gc_orphans
           record_dir image_dir logo_file) ++ Map.keys(@retired_keys)

  @doc """
  Validate and decode a `[module.mcu]` block. `{:ok, %Config{}}` or
  `{:error, message}` naming the offending key.
  """
  @spec parse(map) :: {:ok, t} | {:error, String.t()}
  def parse(block) when is_map(block) do
    with :ok <- reject_moved_mediaserver(block),
         :ok <- reject_unknown_keys(block),
         :ok <- warn_retired_keys(block),
         :ok <- check_ints(block),
         :ok <- check_bools(block),
         :ok <- check_strings(block),
         :ok <- check_enum(block, "rate", @rates),
         {:ok, vad} <- Vocabulary.vad(Map.get(block, "vad"), "vad"),
         {:ok, layout_comp} <- Vocabulary.comp(Map.get(block, "layout_comp"), "layout_comp"),
         {:ok, video_size} <- Vocabulary.size(Map.get(block, "video_size"), "video_size"),
         {:ok, medias} <- medias(block),
         {:ok, did_range} <- did_range(block, "did_range"),
         {:ok, did_ranges} <- did_ranges(block) do
      defaults = %__MODULE__{}

      {:ok,
       %__MODULE__{
         # an absent enum decodes to nil, so `||` picks the default — and it is safe
         # for the id `0` (vad `none`, mosaic `1x1`), which is truthy here
         vad: vad || defaults.vad,
         rate: int(block, "rate", defaults.rate),
         medias: medias,
         dtmf: bool(block, "dtmf", defaults.dtmf),
         max_participants: int(block, "max_participants", defaults.max_participants),
         destroy_when_empty: bool(block, "destroy_when_empty", defaults.destroy_when_empty),
         auto_layout: bool(block, "auto_layout", defaults.auto_layout),
         layout_comp: layout_comp || defaults.layout_comp,
         video: %{
           size: video_size || defaults.video.size,
           fps: int(block, "video_fps", defaults.video.fps),
           bitrate: int(block, "video_bitrate", defaults.video.bitrate),
           intra_period: int(block, "video_intra_period", defaults.video.intra_period)
         },
         did_range: did_range,
         did_ranges: did_ranges,
         xmlrpc_timeout_ms: int(block, "xmlrpc_timeout_ms", defaults.xmlrpc_timeout_ms),
         call_timeout_ms: int(block, "call_timeout_ms", defaults.call_timeout_ms),
         shutdown_grace_ms: int(block, "shutdown_grace_ms", defaults.shutdown_grace_ms),
         rtp_timeout_ms: int(block, "rtp_timeout_ms", defaults.rtp_timeout_ms),
         gc_orphans: bool(block, "gc_orphans", defaults.gc_orphans),
         record_dir: str(block, "record_dir", defaults.record_dir),
         image_dir: str(block, "image_dir", defaults.image_dir),
         logo_file: str(block, "logo_file", defaults.logo_file)
       }}
    end
  end

  def parse(_block), do: {:error, "block must be a table"}

  @doc """
  The allocation range serving `domain`: its `did_ranges` entry, else the
  block-wide `did_range`, else `nil` (which makes `did` mandatory on create).
  """
  @spec range_for(t, String.t()) :: range | nil
  def range_for(%__MODULE__{} = config, domain) when is_binary(domain),
    do: Map.get(config.did_ranges, domain) || config.did_range

  @doc """
  The retired keys, mapped to what replaces each.

  Exported because the same tolerance applies to `conference.create` / `update`
  arguments (§8.4): those come from scripts we do not own, so they are ignored with a
  warning rather than answered `400`. One statement of what is retired and why, read by
  both the config block and the control commands.
  """
  @spec retired_keys() :: %{String.t() => String.t()}
  def retired_keys(), do: @retired_keys

  @doc """
  Log one warning per retired key present in `given`, naming its replacement.

  `context` says where they came from, so an operator can tell a stale config file from
  a stale script. Always returns `:ok` — this is a migration aid, never a refusal.
  """
  @spec warn_retired(Enumerable.t(), String.t()) :: :ok
  def warn_retired(given, context) do
    for key <- given, replacement = Map.get(@retired_keys, to_string(key)) do
      Logger.warning(
        module: __MODULE__,
        message:
          "#{context}: `#{key}` is no longer honoured and was ignored — #{replacement} " <>
            "(remove it: it becomes an error in the next release)"
      )
    end

    :ok
  end

  # ── per-key validation ───────────────────────────────────────────────────────

  # The media servers moved out of this block into `[mediaserver.pool.<name>]`, which
  # the point-to-point path already used. Named explicitly rather than left to
  # `reject_unknown_keys/1`: an operator upgrading a working node deserves the
  # migration, not "unknown key: mediaserver".
  defp reject_moved_mediaserver(block) do
    if Map.has_key?(block, "mediaserver") do
      {:error,
       "[module.mcu.mediaserver.<name>] is gone: declare each media server once in " <>
         "[mediaserver.pool.<name>] (module + url). `rtp_ip`/`public_ip` are no longer " <>
         "needed either — the media server reports the address to announce itself"}
    else
      :ok
    end
  end

  defp reject_unknown_keys(block) do
    case Map.keys(block) -- @keys do
      [] -> :ok
      extra -> {:error, "unknown key(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  defp warn_retired_keys(block), do: warn_retired(Map.keys(block), "[module.mcu]")

  defp check_ints(block) do
    Enum.reduce_while(@int_keys, :ok, fn key, :ok ->
      case Map.get(block, key) do
        nil -> {:cont, :ok}
        v when is_integer(v) and v >= 0 -> {:cont, :ok}
        _ -> {:halt, {:error, "#{key} must be a non-negative integer"}}
      end
    end)
  end

  defp check_strings(block) do
    Enum.reduce_while(@string_keys, :ok, fn key, :ok ->
      case Map.get(block, key) do
        nil -> {:cont, :ok}
        v when is_binary(v) -> {:cont, :ok}
        _ -> {:halt, {:error, "#{key} must be a string"}}
      end
    end)
  end

  defp check_bools(block) do
    Enum.reduce_while(@bool_keys, :ok, fn key, :ok ->
      case Map.get(block, key) do
        nil -> {:cont, :ok}
        v when is_boolean(v) -> {:cont, :ok}
        _ -> {:halt, {:error, "#{key} must be a boolean"}}
      end
    end)
  end

  defp check_enum(block, key, allowed) do
    case Map.get(block, key) do
      nil -> :ok
      v -> if v in allowed, do: :ok, else: {:error, "#{key} must be one of #{inspect(allowed)}"}
    end
  end

  # Which m= sections a conference answers. Names only — the codecs inside them are
  # the media server's call since P8a. An empty list would be a conference that
  # answers nothing, so it is refused rather than silently accepted.
  @media_names ~w(audio video text)

  defp medias(block) do
    case Map.get(block, "medias") do
      nil ->
        {:ok, defaults().medias}

      names when is_list(names) ->
        names = Enum.map(names, &String.downcase(to_string(&1)))

        case Enum.reject(names, &(&1 in @media_names)) do
          [] when names != [] ->
            {:ok, Enum.map(names, &String.to_existing_atom/1)}

          [] ->
            {:error, "medias must name at least one of #{Enum.join(@media_names, ", ")}"}

          bad ->
            {:error, "unknown media(s) #{Enum.join(bad, ", ")}; expected audio, video or text"}
        end

      _ ->
        {:error, "medias must be a list of media names"}
    end
  end

  # "8000-8099" → {8000, 8099}
  defp did_range(block, key) do
    case Map.get(block, key) do
      nil -> {:ok, nil}
      spec -> parse_range(spec, key)
    end
  end

  defp did_ranges(block) do
    case Map.get(block, "did_ranges") do
      nil ->
        {:ok, %{}}

      map when is_map(map) ->
        Enum.reduce_while(map, {:ok, %{}}, fn {domain, spec}, {:ok, acc} ->
          case parse_range(spec, "did_ranges.#{domain}") do
            {:ok, range} -> {:cont, {:ok, Map.put(acc, domain, range)}}
            err -> {:halt, err}
          end
        end)

      _ ->
        {:error, "did_ranges must be a table of domain = \"lo-hi\""}
    end
  end

  defp parse_range(spec, key) when is_binary(spec) do
    with [lo, hi] <- String.split(spec, "-", parts: 2),
         {lo_i, ""} <- Integer.parse(String.trim(lo)),
         {hi_i, ""} <- Integer.parse(String.trim(hi)),
         true <- lo_i <= hi_i do
      {:ok, {lo_i, hi_i}}
    else
      _ -> {:error, ~s(#{key} must look like "8000-8099")}
    end
  end

  defp parse_range(_spec, key), do: {:error, ~s(#{key} must look like "8000-8099")}

  # The struct is the single statement of every default, so a `parse/1` clause that
  # needs one before building it reads it here rather than repeating the literal.
  defp defaults(), do: %__MODULE__{}

  defp int(block, key, default) do
    case Map.get(block, key) do
      v when is_integer(v) -> v
      _ -> default
    end
  end

  defp str(block, key, default) do
    case Map.get(block, key) do
      v when is_binary(v) -> v
      _ -> default
    end
  end

  defp bool(block, key, default) do
    case Map.get(block, key) do
      v when is_boolean(v) -> v
      _ -> default
    end
  end
end
