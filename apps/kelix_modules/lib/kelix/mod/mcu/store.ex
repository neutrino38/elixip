defmodule Kelix.Mod.Mcu.Store do
  @moduledoc """
  The persistent conference **definitions** on disk (design `docs/design/mcu_module.md`
  §9.5).

  One JSON file, read once at module start and rewritten whole every time a definition
  changes. What it holds is a definition and never a runtime state: `conf_id`,
  `participants`, `stale` and `recording` cannot reach it — the encoder names the fields
  it writes, one by one, so a field added to the struct is absent from the file until
  someone decides it belongs there. A restored row is a room, not a call: its MCU-side
  existence is rebuilt by the recovery path of §9.2, which already recreates a `stale`
  conference under the same `uid`.

  **JSON**, because the `toml` dependency only reads and an operator must be able to
  read what a node will bring back. Not `:mnesia`: its schema is bound to the node name
  an `/etc/default/kelixip` edit can change, and this module is hot-loadable, so it
  would own tables across its own reloads for a data set that fits in a page.

  **Atomic on write** — a sibling `.tmp` then a rename inside the same directory — so a
  node killed mid-save loses the last change and never the file.

  Reading is **tolerant per row and strict per file**: one malformed conference is
  skipped with its `uid` named, since a single bad room must not cost every room, while
  a file that does not parse at all disables persistence for the run rather than being
  overwritten. Values may be written as the CLI names them (`"vad": "full"`,
  `"video": {"size": "hd720p"}`): the vocabularies that accept an operator's input at
  the control surface are the ones that read this file, so a hand-edited entry means
  here exactly what it means there.
  """

  require Logger

  alias Kelix.Mod.Mcu.{Conference, Vocabulary}

  # Bumped when the shape changes in a way an older node cannot read. A file from a
  # NEWER version is refused whole: guessing which keys survived a downgrade is how a
  # restart quietly redefines a room.
  @version 1

  @medias %{"audio" => :audio, "video" => :video, "text" => :text}

  @doc """
  The conferences a file holds, ready to be inserted as `stale` rows.

  `{:ok, []}` when the file does not exist yet — a first start is not a failure.
  `{:error, reason}` when it exists and cannot be read or parsed, which the caller
  turns into "persistence off for this run" so nothing overwrites it.
  """
  @spec load(Path.t()) :: {:ok, [Conference.t()]} | {:error, term}
  def load(path) do
    case File.read(path) do
      {:ok, body} -> decode_file(body, path)
      {:error, :enoent} -> {:ok, []}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Write `conferences` as the whole content of `path`.

  A whole-file rewrite and not a delta: the file *is* the set of persistent rooms, and
  a set written in one move cannot half-apply.
  """
  @spec save(Path.t(), [Conference.t()]) :: :ok | {:error, term}
  def save(path, conferences) do
    document = %{"version" => @version, "conferences" => Enum.map(conferences, &encode/1)}

    with {:ok, body} <- Jason.encode(document, pretty: true),
         tmp = path <> ".tmp",
         :ok <- File.write(tmp, [body, "\n"]),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, reason} -> {:error, reason}
      %Jason.EncodeError{} = err -> {:error, err}
    end
  end

  # ── encoding ─────────────────────────────────────────────────────────────────

  # Field by field, deliberately: `Map.from_struct/1` would carry the runtime half of a
  # conference into the file the day someone adds a field to the struct.
  defp encode(%Conference{} = conf) do
    %{
      "uid" => conf.uid,
      "domain" => conf.domain,
      "did" => conf.did,
      "name" => conf.name,
      # the media server this room is pinned to (§1.3). A name and not an address: the
      # pool may well have moved the URL while the node was down
      "mcu" => conf.mcu,
      "vad" => conf.vad,
      "rate" => conf.rate,
      "medias" => Enum.map(conf.medias, &Atom.to_string/1),
      "dtmf" => conf.dtmf,
      "video" => %{
        "size" => conf.video.size,
        "fps" => conf.video.fps,
        "bitrate" => conf.video.bitrate,
        "intra_period" => conf.video.intra_period
      },
      "preferred_video_codec" => conf.preferred_video_codec,
      "layout" => %{
        "comp" => conf.layout.comp,
        "size" => conf.layout.size,
        "auto" => conf.layout.auto
      },
      "logo" => conf.logo,
      # the slots WE pinned — operator policy, replayed on a recreated conference
      # (§8.3.8), so a restart must not be what forgets them
      "slots" => Map.new(conf.slots, fn {slot, value} -> {Integer.to_string(slot), value} end),
      "max_participants" => conf.max_participants,
      "destroy_when_empty" => conf.destroy_when_empty,
      "created_at" => conf.created_at && DateTime.to_iso8601(conf.created_at)
    }
  end

  # ── decoding ─────────────────────────────────────────────────────────────────

  defp decode_file(body, path) do
    case Jason.decode(body) do
      {:ok, %{"conferences" => rows} = document} when is_list(rows) ->
        with :ok <- check_version(Map.get(document, "version")) do
          {:ok, decode_rows(rows, path)}
        end

      {:ok, other} ->
        {:error, {:bad_document, other}}

      {:error, %Jason.DecodeError{} = err} ->
        {:error, err}
    end
  end

  defp check_version(version) when is_integer(version) and version <= @version, do: :ok
  defp check_version(other), do: {:error, {:unsupported_version, other}}

  defp decode_rows(rows, path) do
    Enum.flat_map(rows, fn row ->
      case decode(row) do
        {:ok, conf} ->
          [conf]

        {:error, reason} ->
          Logger.error(
            module: __MODULE__,
            message:
              "#{path}: conference #{inspect(uid_of(row))} was not restored (#{reason}); " <>
                "the other definitions are loaded — fix the entry or delete it"
          )

          []
      end
    end)
  end

  defp uid_of(row) when is_map(row), do: Map.get(row, "uid")
  defp uid_of(_row), do: nil

  defp decode(row) when is_map(row) do
    with {:ok, uid} <- string(row, "uid"),
         {:ok, domain} <- string(row, "domain"),
         {:ok, did} <- string(row, "did"),
         {:ok, vad} <- Vocabulary.vad(Map.get(row, "vad"), "vad"),
         {:ok, medias} <- medias(row),
         {:ok, video} <- video(row),
         {:ok, layout} <- layout(row),
         {:ok, codec} <- Vocabulary.video_codec(Map.get(row, "preferred_video_codec")),
         {:ok, slots} <- slots(row),
         {:ok, created_at} <- created_at(row) do
      {:ok,
       %Conference{
         uid: uid,
         domain: domain,
         did: did,
         name: Map.get(row, "name") || "conference #{did}",
         mcu: Map.get(row, "mcu"),
         vad: vad || %Conference{}.vad,
         rate: int(row, "rate", %Conference{}.rate),
         medias: medias,
         dtmf: boolean(row, "dtmf", true),
         video: video,
         preferred_video_codec: codec,
         layout: layout,
         logo: Map.get(row, "logo"),
         slots: slots,
         max_participants: int(row, "max_participants", %Conference{}.max_participants),
         destroy_when_empty: boolean(row, "destroy_when_empty", false),
         created_at: created_at,
         # A row read from the file is by definition a room that survives a restart,
         # and it has no MCU-side existence yet: `stale` is what makes the recovery of
         # §9.2 recreate it when its media server's control channel comes up.
         persistent: true,
         stale: true,
         conf_id: nil
       }}
    end
  end

  defp decode(_row), do: {:error, "not a JSON object"}

  defp string(row, key) do
    case Map.get(row, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      other -> {:error, "#{key} must be a non-empty string, got #{inspect(other)}"}
    end
  end

  defp int(row, key, default) do
    case Map.get(row, key) do
      value when is_integer(value) and value >= 0 -> value
      _other -> default
    end
  end

  defp boolean(row, key, default) do
    case Map.get(row, key) do
      value when is_boolean(value) -> value
      _other -> default
    end
  end

  defp medias(row) do
    case Map.get(row, "medias") do
      nil ->
        {:ok, %Conference{}.medias}

      names when is_list(names) ->
        case Enum.split_with(names, &Map.has_key?(@medias, &1)) do
          {[_ | _] = known, []} -> {:ok, Enum.map(known, &Map.fetch!(@medias, &1))}
          {_, unknown} -> {:error, "medias: #{inspect(unknown)} is not audio, video or text"}
        end

      other ->
        {:error, "medias must be a list, got #{inspect(other)}"}
    end
  end

  defp video(row) do
    defaults = %Conference{}.video
    given = Map.get(row, "video") || %{}

    with :ok <- table("video", given),
         {:ok, size} <- Vocabulary.size(Map.get(given, "size", defaults.size), "video.size") do
      {:ok,
       %{
         size: size,
         fps: int(given, "fps", defaults.fps),
         bitrate: int(given, "bitrate", defaults.bitrate),
         intra_period: int(given, "intra_period", defaults.intra_period)
       }}
    end
  end

  defp layout(row) do
    defaults = %Conference{}.layout
    given = Map.get(row, "layout") || %{}

    with :ok <- table("layout", given),
         {:ok, comp} <- Vocabulary.comp(Map.get(given, "comp", defaults.comp), "layout.comp"),
         {:ok, size} <- Vocabulary.size(Map.get(given, "size", defaults.size), "layout.size") do
      {:ok, %{comp: comp, size: size, auto: boolean(given, "auto", defaults.auto)}}
    end
  end

  defp table(_key, value) when is_map(value), do: :ok
  defp table(key, value), do: {:error, "#{key} must be a table, got #{inspect(value)}"}

  defp slots(row) do
    given = Map.get(row, "slots") || %{}

    with :ok <- table("slots", given) do
      Enum.reduce_while(given, {:ok, %{}}, fn {slot, value}, {:ok, acc} ->
        case Integer.parse(to_string(slot)) do
          {number, ""} when number >= 0 and is_integer(value) ->
            {:cont, {:ok, Map.put(acc, number, value)}}

          _other ->
            {:halt, {:error, "slots: #{inspect(slot)} => #{inspect(value)} is not slot => id"}}
        end
      end)
    end
  end

  defp created_at(row) do
    case Map.get(row, "created_at") do
      nil ->
        {:ok, DateTime.utc_now()}

      stamp when is_binary(stamp) ->
        case DateTime.from_iso8601(stamp) do
          {:ok, at, _offset} -> {:ok, at}
          {:error, reason} -> {:error, "created_at: #{inspect(reason)}"}
        end

      other ->
        {:error, "created_at must be an ISO 8601 string, got #{inspect(other)}"}
    end
  end
end
