defmodule Kelix.Mod.Mcu.Vocabulary do
  @moduledoc """
  The human names of the MCU's wire enums — mosaic layouts, video sizes, VAD modes
  (design `docs/design/mcu_module.md` §3.6, §8.3.7) — read in **one** place.

  Both directions live here and everything else delegates: the CLI render labels
  (`kelictl` shows `2x2`), the accepted *input* of the control commands and of the
  scenario facades (`layout='2x2 hd720p'`), the `[module.mcu]` block
  (`layout_comp = "2x2"`), and the vocabulary the online help prints.

  A second table would be a second reading of the same thing, and the two would
  drift the day medooze adds a mosaic: the labels would render `4x4` while the
  parser refused it, and the config file would accept a number the help never
  mentioned. Same rule as the REGISTER lifetime of `CLAUDE.md` — one reading,
  policy layered on top.

  ## The short `layout` form (§8.3.7)

  `layout` takes one string of tokens separated by spaces **or commas** — commas so
  the common case needs no shell quoting — in **any order**, because the three
  vocabularies are disjoint: a mosaic name, a size name, and `auto` / `manual`.

      layout='2x2 hd720p'   layout=auto,vga   layout=1+1   layout=manual

  Only what is named changes; the rest of the layout is left as it was (the partial
  merge of §8.3.3). **Naming a mosaic implies `manual`**, unless `auto` is given in
  the same value: on a conference whose layout follows the participant count, a
  fixed mosaic would otherwise be silently undone by the next arrival, which reads
  as a command that did nothing.

  The wire form keeps working and stays **literal** — `layout='{"comp":1}'` sets
  the mosaic and nothing else — so a REST client's `PUT` body means exactly what it
  says. Names are accepted there too (`layout='{"comp":"2x2"}'`).

  ## The short `video` form (§8.3.7)

  Same grammar, on the encoder profile: tokens separated by spaces or commas, in any
  order, and one shape per field so the four vocabularies stay disjoint.

      video='vga 30fps 1024k'   video=hd720p   video=25fps,intra=300

  A size is a name (the `layout` vocabulary), a frame rate is `<n>fps`, a bitrate is
  `<n>k` in kbit/s, and an intra period is `intra=<n>` — a frame count nobody writes
  a unit for. Only what is named changes, and the wire form stays literal here too
  (`video='{"fps":30}'`).
  """

  alias Kelix.Mod.Mcu.Args
  alias MediaServer.SdpTools, as: Sdp

  # §3.6, in wire order: the id is what `SetCompositionType` takes, the name is what
  # an operator says.
  @mosaics [
    {0, "1x1"},
    {1, "2x2"},
    {2, "3x3"},
    {3, "3+4"},
    {4, "1+7"},
    {5, "1+5"},
    {6, "1+1"},
    {7, "pip1"},
    {8, "pip3"},
    {9, "4x4"},
    {10, "1+4"},
    {11, "2+8"}
  ]

  @sizes [
    {0, "qcif"},
    {1, "cif"},
    {2, "vga"},
    {3, "pal"},
    {4, "hvga"},
    {5, "qvga"},
    {6, "hd720p"},
    {7, "wqvga"},
    {14, "xga"},
    {15, "wvga"}
  ]

  @vads [{0, "none"}, {1, "basic"}, {2, "full"}]

  # What a mosaic slot may be told to hold (`Mosaic::Slot*`, `mcu/include/mosaic.h`),
  # the `id` argument of `SetMosaicSlot` when it is not a `partId` (§8.3.8).
  @slot_states [{-2, "vad"}, {-1, "locked"}, {0, "free"}, {-3, "reset"}]

  # Slots per composition, **read from the server's own table**
  # (`Mosaic::GetNumSlotsForType`) and not derived from the name: `1+4` reports 16,
  # not 5, and arithmetic here would refuse a pin the mixer accepts.
  @slots_per_comp %{
    0 => 1,
    1 => 4,
    2 => 9,
    3 => 7,
    4 => 8,
    5 => 6,
    6 => 2,
    7 => 2,
    8 => 4,
    9 => 16,
    10 => 16,
    11 => 10
  }

  # One alias, for the size an operator types most: `720p` is what every other tool
  # in a video stack calls it. Kept to one entry on purpose — a dialect would have to
  # be documented, error-checked and rendered like the vocabulary itself.
  @aliases %{"720p" => "hd720p"}

  @modes %{"auto" => true, "manual" => false}

  @typedoc """
  A decoded `layout`: the fields that were actually named, string-keyed and holding
  wire ids — the shape `Args.sub_map/4` merges over the current layout.
  """
  @type layout :: %{optional(String.t()) => non_neg_integer | boolean}

  # ── the tables, both directions ──────────────────────────────────────────────

  @doc "`%{\"1\" => \"2x2\", …}` — the CLI render labels for a mosaic id."
  @spec mosaic_names() :: %{optional(String.t()) => String.t()}
  def mosaic_names(), do: label_map(@mosaics)

  @doc "`%{\"6\" => \"hd720p\", …}` — the CLI render labels for a video size id."
  @spec size_names() :: %{optional(String.t()) => String.t()}
  def size_names(), do: label_map(@sizes)

  @doc "`%{\"1\" => \"basic\", …}` — the CLI render labels for a VAD mode."
  @spec vad_names() :: %{optional(String.t()) => String.t()}
  def vad_names(), do: label_map(@vads)

  @doc "The mosaic names, in wire order."
  @spec mosaics() :: [String.t()]
  def mosaics(), do: Enum.map(@mosaics, &elem(&1, 1))

  @doc "The video size names, in wire order."
  @spec sizes() :: [String.t()]
  def sizes(), do: Enum.map(@sizes, &elem(&1, 1))

  @doc "The VAD mode names, in wire order."
  @spec vads() :: [String.t()]
  def vads(), do: Enum.map(@vads, &elem(&1, 1))

  # Pixel dimensions of each video size id, transcribed from the media server's
  # own table (`GetWidth`/`GetHeight`, `libmedikit/medkit/config.h`) — the wire
  # ids carry no dimensions, and a codec parameter derived from the *wrong*
  # dimensions announces a capability the mixer does not have.
  @size_dimensions %{
    0 => {176, 144},
    1 => {352, 288},
    2 => {640, 480},
    3 => {768, 576},
    4 => {320, 240},
    5 => {160, 120},
    6 => {1280, 720},
    7 => {400, 240},
    14 => {1024, 768},
    15 => {800, 480}
  }

  @doc """
  `{width, height}` of a video size id, or `nil` for an id this table does not
  carry. Needed by anything that must state a codec capability in real pixels
  (the AV1 `level-idx`, for one) rather than in medooze size ids.
  """
  @spec size_dimensions(non_neg_integer) :: {pos_integer, pos_integer} | nil
  def size_dimensions(id), do: Map.get(@size_dimensions, id)

  defp label_map(table), do: Map.new(table, fn {id, name} -> {Integer.to_string(id), name} end)

  # ── one value ────────────────────────────────────────────────────────────────

  @doc """
  A mosaic, by name (`"2x2"`) or by wire id (`1`, or `"1"`). `nil` passes through, so
  a caller can hand an absent argument straight in.

  `key` names the field in the error message: it is the operator's own spelling
  (`layout.comp`, `layout_comp`) and not this module's business to guess.
  """
  @spec comp(term, String.t()) :: {:ok, non_neg_integer | nil} | {:error, String.t()}
  def comp(value, key \\ "comp"), do: resolve(@mosaics, "mosaic", value, key)

  @doc "A video size, by name (`\"vga\"`) or by wire id. `nil` passes through."
  @spec size(term, String.t()) :: {:ok, non_neg_integer | nil} | {:error, String.t()}
  def size(value, key \\ "size"), do: resolve(@sizes, "video size", value, key)

  @doc "A VAD mode, by name (`\"full\"`) or by wire id. `nil` passes through."
  @spec vad(term, String.t()) :: {:ok, non_neg_integer | nil} | {:error, String.t()}
  def vad(value, key \\ "vad"), do: resolve(@vads, "vad mode", value, key)

  defp resolve(_table, _kind, nil, _key), do: {:ok, nil}

  defp resolve(table, kind, value, key) when is_integer(value) do
    if Enum.any?(table, &(elem(&1, 0) == value)),
      do: {:ok, value},
      else: {:error, "#{key}: #{value} is not a #{kind} id — #{vocabulary(table)}"}
  end

  defp resolve(table, kind, value, key) when is_binary(value) do
    name = value |> String.trim() |> String.downcase() |> unalias()

    case Enum.find(table, &(elem(&1, 1) == name)) do
      {id, _name} ->
        {:ok, id}

      nil ->
        # a digit string is the wire id an HTTP client or a TOML file may have
        # quoted; anything else is a typo, and the vocabulary is the answer to it
        case Integer.parse(name) do
          {id, ""} -> resolve(table, kind, id, key)
          _ -> {:error, ~s(#{key}: unknown #{kind} "#{value}" — #{vocabulary(table)})}
        end
    end
  end

  defp resolve(_table, kind, value, key),
    do: {:error, "#{key} must be a #{kind} name or id, got #{inspect(value)}"}

  defp unalias(name), do: Map.get(@aliases, name, name)

  defp vocabulary(table), do: "one of " <> Enum.map_join(table, ", ", &elem(&1, 1))

  # ── the layout argument ──────────────────────────────────────────────────────

  @doc """
  Decode a `layout` argument into the partial map the merge of §8.3.3 applies: wire
  integers, string keys, only the fields that were named. `nil` passes through.

  Accepts the short form (`"2x2 hd720p"`, `"auto,vga"`), the wire form
  (`%{"comp" => 1}`, with names allowed) and the atom-keyed table a scenario writes
  (`%{comp: "2x2"}`) — one reading for all three (§17.2).
  """
  @spec layout(term, String.t()) :: {:ok, layout | nil} | {:error, String.t()}
  def layout(value, key \\ "layout")

  def layout(nil, _key), do: {:ok, nil}

  def layout(value, key) when is_binary(value) do
    case tokens(value) do
      [] ->
        {:error, "#{key}: nothing given — #{layout_syntax()}"}

      tokens ->
        with {:ok, fields} <- from_tokens(tokens, key, &classify_layout/1, layout_vocabulary()),
             do: {:ok, imply_manual(fields)}
    end
  end

  def layout(value, key) when is_map(value) do
    map = Args.stringify_keys(value)

    with {:ok, map} <- resolve_field(map, "comp", &comp(&1, "#{key}.comp")),
         {:ok, map} <- resolve_field(map, "size", &size(&1, "#{key}.size")) do
      {:ok, map}
    end
  end

  def layout(value, key) when is_integer(value) do
    {:error,
     ~s(#{key}: #{value} alone is ambiguous — a mosaic and a size are both numbered; ) <>
       ~s(write #{key}='2x2 hd720p' or #{key}='{"comp":#{value}}')}
  end

  def layout(value, key),
    do: {:error, ~s(#{key} must be names like "2x2 hd720p" or a table, got #{inspect(value)})}

  @doc """
  Decode a `video` argument: the encoder profile, whose `size` shares the size
  vocabulary.

  Accepts the short form (`"vga 30fps 1024k"`) and the wire form (`%{"fps" => 30}`,
  atom keys included), like `layout/2`. In the wire form the other fields are plain
  integers and stay for `Args.sub_map/4` to check — that pass only turns names into
  ids.
  """
  @spec video(term, String.t()) :: {:ok, map | nil} | {:error, String.t()}
  def video(value, key \\ "video")

  def video(nil, _key), do: {:ok, nil}

  def video(value, key) when is_binary(value) do
    case tokens(value) do
      [] -> {:error, "#{key}: nothing given — #{video_syntax()}"}
      tokens -> from_tokens(tokens, key, &classify_video/1, video_vocabulary())
    end
  end

  def video(value, key) when is_map(value) do
    map = Args.stringify_keys(value)

    with {:ok, map} <- resolve_field(map, "size", &size(&1, "#{key}.size")) do
      {:ok, map}
    end
  end

  def video(value, key) when is_integer(value) do
    {:error,
     ~s(#{key}: #{value} alone is ambiguous — a size, a frame rate and a bitrate are all ) <>
       ~s(numbered; write #{key}='vga 30fps 1024k' or #{key}='{"size":#{value}}')}
  end

  # not a table: `Args.sub_map/4` owns that message, and says it about the same field
  def video(value, _key), do: {:ok, value}

  @doc """
  Decode a `preferred_video_codec` value: the codec name an answer puts first, or
  `nil` for no preference.

  Case-insensitive, and `"none"` (equivalently `"any"`) is what **clears** a
  preference — an update merges the fields it is given, so removing one needs a value
  to say it with.

  The names come from the framework's codec tables (`MediaServer.SdpTools.codec_names/1`)
  and the canonical spelling is theirs: a list here would be the second reading this
  module exists to prevent. Recognising a name is **not** claiming the media server
  carries it — that stays the server's answer to give (§16.3), and a preference it does
  not accept is logged and dropped at answer time.
  """
  @spec video_codec(term, String.t()) :: {:ok, String.t() | nil} | {:error, String.t()}
  def video_codec(value, key \\ "preferred_video_codec")

  def video_codec(nil, _key), do: {:ok, nil}

  def video_codec(value, key) when is_binary(value) do
    case value |> String.trim() |> String.downcase() do
      name when name in ["", "none", "any"] ->
        {:ok, nil}

      name ->
        case Enum.find(video_codec_names(), &(String.downcase(&1) == name)) do
          nil -> {:error, ~s(#{key}: unknown "#{value}" — #{video_codec_vocabulary()})}
          canonical -> {:ok, canonical}
        end
    end
  end

  def video_codec(value, key),
    do: {:error, ~s(#{key} must be a codec name like "h264", or "none", got #{inspect(value)})}

  @doc "The video codec names an operator may write, as the codec tables spell them."
  @spec video_codec_names() :: [String.t()]
  def video_codec_names(), do: Sdp.codec_names(:video)

  defp video_codec_vocabulary(),
    do: "one of " <> Enum.join(video_codec_names(), " ") <> " (case-insensitive), or none"

  defp resolve_field(map, name, resolver) do
    case Map.fetch(map, name) do
      :error -> {:ok, map}
      {:ok, value} -> with {:ok, id} <- resolver.(value), do: {:ok, Map.put(map, name, id)}
    end
  end

  defp tokens(value), do: String.split(value, ~r/[\s,]+/, trim: true)

  defp from_tokens(tokens, key, classify, vocabulary) do
    tokens
    |> Enum.reduce_while({:ok, {%{}, %{}}}, fn token, {:ok, {fields, seen}} ->
      case classify.(String.downcase(token)) do
        {field, value} ->
          case Map.fetch(seen, field) do
            {:ok, first} ->
              {:halt,
               {:error,
                ~s(#{key}: "#{first}" and "#{token}" both set the #{group(field)} — give one)}}

            :error ->
              {:cont, {:ok, {Map.put(fields, field, value), Map.put(seen, field, token)}}}
          end

        :unknown ->
          # the whole vocabulary, at the moment it is needed: an operator who typed
          # `2+2` wants the mosaic list, not a pointer to the online help
          {:halt, {:error, ~s(#{key}: unknown "#{token}" — #{vocabulary})}}
      end
    end)
    |> case do
      {:ok, {fields, _seen}} -> {:ok, fields}
      {:error, _message} = err -> err
    end
  end

  @fps_token ~r/^(\d+)fps$/
  @bitrate_token ~r/^(\d+)k(?:bps)?$/
  @intra_token ~r/^intra=(\d+)$/

  defp classify_video(name) do
    cond do
      id = find_id(@sizes, unalias(name)) -> {"size", id}
      n = number(@fps_token, name) -> {"fps", n}
      n = number(@bitrate_token, name) -> {"bitrate", n}
      n = number(@intra_token, name) -> {"intra_period", n}
      true -> :unknown
    end
  end

  defp number(regex, name) do
    case Regex.run(regex, name) do
      [_token, digits] -> String.to_integer(digits)
      nil -> nil
    end
  end

  defp classify_layout(name) do
    name = unalias(name)

    cond do
      Map.has_key?(@modes, name) -> {"auto", Map.fetch!(@modes, name)}
      id = find_id(@mosaics, name) -> {"comp", id}
      id = find_id(@sizes, name) -> {"size", id}
      true -> :unknown
    end
  end

  defp find_id(table, name) do
    case Enum.find(table, &(elem(&1, 1) == name)) do
      {id, _name} -> id
      nil -> nil
    end
  end

  defp group("comp"), do: "mosaic"
  defp group("size"), do: "size"
  defp group("auto"), do: "mode"
  defp group("fps"), do: "frame rate"
  defp group("bitrate"), do: "bitrate"
  defp group("intra_period"), do: "intra period"

  # Why the short form implies what the wire form does not: `layout=2x2` on a
  # conference in `auto` would be overwritten by `follow_auto_layout/1` the next time
  # a video leg joins — the operator's mosaic would last seconds. The short form is an
  # intent ("show me a 2x2"), the wire form is a field assignment.
  defp imply_manual(fields) do
    if Map.has_key?(fields, "comp") and not Map.has_key?(fields, "auto"),
      do: Map.put(fields, "auto", false),
      else: fields
  end

  # ── mosaic slots (§8.3.8) ────────────────────────────────────────────────────

  @doc """
  How many slots a composition has — the server's own table, keyed by the mosaic id.

  `nil` for an unknown id, which is not the same as `0`: a caller that cannot know the
  slot count must not conclude "no slot is valid".
  """
  @spec slots_for(non_neg_integer) :: pos_integer | nil
  def slots_for(comp), do: Map.get(@slots_per_comp, comp)

  @doc "The slot-state names an operator may write (`vad`, `locked`, `free`, `reset`)."
  @spec slot_states() :: [String.t()]
  def slot_states(), do: Enum.map(@slot_states, &elem(&1, 1))

  @doc """
  What a slot was told to hold. `{:state, wire}` for a named state, `{:part_id, n}` for
  a participant id, `{:name, s}` for anything else — a participant *name*, which only
  the conference's roster can resolve, so it is handed back for the caller to look up.

  A bare `0` or a negative number is **refused**: `0` is both "participant zero" and
  `SlotFree`, and the state names exist precisely so that no one has to know which.
  """
  @spec holds(term, String.t()) ::
          {:ok, {:state, integer} | {:part_id, pos_integer} | {:name, String.t()}}
          | {:error, String.t()}
  def holds(value, key \\ "holds")

  def holds(nil, key), do: {:error, "#{key} is required — #{holds_vocabulary()}"}

  def holds(value, _key) when is_integer(value) and value > 0, do: {:ok, {:part_id, value}}

  def holds(value, key) when is_integer(value) do
    {:error,
     "#{key}: #{value} is not a participant id — say what you mean by name (#{holds_vocabulary()})"}
  end

  def holds(value, key) when is_binary(value) do
    name = value |> String.trim() |> String.downcase()

    case Enum.find(@slot_states, &(elem(&1, 1) == name)) do
      {wire, _name} ->
        {:ok, {:state, wire}}

      nil ->
        case Integer.parse(name) do
          {id, ""} -> holds(id, key)
          _ -> named_participant(String.trim(value), key)
        end
    end
  end

  def holds(value, key),
    do: {:error, "#{key} must be a name or a participant id, got #{inspect(value)}"}

  defp named_participant("", key), do: {:error, "#{key} is empty — #{holds_vocabulary()}"}
  defp named_participant(name, _key), do: {:ok, {:name, name}}

  @doc """
  The wire value of a slot state, by name — `slot_wire("reset")`. Raises on an unknown
  name, which can only be a typo in the module itself.
  """
  @spec slot_wire(String.t()) :: integer
  def slot_wire(name) do
    {wire, _name} = Enum.find(@slot_states, &(elem(&1, 1) == name))
    wire
  end

  @doc """
  The name of a slot's wire value, for rendering: a state name, or `\"part\"` when a
  participant is nailed there.
  """
  @spec holds_name(integer) :: String.t()
  def holds_name(wire) when wire > 0, do: "part"

  def holds_name(wire) do
    case Enum.find(@slot_states, &(elem(&1, 0) == wire)) do
      {_wire, name} -> name
      nil -> Integer.to_string(wire)
    end
  end

  # ── online help (§8.3.7) ─────────────────────────────────────────────────────

  @doc """
  The `layout` argument's help, as the lines `kelictl <module> help` prints under the
  command. Declared here so the CLI needs to know nothing about mosaics, and so the
  vocabulary it shows is the one the parser enforces.
  """
  @spec layout_help() :: [String.t()]
  def layout_help() do
    [
      layout_syntax(),
      "mosaic: " <> Enum.join(mosaics(), " "),
      "size:   " <> Enum.join(sizes(), " ") <> "  (720p = hd720p)",
      "mode:   auto (follows the participant count) | manual",
      "naming a mosaic implies manual, so the next arrival cannot undo it",
      "only what is named changes — layout=vga keeps the current mosaic",
      ~s(e.g. layout='2x2 hd720p' | layout=auto,vga | layout=1+1 | layout=manual),
      ~s(the wire form is still accepted, literally: layout='{"comp":1,"auto":false}')
    ]
  end

  @doc "The `video` argument's help (its `size` shares the layout vocabulary)."
  @spec video_help() :: [String.t()]
  def video_help() do
    [
      "encoder profile: " <> video_syntax(),
      "size:   " <> Enum.join(sizes(), " ") <> "  (720p = hd720p)",
      "only what is named changes — video=30fps keeps the size and the bitrate",
      "naming a size moves the mosaic canvas with it: the canvas IS the encoded picture",
      ~s(e.g. video='vga 30fps 1024k' | video=hd720p | video=25fps,intra=300),
      ~s(the wire form is still accepted, literally: video='{"size":"vga","fps":30}'),
      "applies to the participants that join next, not to the ones already encoding"
    ]
  end

  @doc "The `preferred_video_codec` argument's help."
  @spec video_codec_help() :: [String.t()]
  def video_codec_help() do
    [
      "the video codec the answer states first: " <> video_codec_vocabulary(),
      "honoured only when the caller offered it and the media server accepted it",
      "it reorders the answer, it never adds a codec — and it is what the mixer encodes",
      "none = no preference: the caller's own order decides (RFC 3264 §6.1)"
    ]
  end

  @doc "The `vad` argument's help."
  @spec vad_help() :: [String.t()]
  def vad_help(),
    do: ["voice activity detection: " <> Enum.join(vads(), " | ") <> " (or 0 | 1 | 2)"]

  @doc "The `holds` argument's help (§8.3.8)."
  @spec holds_help() :: [String.t()]
  def holds_help() do
    [
      "what the slot shows: " <> Enum.join(slot_states(), " | ") <> " | <part_id> | <name>",
      "vad = follows the active speaker, locked = shows nobody, free = the mixer decides",
      "reset = free again *and* forget the pin",
      "a participant by name (its user part, or its full alice@host) when it matches one leg",
      "pinning a slot turns the automatic layout off (it would move what you pinned)"
    ]
  end

  @doc "The `slot` argument's help (§8.3.8)."
  @spec slot_help() :: [String.t()]
  def slot_help() do
    [
      "slot number, 0-based — as the media server numbers and logs them",
      "how many depends on the mosaic: 1x1 1, 1+1 2, 2x2 4, 3x3 9, 4x4 16 … (slot.list shows them)"
    ]
  end

  @doc "The `file` argument's help of `recording.start` (§8.3.8)."
  @spec record_file_help() :: [String.t()]
  def record_file_help() do
    [
      "a bare file name ending in .mp4 or .flv — no directory, no ..",
      "written under the configured record_dir, on the MEDIA SERVER's filesystem",
      "omitted: <uid>-<YYYYmmdd-HHMMSS>.mp4"
    ]
  end

  @doc "The `logo` argument's help (§8.3.8)."
  @spec logo_help() :: [String.t()]
  def logo_help() do
    [
      "a bare image file name, read from the configured image_dir on the media server",
      "drawn in every empty mosaic slot; it cannot be unset on a live conference (L11)"
    ]
  end

  defp holds_vocabulary(),
    do: "one of " <> Enum.join(slot_states(), ", ") <> ", a part_id, or a participant name"

  defp layout_syntax(),
    do: "a mosaic, a size and/or auto|manual, in any order, spaces or commas"

  defp layout_vocabulary() do
    "mosaics: " <>
      Enum.join(mosaics(), " ") <>
      "; sizes: " <> Enum.join(sizes(), " ") <> "; modes: auto manual"
  end

  defp video_syntax(),
    do: "a size, <n>fps, <n>k and/or intra=<n>, in any order, spaces or commas"

  defp video_vocabulary() do
    "sizes: " <>
      Enum.join(sizes(), " ") <>
      "; frame rate: <n>fps; bitrate: <n>k (kbit/s); intra period: intra=<n>"
  end
end
