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
  """

  alias Kelix.Mod.Mcu.Args

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
    case String.split(value, ~r/[\s,]+/, trim: true) do
      [] -> {:error, "#{key}: nothing given — #{layout_syntax()}"}
      tokens -> from_tokens(tokens, key)
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
  vocabulary. The other fields are plain integers and stay for `Args.sub_map/4` to
  check — this pass only turns names into ids.
  """
  @spec video(term, String.t()) :: {:ok, map | nil} | {:error, String.t()}
  def video(value, key \\ "video")

  def video(nil, _key), do: {:ok, nil}

  def video(value, key) when is_map(value) do
    map = Args.stringify_keys(value)

    with {:ok, map} <- resolve_field(map, "size", &size(&1, "#{key}.size")) do
      {:ok, map}
    end
  end

  # not a table: `Args.sub_map/4` owns that message, and says it about the same field
  def video(value, _key), do: {:ok, value}

  defp resolve_field(map, name, resolver) do
    case Map.fetch(map, name) do
      :error -> {:ok, map}
      {:ok, value} -> with {:ok, id} <- resolver.(value), do: {:ok, Map.put(map, name, id)}
    end
  end

  defp from_tokens(tokens, key) do
    tokens
    |> Enum.reduce_while({:ok, {%{}, %{}}}, fn token, {:ok, {fields, seen}} ->
      name = String.downcase(token)

      case classify(name) do
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
          {:halt, {:error, ~s(#{key}: unknown "#{token}" — #{layout_vocabulary()})}}
      end
    end)
    |> case do
      {:ok, {fields, _seen}} -> {:ok, imply_manual(fields)}
      {:error, _message} = err -> err
    end
  end

  defp classify(name) do
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

  # Why the short form implies what the wire form does not: `layout=2x2` on a
  # conference in `auto` would be overwritten by `follow_auto_layout/1` the next time
  # a video leg joins — the operator's mosaic would last seconds. The short form is an
  # intent ("show me a 2x2"), the wire form is a field assignment.
  defp imply_manual(fields) do
    if Map.has_key?(fields, "comp") and not Map.has_key?(fields, "auto"),
      do: Map.put(fields, "auto", false),
      else: fields
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
      ~s(encoder profile: video='{"size":"vga","fps":25,"bitrate":1024,"intra_period":300}'),
      "size: " <> Enum.join(sizes(), " ") <> "  (or its wire id)",
      "applies to the participants that join next, not to the ones already encoding"
    ]
  end

  @doc "The `vad` argument's help."
  @spec vad_help() :: [String.t()]
  def vad_help(),
    do: ["voice activity detection: " <> Enum.join(vads(), " | ") <> " (or 0 | 1 | 2)"]

  defp layout_syntax(),
    do: "a mosaic, a size and/or auto|manual, in any order, spaces or commas"

  defp layout_vocabulary() do
    "mosaics: " <>
      Enum.join(mosaics(), " ") <>
      "; sizes: " <> Enum.join(sizes(), " ") <> "; modes: auto manual"
  end
end
