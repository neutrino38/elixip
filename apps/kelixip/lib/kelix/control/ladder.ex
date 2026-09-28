defmodule Kelix.Control.Ladder do
  @moduledoc """
  A scenario's journal as a text ladder, the way sngrep draws a call:
  `kelictl debug show <id>`.

  One column per lane — the scenario itself, each conversation it had (one per
  Call-ID, `FSL.Diagram.message_lanes/1`), and the media server when it was
  used — one line per event, the time since the journal started on the left:

  ```
                 1000                        dev71.dev.ives.fr:443/wss
                   |                                  |
     +0.641s       |------- INVITE #1 +SDP ---------->|
     +0.756s       |<-- 407 Proxy Authentication … ---|
     +0.766s       | send_auth_INVITE                 |
     +5.302s       | calling -> call_answered         |
  ```

  It draws what `Kelix.Traces` kept, `FSL.Journal` events, and reads them the
  way FSL's own renderers do: a `:message` is an arrow on its conversation's
  column, a media command or event an arrow to or from the media column,
  anything else a note under the scenario's column, and a kind it does not know
  is skipped. With `full: true` each message is followed by its text, the body
  decoded, as sngrep's message view shows it.

  A rendering belongs to its reader: the node keeps the journal, `kelictl`
  draws this, kelescope draws its popup.
  """

  # Where the first column stands, and the distance between two columns.
  @time_width 14
  @gap 36

  @doc "The ladder of a journal (`events`, `meta`), as one string."
  @spec render([map], map, keyword) :: String.t()
  def render(events, meta, opts \\ []) do
    full? = Keyword.get(opts, :full, false)
    peers = FSL.Diagram.message_lanes(events)
    media? = FSL.Diagram.media?(events)

    {local_label, _peer} = FSL.Diagram.lane_labels(meta)

    columns =
      [{:local, local_label}] ++
        Enum.map(peers, &{{:lane, &1.lane}, &1.label}) ++
        if(media?, do: [{:media, "media server"}], else: [])

    x =
      columns
      |> Enum.with_index()
      |> Map.new(fn {{key, _}, i} -> {key, @time_width + i * @gap} end)

    width = @time_width + (length(columns) - 1) * @gap + 1

    rows =
      events
      |> Enum.reduce({[], Map.get(meta, :joined_in)}, fn event, {acc, current} ->
        {lines, next} = rows(event, current, x, width, meta, full?)
        {[lines | acc], next}
      end)
      |> elem(0)
      |> Enum.reverse()
      |> List.flatten()

    [
      header(meta, peers),
      "",
      names(columns, x, width),
      rails(x, width),
      rows,
      rails(x, width)
    ]
    |> List.flatten()
    |> Enum.join("\n")
  end

  # ── header ──────────────────────────────────────────────────────────────────

  defp header(meta, peers) do
    [
      "Scenario : #{Map.get(meta, :scenario)}   (#{Map.get(meta, :pid)})"
      | Enum.map(peers, fn p ->
          "#{p.alias}: #{p.label} — Call-ID #{FSL.Diagram.lane_name(p.lane)}"
        end)
    ]
  end

  defp names(columns, x, width) do
    Enum.reduce(columns, blank(width), fn {key, label}, line ->
      label = truncate(to_string(label), @gap - 2)
      put(line, max(x[key] - div(String.length(label), 2), 0), label)
    end)
    |> String.trim_trailing()
  end

  defp rails(x, width), do: x |> Map.values() |> rail_line(width)

  defp rail_line(xs, width),
    do: Enum.reduce(xs, blank(width), &put(&2, &1, "|")) |> String.trim_trailing()

  # ── one event → its lines ───────────────────────────────────────────────────

  defp rows(%{kind: :message} = msg, current, x, width, meta, full?) do
    lane = x[{:lane, Map.get(msg, :lane)}] || x[:local]
    {from, to} = if Map.get(msg, :dir) == :in, do: {lane, x[:local]}, else: {x[:local], lane}
    line = time(msg, meta) |> overlay(arrow(from, to, Map.get(msg, :label, ""), x, width))

    body =
      if full? and is_binary(Map.get(msg, :body)) do
        clipped = if Map.get(msg, :clipped), do: ["      (clipped)"], else: []

        decoded =
          if d = Map.get(msg, :decoded_from), do: ["      (body shown decoded: #{d})"], else: []

        (msg.body
         |> String.split(~r/\r?\n/)
         |> Enum.map(&String.trim_trailing("      " <> &1))) ++
          decoded ++ clipped ++ [""]
      else
        []
      end

    {[line | body], current}
  end

  defp rows(%{kind: :command, type: :media, name: name} = event, current, x, width, meta, _full?) do
    {[
       time(event, meta)
       |> overlay(arrow(x[:local], x[:media], FSL.Diagram.media_label(name), x, width))
     ], current}
  end

  defp rows(%{kind: :command, name: name} = event, current, x, width, meta, _full?) do
    {[note(event, name, x, width, meta)], current}
  end

  defp rows(%{kind: :transition, to: to} = event, nil, x, width, meta, _full?) do
    {[note(event, to_string(to), x, width, meta)], to}
  end

  defp rows(
         %{kind: :transition, to: to, type: :media, event: label} = event,
         from,
         x,
         width,
         meta,
         _full?
       ) do
    inbound =
      if FSL.Diagram.labelled?(label) and Map.has_key?(x, :media),
        do: [time(event, meta) |> overlay(arrow(x[:media], x[:local], label, x, width))],
        else: []

    {inbound ++ [note(event, "#{from} -> #{to}", x, width, meta)], to}
  end

  defp rows(%{kind: :transition, to: to} = event, from, x, width, meta, _full?) do
    {[note(event, "#{from} -> #{to}", x, width, meta)], to}
  end

  defp rows(
         %{kind: :terminal, outcome: outcome, reason: reason} = event,
         current,
         x,
         width,
         meta,
         _full?
       ) do
    text = if reason in ["", nil], do: "#{outcome}", else: "#{outcome}: #{reason}"
    {[note(event, "== #{text} ==", x, width, meta)], current}
  end

  defp rows(%{kind: :cut} = event, current, x, width, meta, _full?) do
    {[note(event, "-- journal truncated --", x, width, meta)], current}
  end

  # A kind this ladder does not know: skipped, as FSL's renderers do.
  defp rows(_event, current, _x, _width, _meta, _full?), do: {[], current}

  # ── drawing ─────────────────────────────────────────────────────────────────

  # The rails with an arrow from column `from` to column `to`, the label centred.
  defp arrow(from, to, label, x, width) do
    {left, right} = {min(from, to), max(from, to)}
    span = right - left - 1
    label = " " <> truncate(to_string(label), max(span - 6, 1)) <> " "
    dashes = max(span - String.length(label), 0)
    lead = div(dashes, 2)

    shaft =
      String.duplicate("-", lead) <> label <> String.duplicate("-", dashes - lead)

    shaft =
      if from < to,
        do: String.slice(shaft, 0, span - 1) <> ">",
        else: "<" <> String.slice(shaft, 1, span - 1)

    x |> Map.values() |> rail_line(width) |> pad(width) |> put(left + 1, shaft)
  end

  # A note: the text right of the scenario's column, over the rails.
  defp note(event, text, x, width, meta) do
    line = x |> Map.values() |> rail_line(width) |> pad(width)
    time(event, meta) |> overlay(put(line, x[:local] + 2, text))
  end

  # The time since the journal started, left of the first column.
  defp time(%{at: at}, %{t0: t0}) when is_integer(at) and is_integer(t0) do
    ms = div(at - t0, 1000)

    String.pad_leading(
      "+#{div(ms, 1000)}.#{String.pad_leading(to_string(rem(ms, 1000)), 3, "0")}s",
      9
    )
  end

  defp time(_event, _meta), do: ""

  # The time written into the first columns of a line.
  defp overlay(time, line), do: put(line, 0, time)

  defp blank(width), do: String.duplicate(" ", width)
  defp pad(line, width), do: String.pad_trailing(line, width)

  # `text` written over `line` from column `at`, the line growing when needed.
  defp put(line, at, text) do
    line = String.pad_trailing(line, at)
    before = String.slice(line, 0, at)
    rest = String.slice(line, (at + String.length(text))..-1//1)
    (before <> text <> rest) |> String.trim_trailing()
  end

  defp truncate(text, max) do
    if String.length(text) > max, do: String.slice(text, 0, max - 1) <> "…", else: text
  end
end
