defmodule SIP.Scenario.SequenceDiagram do
  @moduledoc """
  Pure renderer turning a `SIP.Scenario.SequenceJournal` event list plus metadata
  into a [PlantUML](https://plantuml.com/sequence-diagram) sequence diagram.

  It has **no dependency on the SIP stack**, so it is fully unit-testable in
  isolation.

  When the journal holds the real SIP messages (`kind: :sip`, recorded by
  `SIP.Scenario.SipTrace`), every message is an arrow: one participant per
  Call-ID — a leg of a B2BUA, a registration, a call — labelled with the leg tag
  and the peer address, solid for a request, dashed for a response, grey for a
  retransmission. The `send_*` commands are then drawn as hexagon notes so the
  reader can match a script line to what went out, and the free-text description
  of a `:sip` transition is no longer drawn as an arrow of its own.

  Without them, the diagram falls back to what the scenario reports: outbound
  command names become request arrows (`send_INVITE` → `INVITE`) and a `:sip`
  transition carrying a description becomes an inbound arrow.

  Every label is prefixed with the time since the journal started when the
  events carry one.
  """

  # Participant aliases used throughout the diagram.
  @local "elixip"
  @remote "peer"
  @media "ms"

  # Media commands/events are drawn in a distinct color to stand out from SIP;
  # retransmissions are dimmed so the first copy stays the one the eye reads.
  @media_color "#DarkOrange"
  @retransmit_color "#Gray"

  @doc "Render the full PlantUML document as a String."
  @spec to_plantuml([map()], map()) :: String.t()
  def to_plantuml(events, meta) when is_list(events) and is_map(meta) do
    lanes = lanes(events)

    ctx = %{
      t0: Map.get(meta, :t0),
      traced?: lanes != [],
      aliases: Map.new(lanes, fn lane -> {lane.callid, lane.alias} end)
    }

    [
      header(meta, lanes),
      "@startuml",
      participants(meta, events, lanes),
      "",
      body(events, ctx),
      "@enduml"
    ]
    |> List.flatten()
    |> Enum.join("\n")
    |> Kernel.<>("\n")
  end

  @doc """
  Build the `.puml` filename from metadata: `<scenario>_<pid>.puml`, with the pid
  sanitized to keep only digits and dots (`#PID<0.123.0>` → `0.123.0`).
  """
  @spec filename(map()) :: String.t()
  def filename(meta) when is_map(meta) do
    "#{meta.scenario}_#{safe_pid(meta.pid)}.puml"
  end

  @doc "Sanitize an inspected pid into a filename-safe string."
  @spec safe_pid(String.t()) :: String.t()
  def safe_pid(pid_string) do
    String.replace(to_string(pid_string), ~r/[^0-9.]/, "")
  end

  # ── Header (PlantUML comment lines start with a single quote) ───────────────

  defp header(meta, lanes) do
    config = Map.get(meta, :config, [])

    [
      "' Scenario      : #{meta.scenario}",
      "' Instance pid  : #{meta.pid}",
      "' Configuration (passwords masked):",
      Enum.map(config, fn {key, value} -> "'   #{key}: #{mask(key, value)}" end),
      lane_comments(lanes),
      "'"
    ]
  end

  defp lane_comments([]), do: []

  defp lane_comments(lanes) do
    [
      "' SIP peers (one per Call-ID):",
      Enum.map(lanes, fn lane -> "'   #{lane.alias}: #{lane.label} — Call-ID #{lane.callid}" end)
    ]
  end

  # Secrets are never written out, even though the plaintext password is normally
  # already absent from the context (it is hashed into :ha1 at config time).
  defp mask(key, _value) when key in [:passwd, :password, :ha1, :ha1b], do: "****"
  defp mask(_key, value), do: inspect(value)

  # ── Participants ────────────────────────────────────────────────────────────

  # One lane per Call-ID seen in the recorded SIP messages, in order of first
  # appearance, labelled with the leg tag and the peer address when known.
  defp lanes(events) do
    events
    |> Enum.filter(&(&1.kind == :sip))
    |> Enum.group_by(& &1.callid)
    |> Enum.sort_by(fn {_callid, msgs} -> hd(msgs).at end)
    |> Enum.with_index(1)
    |> Enum.map(fn {{callid, msgs}, index} ->
      tag = Enum.find_value(msgs, & &1.tag)
      peer = Enum.find_value(msgs, & &1.peer)
      label = [tag, peer] |> Enum.reject(&is_nil/1) |> Enum.join(" ")

      %{
        callid: callid,
        alias: "#{@remote}#{index}",
        label: if(label == "", do: "#{@remote} #{index}", else: label)
      }
    end)
  end

  defp participants(meta, events, lanes) do
    config = Map.get(meta, :config, [])

    peers =
      case lanes do
        [] -> [participant(@remote, Keyword.get(config, :domain))]
        lanes -> Enum.map(lanes, &participant(&1.alias, &1.label))
      end

    base = [participant(@local, Keyword.get(config, :username)) | peers]

    # Only declare the media-server lane when the scenario actually touched media,
    # as a `control` so it is visually distinct from the SIP participants.
    if media?(events), do: base ++ [~s(control "media server" as #{@media})], else: base
  end

  defp participant(alias_name, nil), do: "participant #{alias_name}"
  defp participant(alias_name, label), do: ~s(participant "#{label}" as #{alias_name})

  defp media?(events) do
    Enum.any?(events, fn
      %{kind: :command, type: :media} -> true
      %{kind: :transition, type: :media} -> true
      _ -> false
    end)
  end

  # ── Body ──────────────────────────────────────────────────────────────────

  defp body(events, ctx) do
    {lines, _current_state} =
      Enum.reduce(events, {[], nil}, fn event, {acc, current} ->
        {rendered, next} = render(event, current, ctx)
        {acc ++ rendered, next}
      end)

    lines
  end

  # A real SIP message → arrow on the lane of its Call-ID.
  defp render(%{kind: :sip} = msg, current, ctx) do
    lane = Map.get(ctx.aliases, msg.callid, @remote)
    {from, to} = if msg.dir == :out, do: {@local, lane}, else: {lane, @local}
    {[~s(#{from} #{arrow(msg)} #{to} : #{stamp(msg, ctx)}#{message_label(msg)})], current}
  end

  # Outbound SIP command: a request arrow towards the peer when nothing better is
  # known, a note beside the real arrows when the messages are traced.
  defp render(%{kind: :command, type: :sip, name: name} = event, current, ctx) do
    if ctx.traced? do
      {["hnote over #{@local} : #{stamp(event, ctx)}#{name}"], current}
    else
      {["#{@local} -> #{@remote} : #{stamp(event, ctx)}#{method_label(name)}"], current}
    end
  end

  # Outbound media command → colored arrow towards the media server.
  defp render(%{kind: :command, type: :media, name: name} = event, current, ctx) do
    {["#{@local} -[#{@media_color}]> #{@media} : #{stamp(event, ctx)}#{media_label(name)}"],
     current}
  end

  # Other command categories have no dedicated lane: render them as a self-note.
  defp render(%{kind: :command, name: name} = event, current, ctx) do
    {["note over #{@local} : #{stamp(event, ctx)}#{name}"], current}
  end

  # First transition (no previous state) = entering the initial state.
  defp render(%{kind: :transition, to: to} = event, nil, ctx) do
    {["note over #{@local} : #{stamp(event, ctx)}#{to}"], to}
  end

  # Subsequent transition: optionally an inbound arrow (from the peer for a SIP
  # event, from the media server for a media event), then the state-change note.
  defp render(%{kind: :transition, to: to, event: event, type: type} = transition, from, ctx) do
    inbound =
      cond do
        type == :sip and event not in ["", "start"] and not ctx.traced? ->
          ["#{@local} <-- #{@remote} : #{event}"]

        # Media events are drawn as a colored arrow from the media server.
        type == :media and event not in ["", "start"] ->
          ["#{@media} -[#{@media_color}]> #{@local} : #{event}"]

        true ->
          []
      end

    {inbound ++ ["note over #{@local} : #{stamp(transition, ctx)}#{from} -> #{to}"], to}
  end

  # Terminal outcome → coloured note.
  defp render(%{kind: :terminal, outcome: outcome, reason: reason} = event, current, ctx) do
    label = if reason in ["", nil], do: to_string(outcome), else: "#{outcome}: #{reason}"
    color = if outcome == :succeeded, do: "#LightGreen", else: "#Pink"
    {["note over #{@local} #{color} : #{stamp(event, ctx)}#{label}"], current}
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # Time since the journal started, when both sides carry a clock.
  defp stamp(%{at: at}, %{t0: t0}) when is_integer(at) and is_integer(t0) do
    "+#{div(at - t0, 1000)}ms "
  end

  defp stamp(_event, _ctx), do: ""

  # Solid for a request, dashed for a response; grey when re-sent.
  defp arrow(%{code: code, retransmit: retransmit}) do
    color = if retransmit, do: "[#{@retransmit_color}]", else: ""
    if is_integer(code), do: "-#{color}->", else: "-#{color}>"
  end

  defp message_label(%{code: code} = msg) when is_integer(code) do
    "#{code} #{msg.reason} / #{msg.cseq}" <> suffixes(msg)
  end

  defp message_label(msg) do
    cseq = if msg.cseq, do: " ##{msg.cseq |> String.split(" ") |> hd()}", else: ""
    "#{msg.method}#{cseq}" <> suffixes(msg)
  end

  defp suffixes(msg) do
    Enum.join([
      if(msg.sdp, do: " +SDP", else: ""),
      if(msg.retransmit, do: " (retransmission)", else: "")
    ])
  end

  # "send_INVITE" → "INVITE", "send_auth_REGISTER" → "REGISTER (auth)".
  defp method_label(name) do
    base = String.replace_prefix(name, "send_", "")

    {base, suffix} =
      if String.starts_with?(base, "auth_") do
        {String.replace_prefix(base, "auth_", ""), " (auth)"}
      else
        {base, ""}
      end

    String.upcase(base) <> suffix
  end

  # "media_connect" → "connect", "media_play" → "play", "media_start_echo" → "start_echo".
  defp media_label(name), do: String.replace_prefix(name, "media_", "")
end
