defmodule FSL.Diagram.PlantUML do
  @moduledoc """
  Pure renderer turning a `FSL.Journal` event list plus metadata
  into a [PlantUML](https://plantuml.com/sequence-diagram) sequence diagram.

  It has **no dependency on the SIP stack**, so it is fully unit-testable in
  isolation. The fidelity is deliberately reduced (v1): the diagram is built from
  the instrumentation already available — outbound command names (`send_INVITE` →
  an `INVITE` arrow), state transitions (rendered as notes) and the free-text
  description carried by each transition. A transition carrying a protocol event
  and a non-empty description is rendered as an inbound arrow (the description is
  the message the scenario author labelled it with, e.g. `"200 OK"`).

  ## Three lanes, and which one an event is drawn on

  The rule is **by exclusion**, which is what lets this renderer serve a binding
  it has never heard of (extraction plan §4.8):

  | Event / command type | Lane |
  |---|---|
  | `:media` | the media server |
  | `:scenario`, `:control`, `:timer`, `:http`, `:db`, `nil` | a note over the local lane |
  | **anything else** — `:sip`, `:matrix`, `:xmpp`, … | the peer |

  Written the other way round — matching `:sip` for the peer — a binding
  emitting `:matrix` would fall through to the self-note and produce a worse
  diagram for no reason. By exclusion it reproduces today's rendering exactly
  for every type Elixip emits, and does something sensible for one it has never
  seen.

  What is left of SIP vocabulary here is naming convention that generalizes for
  free: `send_INVITE → INVITE` and `media_play → play` are prefix rules over
  *command names*, and they read `send_message → MESSAGE` just as well.
  """

  # Participant aliases used throughout the diagram. `local` rather than
  # `elixip`: it is an alias, and the rendered label is already the config's
  # username.
  @local "local"
  @remote "peer"
  @media "ms"

  # The types that get a note over the local lane rather than an arrow: nothing
  # came from anywhere for them. Everything NOT here is a protocol event and is
  # drawn as coming from the peer.
  @self_note_types [:scenario, :control, :timer, :http, :db, nil]

  # Media commands/events are drawn in a distinct color to stand out from SIP.
  @media_color "#DarkOrange"

  @doc "Render the full PlantUML document as a String."
  @spec to_plantuml([map()], map()) :: String.t()
  def to_plantuml(events, meta) when is_list(events) and is_map(meta) do
    [
      header(meta),
      "@startuml",
      participants(meta, events),
      "",
      body(events),
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

  defp header(meta) do
    config = Map.get(meta, :config, [])

    [
      "' Scenario      : #{meta.scenario}",
      "' Instance pid  : #{meta.pid}",
      "' Configuration (passwords masked):",
      Enum.map(config, fn {key, value} -> "'   #{key}: #{mask(key, value)}" end),
      "'"
    ]
  end

  # Secrets are never written out, even though the plaintext password is normally
  # already absent from the context (it is hashed into :ha1 at config time).
  defp mask(key, _value) when key in [:passwd, :password, :ha1, :ha1b], do: "****"
  defp mask(_key, value), do: inspect(value)

  # ── Participants ────────────────────────────────────────────────────────────

  defp participants(meta, events) do
    config = Map.get(meta, :config, [])

    base = [
      participant(@local, Keyword.get(config, :username)),
      participant(@remote, Keyword.get(config, :domain))
    ]

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

  defp body(events) do
    {lines, _current_state} =
      Enum.reduce(events, {[], nil}, fn event, {acc, current} ->
        {rendered, next} = render(event, current)
        {acc ++ rendered, next}
      end)

    lines
  end

  # Outbound media command → colored arrow towards the media server.
  defp render(%{kind: :command, type: :media, name: name}, current) do
    {["#{@local} -[#{@media_color}]> #{@media} : #{media_label(name)}"], current}
  end

  # A command that went nowhere — a timer armed, a database read, a block
  # entered: a note, because there is no lane it travelled to.
  defp render(%{kind: :command, type: type, name: name}, current)
       when type in @self_note_types do
    {["note over #{@local} : #{name}"], current}
  end

  # Anything else is a protocol command, and a protocol command goes to the peer.
  defp render(%{kind: :command, name: name}, current) do
    {["#{@local} -> #{@remote} : #{method_label(name)}"], current}
  end

  # First transition (no previous state) = entering the initial state.
  defp render(%{kind: :transition, to: to}, nil) do
    {["note over #{@local} : #{to}"], to}
  end

  # Subsequent transition: optionally an inbound arrow (from the peer for a SIP
  # event, from the media server for a media event), then the state-change note.
  defp render(%{kind: :transition, to: to, event: event, type: type}, from) do
    labelled? = event not in ["", "start"]

    inbound =
      cond do
        # Media events are drawn as a colored arrow from the media server.
        type == :media and labelled? ->
          ["#{@media} -[#{@media_color}]> #{@local} : #{event}"]

        type in @self_note_types ->
          []

        # By exclusion: a type this renderer has never heard of came from the
        # peer, which is the only place an unrecognised protocol event can come
        # from.
        labelled? ->
          ["#{@local} <-- #{@remote} : #{event}"]

        true ->
          []
      end

    {inbound ++ ["note over #{@local} : #{from} -> #{to}"], to}
  end

  # Terminal outcome → coloured note.
  defp render(%{kind: :terminal, outcome: outcome, reason: reason}, current) do
    label = if reason in ["", nil], do: to_string(outcome), else: "#{outcome}: #{reason}"
    color = if outcome == :succeeded, do: "#LightGreen", else: "#Pink"
    {["note over #{@local} #{color} : #{label}"], current}
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # A prefix rule over command names, not a SIP table: "send_INVITE" → "INVITE",
  # "send_auth_REGISTER" → "REGISTER (auth)", "send_message" → "MESSAGE".
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
