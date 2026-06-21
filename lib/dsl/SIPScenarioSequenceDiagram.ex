defmodule SIP.Scenario.SequenceDiagram do
  @moduledoc """
  Pure renderer turning a `SIP.Scenario.SequenceJournal` event list plus metadata
  into a [PlantUML](https://plantuml.com/sequence-diagram) sequence diagram.

  It has **no dependency on the SIP stack**, so it is fully unit-testable in
  isolation. The fidelity is deliberately reduced (v1): the diagram is built from
  the instrumentation already available — outbound command names (`send_INVITE` →
  an `INVITE` arrow), state transitions (rendered as notes) and the free-text
  description carried by each transition. A transition categorized as `:sip` with
  a non-empty description is rendered as an inbound arrow (the description is the
  message the scenario author labelled it with, e.g. `"200 OK"`).
  """

  # Participant aliases used throughout the diagram.
  @local "elixip"
  @remote "peer"

  @doc "Render the full PlantUML document as a String."
  @spec to_plantuml([map()], map()) :: String.t()
  def to_plantuml(events, meta) when is_list(events) and is_map(meta) do
    [
      header(meta),
      "@startuml",
      participants(meta),
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

  defp participants(meta) do
    config = Map.get(meta, :config, [])

    [
      participant(@local, Keyword.get(config, :username)),
      participant(@remote, Keyword.get(config, :domain))
    ]
  end

  defp participant(alias_name, nil), do: "participant #{alias_name}"
  defp participant(alias_name, label), do: ~s(participant "#{label}" as #{alias_name})

  # ── Body ──────────────────────────────────────────────────────────────────

  defp body(events) do
    {lines, _current_state} =
      Enum.reduce(events, {[], nil}, fn event, {acc, current} ->
        {rendered, next} = render(event, current)
        {acc ++ rendered, next}
      end)

    lines
  end

  # Outbound SIP command → request arrow towards the peer.
  defp render(%{kind: :command, type: :sip, name: name}, current) do
    {["#{@local} -> #{@remote} : #{method_label(name)}"], current}
  end

  # Media / other commands have no SIP peer: render them as a self-note.
  defp render(%{kind: :command, name: name}, current) do
    {["note over #{@local} : #{name}"], current}
  end

  # First transition (no previous state) = entering the initial state.
  defp render(%{kind: :transition, to: to}, nil) do
    {["note over #{@local} : #{to}"], to}
  end

  # Subsequent transition: optionally an inbound arrow, then the state-change note.
  defp render(%{kind: :transition, to: to, event: event, type: type}, from) do
    inbound =
      if type == :sip and event not in ["", "start"] do
        ["#{@local} <-- #{@remote} : #{event}"]
      else
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
end
