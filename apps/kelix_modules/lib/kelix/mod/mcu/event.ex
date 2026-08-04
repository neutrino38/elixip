defmodule Kelix.Mod.Mcu.Event do
  @moduledoc """
  The module's **canonical event vocabulary** (design
  `docs/design/mcu_module.md` §11.1), frozen now so that adding a transport later
  (per-conference HTTP callbacks) is a transport change and not a redesign.

  Everything the module observes is emitted here exactly once, and the consumers
  read the same term: today the logger, tomorrow the metrics emitter and a callback
  fan-out. Two invariants the design leans on:

  1. **`participant.left` is emitted exactly once per participant**, whatever the
     teardown path (BYE, kick, crash reaper, MCU loss) — the reason `leave/1` is
     idempotent.
  2. **A rejected call never emits `participant.ringing`**, so a UI can count
     `ringing − joined` as "abandoned before answer" without correcting for 404s
     and 486s.
  3. **`participant.joined` is emitted once per entry into the mix** — the
     registry absorbs a repeated `attach/1` (a retransmitted ACK, a re-INVITE
     renegotiation), so a joined count is a call count, not an ACK count.

  `participant.media_connected` / `participant.media_timeout` are declared although
  the server does not emit them before P7 (§16.1-16.2): a consumer written today
  needs no change when they start arriving.
  """
  require Logger

  @type name ::
          :"conference.created"
          | :"conference.updated"
          | :"conference.destroyed"
          | :"conference.layout_changed"
          | :"conference.recording_started"
          | :"conference.recording_stopped"
          | :"conference.slot_changed"
          | :"participant.ringing"
          | :"participant.joined"
          | :"participant.left"
          | :"participant.rejected"
          | :"participant.muted"
          | :"participant.fpu_requested"
          | :"participant.media_connected"
          | :"participant.media_timeout"
          | :"mediaserver.up"
          | :"mediaserver.down"

  @type t :: %__MODULE__{name: name, uid: String.t() | nil, at: DateTime.t(), data: map}

  defstruct name: nil, uid: nil, at: nil, data: %{}

  @doc """
  Emit one event. Returns the event, so a caller can pass it on.

  Every line carries the conference `uid`, which is what lets a call be followed
  end to end in the logs (§11).
  """
  @spec emit(name, String.t() | nil, map) :: t
  def emit(name, uid, data \\ %{}) do
    event = %__MODULE__{name: name, uid: uid, at: DateTime.utc_now(), data: data}
    log(event)
    event
  end

  # Conference and participant lifecycle are the operator's timeline: info.
  # A rejection is not an error of ours (a full conference, an unknown DID), so it
  # stays info too; only losing a media server is an error.
  defp log(%__MODULE__{name: :"mediaserver.down"} = event), do: Logger.error(fields(event))

  defp log(%__MODULE__{} = event), do: Logger.info(fields(event))

  defp fields(%__MODULE__{name: name, uid: uid, data: data}) do
    [module: __MODULE__, message: "#{name} #{uid}: #{describe(data)}"]
  end

  defp describe(data) when map_size(data) == 0, do: "-"

  defp describe(data) do
    Enum.map_join(data, " ", fn {k, v} -> "#{k}=#{render(v)}" end)
  end

  defp render(v) when is_binary(v) or is_integer(v) or is_atom(v), do: to_string(v)
  defp render(v), do: inspect(v)
end
