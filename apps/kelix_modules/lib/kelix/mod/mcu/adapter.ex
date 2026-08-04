defmodule Kelix.Mod.Mcu.Adapter do
  @moduledoc """
  The `MediaServer.Behaviour` face of the MCU module (design
  `docs/design/mcu_module.md` §4.2).

  Being a behaviour implementation is the whole point: `media_connect()`,
  `reply_invite_with_sdp/2` and `media_cleanup_ressources()` in `mcu.exs` are the
  *same* macros `uas_invite.exs` already uses — a conference leg is a peer
  connection whose far end happens to be a mixer.

  | `MediaServer.Behaviour` | MCU API |
  |---|---|
  | `connect/1` | resolve the `Client` of that MCU entry |
  | `create_peer_connection/3` | `CreateParticipant` in `opts[:mcu_participant]`'s conference |
  | `set_remote_offer/2` | the answer-time sequence (§6.2 steps 3-6) → SDP answer |
  | `close_peer_connection/1` | `StopSending`/`StopReceiving` + `DeleteParticipant` |
  | `add_remote_candidate/2` | `:ok`, no-op (G5: ICE-lite plus the offerer's candidates is enough) |
  | `get_local_offer/1`, `set_remote_answer/2` | `{:error, :not_supported}` until B2BUA legs exist |
  | player / recorder / echo | `{:error, :not_supported}` — the RPCs exist (§1.2), the perimeter does not |

  The conference-level operations are **not** forced into the behaviour: they are
  plain functions on `Kelix.Mod.Mcu`. What is here is what belongs to one leg.

  **This increment answers audio over plain RTP** (§14, P2). Video (mosaic,
  `SetVideoCodec`, FPU) is P3 and SDES/DTLS+ICE is P4, so a video `m=` line is
  answered with port 0 — the call proceeds audio-only, which is mcuGold's behaviour
  — and a secure offer is refused with `:secure_not_supported` rather than answered
  with a security level we do not yet configure.
  """
  @behaviour MediaServer.Behaviour

  require Logger

  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.Adapter.Conn

  # ── server lifecycle ─────────────────────────────────────────────────────────

  @doc """
  Resolve the media server a conference leg must reach.

  `url` is `"mcu://<entry name>"` (what `Kelix.Mod.Mcu.media_config/1` produces), a
  configured entry name, or the entry's own `url` — a conference is pinned to one
  MCU (§1.3), so this resolves a *named* server rather than picking one.
  """
  @impl MediaServer.Behaviour
  @spec connect(String.t() | {String.t(), pos_integer}) :: {:ok, pid} | {:error, term}
  def connect("mcu://" <> name), do: connect_entry(name)
  def connect(url) when is_binary(url), do: connect_entry(url)
  def connect({host, port}), do: connect_entry("http://#{host}:#{port}")

  defp connect_entry(name_or_url) do
    case find_entry(name_or_url) do
      %{status: :up, client: client} when is_pid(client) -> {:ok, client}
      %{name: name} -> {:error, {:mcu_down, name}}
      nil -> {:error, {:unknown_mcu, name_or_url}}
    end
  end

  defp find_entry(name_or_url) do
    case Mcu.mediaserver(name_or_url) do
      {:ok, entry} -> entry
      :error -> Enum.find(Mcu.mediaservers(), &(&1.url == name_or_url))
    end
  end

  @doc """
  Release the leg's reference to the media server.

  A no-op by design: the control channel is **node-scoped** (one per MCU, shared by
  every conference on it), so a call ending must not close it.
  """
  @impl MediaServer.Behaviour
  @spec disconnect(pid, keyword) :: :ok
  def disconnect(_client, _opts \\ []), do: :ok

  # ── peer connection ──────────────────────────────────────────────────────────

  @doc """
  Create the MCU-side participant for this leg.

  `opts[:mcu_participant]` is the row `Kelix.Mod.Mcu.admit/2` returned; the script
  passes it through `appdata[:media_conn_opts]`, which FW-1 merges into these opts.
  Without it there is no conference to join, and that is a scenario bug rather than a
  call failure — hence the explicit error.

  `opts[:nat_latch]` (default `false`) travels the same way and asks the MCU to
  follow a symmetric NAT's mapping on this leg — see `Conn.set_rtp_properties/3`.
  """
  @impl MediaServer.Behaviour
  @spec create_peer_connection(pid, pid, keyword) :: {:ok, pid} | {:error, term}
  def create_peer_connection(client, event_sink, opts \\ []) do
    case Keyword.get(opts, :mcu_participant) do
      %{conf_uid: _, ref: _} = part -> Conn.start(client, event_sink, part, opts)
      _ -> {:error, :no_mcu_participant}
    end
  end

  @impl MediaServer.Behaviour
  def set_remote_offer(conn, sdp), do: Conn.set_remote_offer(conn, sdp)

  @impl MediaServer.Behaviour
  @spec close_peer_connection(pid | nil) :: :ok
  def close_peer_connection(conn), do: Conn.close(conn)

  @doc """
  Trickle ICE is not fed to the MCU (G5): the API has no input for it, and
  ICE-lite plus the offerer's own candidates covers the gateway and WebRTC cases in
  scope. `:ok` rather than an error, so a script that forwards candidates blindly
  keeps working.
  """
  @impl MediaServer.Behaviour
  def add_remote_candidate(_conn, _candidate), do: :ok

  # Outbound legs need `get_local_offer/1` + `set_remote_answer/2`; they arrive with
  # the B2BUA leg primitives (§1.2), and the DSL surfaces the error as a 500 —
  # which is the honest answer to a scenario asking a mixer to place a call.
  @impl MediaServer.Behaviour
  def get_local_offer(_conn), do: {:error, :not_supported}

  @impl MediaServer.Behaviour
  def set_remote_answer(_conn, _sdp), do: {:error, :not_supported}

  # ── participant-level extras (not part of the behaviour) ─────────────────────

  @doc "ACK-time: codecs, `StartSending`, mixer join. Returns the per-media summary."
  @spec attach(pid | nil) :: {:ok, map} | {:error, term}
  def attach(conn), do: Conn.attach(conn)

  @doc "Close the leg: `StopSending`/`StopReceiving` + `DeleteParticipant`. Idempotent."
  @spec close(pid | nil) :: :ok
  def close(conn), do: Conn.close(conn)

  @doc "`SendFPU` — ask the MCU for an intra-frame from this participant."
  @spec send_fpu(pid | nil) :: :ok | {:error, term}
  def send_fpu(conn), do: Conn.send_fpu(conn)

  @doc "`SetMute` on one media of this participant."
  @spec mute(pid | nil, MediaServer.media(), boolean) :: :ok | {:error, term}
  def mute(conn, media, muted?), do: Conn.mute(conn, media, muted?)

  # ── out of scope for a conference leg ────────────────────────────────────────

  @impl MediaServer.Behaviour
  def create_player(_conn, _file, _opts \\ []), do: {:error, :not_supported}
  @impl MediaServer.Behaviour
  def start_player(_player), do: {:error, :not_supported}
  @impl MediaServer.Behaviour
  def pause_player(_player), do: {:error, :not_supported}
  @impl MediaServer.Behaviour
  def stop_player(_player), do: :ok
  @impl MediaServer.Behaviour
  def create_recorder(_conn, _file, _duration, _opts \\ []), do: {:error, :not_supported}
  @impl MediaServer.Behaviour
  def start_recorder(_recorder), do: {:error, :not_supported}
  @impl MediaServer.Behaviour
  def stop_recorder(_recorder), do: :ok
  @impl MediaServer.Behaviour
  def create_echo(_conn), do: {:error, :not_supported}
  @impl MediaServer.Behaviour
  def stop_echo(_echo), do: :ok
end
