defmodule Kelix.Mod.Mcu.Adapter.Conn do
  @moduledoc """
  One conference leg: the MCU-side participant plus its media state (design
  `docs/design/mcu_module.md` §4.1, §6.2).

  The participant is created in `init/1` and deleted in `terminate/2`, so **its MCU
  lifetime is exactly this process's lifetime** (§8.2) — that is the invariant that
  makes an orphaned participant impossible, and the reason `admit/2` reserves only
  the slot.

  The split between answer-time and ACK-time work is transcribed from mcuGold and is
  not an implementation detail (§2, point 2):

    * **answer time** (`set_remote_offer/2`) — negotiate, `StartReceiving` (which is
      what yields the local port the SDP needs), `SetRTPProperties`. We start
      *receiving* before answering;
    * **ACK time** (`attach/1`) — `SetAudioCodec`, `StartSending`, then join the
      mixer. So a caller that never ACKs never enters the mix, and no RTP leaves the
      MCU before the call is established.

  Getting that order wrong yields a media server that answers `returnCode: 1` to
  everything and sends no RTP.

  P2 perimeter: audio, plain RTP. `@supported_medias` is what gates it — a video or
  text section is answered with port 0 rather than half-configured.
  """
  use GenServer
  require Logger

  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.Client
  alias MediaServer.SdpTools, as: Sdp

  # MediaFrame::Type wire values (§3.6)
  @media_int %{audio: 0, video: 1, text: 2}
  # MediaRole: main. Slides (1) is out of scope, but the parameter is passed
  # correctly so adding it later is additive (§1.2).
  @role_main 0
  # MediaProtocol: RTP
  @proto_rtp 0
  # RTP participant (1 is RTMP, unused)
  @participant_rtp 0
  # the default mosaic and the default sidebar (decision 6b)
  @default_mosaic 0
  @default_sidebar 0

  # Audio only in this increment: video is P3 (mosaic + SetVideoCodec + FPU), text
  # needs SetTextCodec. Anything else offered is declined with port 0.
  @supported_medias [:audio]

  @call_timeout 30_000

  # ── API ──────────────────────────────────────────────────────────────────────

  @spec start(pid, pid, map, keyword) :: {:ok, pid} | {:error, term}
  def start(client, event_sink, participant, opts) do
    case GenServer.start(__MODULE__, {client, event_sink, participant, opts}) do
      {:ok, pid} -> {:ok, pid}
      {:error, reason} -> {:error, reason}
      :ignore -> {:error, :conn_failed}
    end
  end

  @spec set_remote_offer(pid, String.t()) :: {:ok, String.t()} | {:error, term}
  def set_remote_offer(conn, sdp) when is_pid(conn),
    do: safe_call(conn, {:set_remote_offer, sdp})

  @spec attach(pid | nil) :: {:ok, map} | {:error, term}
  def attach(conn) when is_pid(conn), do: safe_call(conn, :attach)
  def attach(_conn), do: {:error, :no_connection}

  @spec send_fpu(pid | nil) :: :ok | {:error, term}
  def send_fpu(conn) when is_pid(conn), do: safe_call(conn, :send_fpu)
  def send_fpu(_conn), do: {:error, :no_connection}

  @spec mute(pid | nil, atom, boolean) :: :ok | {:error, term}
  def mute(conn, media, muted?) when is_pid(conn), do: safe_call(conn, {:mute, media, muted?})
  def mute(_conn, _media, _muted?), do: {:error, :no_connection}

  @doc "Close the leg. Idempotent, and safe on a nil / already-dead connection."
  @spec close(pid | nil) :: :ok
  def close(conn) when is_pid(conn) do
    GenServer.stop(conn, :normal, @call_timeout)
  catch
    :exit, _ -> :ok
  end

  def close(_conn), do: :ok

  # A wedged or dead connection is an error the script can answer with, never a
  # raised exit inside a scenario instance.
  defp safe_call(conn, request) do
    GenServer.call(conn, request, @call_timeout)
  catch
    :exit, {:noproc, _} -> {:error, :no_connection}
    :exit, _ -> {:error, :media_timeout}
  end

  # ── init: CreateParticipant ──────────────────────────────────────────────────

  @impl true
  def init({client, event_sink, participant, opts}) do
    with {:ok, conf} <- fetch_conference(participant.conf_uid),
         {:ok, entry} <- fetch_entry(conf.mcu),
         {:ok, part_id} <- create_participant(client, conf, participant) do
      Mcu.bind_participant(conf.uid, participant.ref, part_id, self())

      Logger.info(
        module: __MODULE__,
        message:
          "conference #{conf.uid}: participant #{part_id} (#{participant.name}) created on #{conf.mcu}"
      )

      {:ok,
       %{
         client: client,
         event_sink: event_sink,
         entry: entry,
         conf_uid: conf.uid,
         conf_id: conf.conf_id,
         part_ref: participant.ref,
         part_id: part_id,
         # medias requested by the scenario, capped to what this increment answers
         medias: requested_medias(opts),
         # per media: %{codec:, rec_port:, send: {ip, port}, rtp_map:, dtmf_clock:}
         negotiated: %{},
         receiving: [],
         sending: [],
         status: :created
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  defp requested_medias(opts) do
    opts
    |> Keyword.get(:media, :audio)
    |> MediaServer.media_list()
    |> Enum.filter(&(&1 in @supported_medias))
  end

  defp fetch_conference(uid) do
    case Mcu.conference(uid) do
      {:ok, conf} -> {:ok, conf}
      :error -> {:error, :no_such_conference}
    end
  end

  defp fetch_entry(mcu) do
    case Mcu.mediaserver(mcu) do
      {:ok, entry} -> {:ok, entry}
      :error -> {:error, {:unknown_mcu, mcu}}
    end
  end

  defp create_participant(client, conf, participant) do
    Client.create(client, "CreateParticipant", [
      conf.conf_id,
      participant.name,
      @participant_rtp,
      @default_mosaic,
      @default_sidebar
    ])
  end

  # ── answer time (§6.2 steps 3-6) ─────────────────────────────────────────────

  @impl true
  def handle_call({:set_remote_offer, sdp}, _from, state) do
    with {:ok, descs} <- parse_offer(sdp),
         :ok <- ensure_insecure(descs),
         {:ok, conf} <- fetch_conference(state.conf_uid),
         {:ok, state, negotiated} <- open_receive_plane(state, conf, descs),
         :ok <- ensure_audio(negotiated) do
      answer =
        Sdp.build(%{
          ip: media_ip(state),
          # RFC 3264 §6: one answer m= per offered m=, in order. What we cannot
          # answer is declined with port 0 rather than omitted.
          medias: Enum.map(descs, &answer_or_reject(state, negotiated, &1))
        })

      {:reply, {:ok, answer}, %{state | negotiated: negotiated, status: :answered}}
    else
      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message: "conference #{state.conf_uid}: offer refused (#{inspect(reason)})"
        )

        {:reply, {:error, reason}, state}
    end
  end

  # ── ACK time (§6.2, after the 200 OK) ────────────────────────────────────────

  def handle_call(:attach, _from, %{status: :attached} = state) do
    # a re-INVITE answered on the same leg re-runs the answer sequence, and its ACK
    # arrives again: joining the mixer twice is not an error, it is a no-op
    {:reply, {:ok, media_summary(state)}, state}
  end

  def handle_call(:attach, _from, state) do
    case start_sending_all(state) do
      {:ok, state} ->
        {:reply, {:ok, media_summary(state)}, %{state | status: :attached}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:send_fpu, _from, state) do
    {:reply, void_rpc(state, "SendFPU", [state.conf_id, state.part_id]), state}
  end

  def handle_call({:mute, media, muted?}, _from, state) do
    reply =
      void_rpc(state, "SetMute", [
        state.conf_id,
        state.part_id,
        media_int(media),
        bool_int(muted?)
      ])

    {:reply, reply, state}
  end

  @impl true
  def terminate(_reason, state) do
    teardown(state)
    :ok
  end

  # ── receive plane ────────────────────────────────────────────────────────────

  # Per media: negotiate, StartReceiving (whose return is the port the SDP answer
  # advertises), then the transport properties. Nothing is sent yet.
  defp open_receive_plane(state, conf, descs) do
    descs
    |> Enum.filter(&answerable?(&1, state.medias))
    |> Enum.reduce_while({:ok, state, %{}}, fn desc, {:ok, st, acc} ->
      case open_receive(st, conf, desc) do
        {:ok, st, neg} -> {:cont, {:ok, st, Map.put(acc, desc.type, neg)}}
        # no codec in common on this media: declined (port 0), not a call failure
        :skip -> {:cont, {:ok, st, acc}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp open_receive(state, conf, desc) do
    codecs = Map.get(conf.codecs, desc.type, [])

    case Sdp.negotiate(desc, codecs, conf.dtmf) do
      # nothing in common on this media: it is declined (port 0), not a call failure
      {:error, :no_common_codec} ->
        :skip

      {:ok, neg} ->
        media = desc.type
        m = media_int(media)

        # §6.3 rule 1: the answer reuses the offer's payload-type numbering, so both
        # rtpMaps are keyed with the OFFERED PTs — no local renumbering.
        rtp_map = neg.rtp_map

        with {:ok, [rec_port | _]} <-
               rpc(state, "StartReceiving", [
                 state.conf_id,
                 state.part_id,
                 m,
                 rtp_map,
                 @role_main,
                 @proto_rtp
               ]),
             :ok <- set_rtp_properties(state, m, desc) do
          {:ok, %{state | receiving: [media | state.receiving]},
           Map.merge(neg, %{rec_port: rec_port, remote: {desc.ip, desc.port}})}
        end
    end
  end

  # rtcp-mux is mirrored from the offer; the RTCP-feedback hints ride along on an
  # AVPF profile. `secure` is deliberately not sent: SDES/DTLS is P4, and claiming
  # it here would configure a security level we never key.
  defp set_rtp_properties(state, m, desc) do
    props =
      %{}
      |> put_if(Map.get(desc, :rtcp_mux, false), "rtcp-mux", "1")
      |> put_if(avpf?(desc), "useNACK", "1")
      |> put_if(avpf?(desc), "tmmbr", "1")

    if props == %{} do
      :ok
    else
      void_rpc(state, "SetRTPProperties", [
        state.conf_id,
        state.part_id,
        m,
        props,
        @role_main
      ])
    end
  end

  defp put_if(map, true, key, value), do: Map.put(map, key, value)
  defp put_if(map, false, _key, _value), do: map

  defp avpf?(%{protocol: protocol}), do: String.ends_with?(protocol, "F")

  # ── send plane + mixer join ──────────────────────────────────────────────────

  defp start_sending_all(state) do
    state.negotiated
    |> Enum.reduce_while({:ok, state}, fn {media, neg}, {:ok, st} ->
      case start_sending(st, media, neg) do
        {:ok, st} -> {:cont, {:ok, st}}
        {:error, _} = err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, state} -> join_mixer(state)
      err -> err
    end
  end

  defp start_sending(state, media, neg) do
    {ip, port} = neg.remote
    m = media_int(media)

    with :ok <- set_codec(state, media, neg),
         :ok <-
           void_rpc(state, "StartSending", [
             state.conf_id,
             state.part_id,
             m,
             ip,
             port,
             neg.rtp_map,
             @role_main
           ]) do
      {:ok, %{state | sending: [media | state.sending]}}
    end
  end

  # The codec the mixer encodes *towards* this participant: the first common one, in
  # the conference's preference order (which `negotiate/3` preserved).
  defp set_codec(state, :audio, neg) do
    case primary_code(:audio, neg) do
      nil ->
        {:error, :no_common_codec}

      code ->
        void_rpc(state, "SetAudioCodec", [state.conf_id, state.part_id, code])
    end
  end

  # Video needs SetVideoCodec with the conference's inline profile (P3); until then
  # no video media reaches here (@supported_medias).
  defp set_codec(_state, media, _neg), do: {:error, {:media_not_supported, media}}

  # The Medooze constant of a codec name, read off the shared codec tables (a
  # one-entry rtpMap is the table lookup those tables expose).
  defp primary_code(media, neg) do
    case neg.codecs do
      [name | _] -> media |> Sdp.local_rtp_map([name], false) |> Map.values() |> List.first()
      [] -> nil
    end
  end

  # Audio joins the default **sidebar** (what the MCU API calls a sidebar is what
  # mcuGold's UI calls the audio mixer); video would join the default mosaic (P3).
  defp join_mixer(state) do
    if :audio in state.sending do
      case void_rpc(state, "AddSidebarParticipant", [
             state.conf_id,
             @default_sidebar,
             state.part_id
           ]) do
        :ok -> {:ok, state}
        err -> err
      end
    else
      {:ok, state}
    end
  end

  # ── answer building ──────────────────────────────────────────────────────────

  defp answer_or_reject(state, negotiated, desc) do
    case Map.get(negotiated, desc.type) do
      nil -> reject_spec(desc)
      neg -> answer_spec(state, desc, neg)
    end
  end

  # A declined section keeps its place in the answer with port 0 and the offered
  # format list echoed verbatim (RFC 3264 §6): the m= line count must match.
  defp reject_spec(desc) do
    %{
      type: desc.type,
      protocol: Map.get(desc, :protocol, "RTP/AVP"),
      reject_fmt: Map.get(desc, :raw_fmt, [])
    }
  end

  defp answer_spec(_state, desc, neg) do
    %{
      type: desc.type,
      port: neg.rec_port,
      # the offerer's payload-type numbering (§6.3 rule 1)
      rtpmaps: Sdp.answer_rtpmaps(desc.type, neg),
      fmtp: dtmf_fmtp(neg),
      # sendrecv for a mixed participant; a one-way offer is mirrored (rule 7)
      direction: Sdp.reverse_direction(desc.direction),
      # mirror the transport of the offer (rule 4)
      protocol: desc.protocol,
      rtcp_mux: Map.get(desc, :rtcp_mux, false),
      crypto: :none,
      ice: nil
    }
  end

  # RFC 4733: the telephone-event PT carries the tone range it accepts.
  defp dtmf_fmtp(%{dtmf: true, dtmf_pt: pt}) when is_integer(pt),
    do: %{Integer.to_string(pt) => "0-16"}

  defp dtmf_fmtp(_neg), do: %{}

  # G2: the media address is configuration, not a server answer — `public_ip` is
  # what goes in the SDP (it differs from `rtp_ip` behind NAT).
  defp media_ip(%{entry: entry}) do
    entry.public_ip || entry.rtp_ip ||
      raise "mcu #{entry.name} has neither public_ip nor rtp_ip: the SDP answer has no address"
  end

  # ── guards ───────────────────────────────────────────────────────────────────

  defp parse_offer(sdp) do
    case Sdp.parse(sdp) do
      {:ok, descs} -> {:ok, descs}
      # an unparsable offer is a 400 on the SIP side (§6.5)
      {:error, reason} -> {:error, {:bad_offer, reason}}
    end
  end

  # SDES / DTLS legs are P4. Refused explicitly: answering a secure offer with a
  # clear-RTP answer would produce a call that connects and never decodes.
  defp ensure_insecure(descs) do
    if Enum.any?(descs, &(Map.get(&1, :crypto, :none) != :none)),
      do: {:error, :secure_not_supported},
      else: :ok
  end

  # No audio ⇒ no conference leg. Video-only would need P3 anyway.
  defp ensure_audio(negotiated) do
    if Map.has_key?(negotiated, :audio), do: :ok, else: {:error, :no_common_codec}
  end

  defp answerable?(desc, medias) do
    Map.get(desc, :supported?, false) and desc.type in medias
  end

  # ── teardown ─────────────────────────────────────────────────────────────────

  # Stop the planes then delete the participant. Best effort throughout: this runs
  # on the call-end path (and on a crash), where a failed RPC must not prevent the
  # rest of the cleanup.
  defp teardown(state) do
    for media <- state.sending do
      void_rpc(state, "StopSending", [state.conf_id, state.part_id, media_int(media), @role_main])
    end

    for media <- state.receiving do
      void_rpc(state, "StopReceiving", [
        state.conf_id,
        state.part_id,
        media_int(media),
        @role_main
      ])
    end

    void_rpc(state, "DeleteParticipant", [state.conf_id, state.part_id])
    :ok
  end

  # ── helpers ──────────────────────────────────────────────────────────────────

  defp media_summary(state) do
    Map.new(state.negotiated, fn {media, neg} ->
      {media,
       %{
         codec: List.first(neg.codecs),
         rec_port: neg.rec_port,
         send: neg.remote,
         dtmf: Map.get(neg, :dtmf, false)
       }}
    end)
  end

  defp media_int(media), do: Map.fetch!(@media_int, media)
  defp bool_int(true), do: 1
  defp bool_int(false), do: 0

  defp rpc(state, method, params), do: Client.call(state.client, method, params)

  defp void_rpc(state, method, params) do
    case Client.call(state.client, method, params) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end
end
