defmodule Kelix.Mod.Mcu.Adapter.Conn do
  @moduledoc """
  One conference leg: the MCU-side participant plus its media state (design
  `docs/design/DESIGN-MCU.md`).

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

  Perimeter: **total conversation** — audio, video and T.140 text — over plain RTP,
  SDES-SRTP or DTLS-SRTP + ICE-lite, the three transports mcuGold supports, so a SIP
  phone, a text terminal and a WebRTC gateway join the same conference.
  `@supported_medias` is what gates the media list; anything else offered is answered
  with port 0 rather than half-configured.

  Text is a media like the others here, with two differences worth knowing: the MCU
  wires every participant into the text mixer at `CreateParticipant`, so there is no
  join RPC to pair with `AddSidebarParticipant`/`AddMosaicParticipant`; and `T140RED`
  (RFC 4103 redundancy) needs an `a=fmtp` naming the T.140 payload type, which
  `red_fmtp/2` builds in the *offerer's* numbering like every other answer field.
  """
  use GenServer
  require Logger

  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.Client
  alias Kelix.Mod.Mcu.Vocabulary
  alias MediaServer.SdpTools, as: Sdp

  # MediaFrame::Type wire values (§3.6)
  @media_int %{audio: 0, video: 1, text: 2}
  # MediaRole: main. Slides (1) is out of scope, but the parameter is passed
  # correctly so adding it later is additive (§1.2).
  @role_main 0
  # MediaProtocol: RTP
  @proto_rtp 0
  # MediaProtocol: WS — the only non-RTP transport this adapter drives, and only
  # for text (S5, DESIGN-MCU.md)
  @proto_ws 2
  # telephone-event's Medooze codec constant (§3.6): a payload type the mixer never
  # encodes towards anyone, so it can never be a primary codec.
  @dtmf_code 100
  # A conference leg is a stream the mixer ENCODES, so the H.264 profile is ours to
  # pick among what the peer offered (§6): Main over Baseline. The JSR309 adapter,
  # which relays another peer's stream, does not set this.
  @fmt_order_opts [prefer_h264_profile: true]
  # RTP participant (1 is RTMP, unused)
  @participant_rtp 0
  # the default mosaic and the default sidebar (decision 6b)
  @default_mosaic 0
  @default_sidebar 0

  # Total conversation: audio, video and text. Anything else offered (an
  # `application` section for BFCP, say) is declined with port 0.
  @supported_medias [:audio, :video, :text]

  # The hash the DTLS fingerprint is fetched and advertised under (§6.3 rule 6).
  @dtls_hash "SHA-256"

  # SDES suites, in our preference order. The first is what an offer we do not
  # recognise gets answered with; anything the offer states and we know is mirrored.
  # SDES suites this mixer implements, in our preference order. An offer whose every
  # `a=crypto` line names something else is refused (`:no_common_sdes_suite`), which is
  # honest: the alternative is a call that establishes and decrypts nothing.
  @sdes_suites ["AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32"]

  # MKI rank of the remote key (`SetRemoteCryptoSDES`'s seventh argument, MCU-API):
  # 0 when the offered line declares no MKI, which is every offer seen so far.
  @sdes_key_rank 0

  # The feedback types this mixer can actually honour, each with the server-side switch
  # that implements it (§3.4). Announcing anything else would tell the peer it has a
  # capability nothing implements — the same class of defect as the unprefixed
  # `h264.profile-level-id` of rule 9.
  #
  # `nack pli` shares the FIR switch: the server treats an incoming PLI exactly like
  # a FIR (both land in onFPURequested, rtpsession.cpp), so there is nothing more to
  # enable — but a peer that negotiated `nack pli` may send PLI *instead of* FIR
  # (Linphone does), so it must be confirmed in the answer, not dropped (the FPU flow
  # of §6.4 covers both). NOT `useNACK`: PLI is a keyframe request, not a
  # retransmission request.
  #
  # `goog-remb` (draft-alvestrand-rmcat-remb-03) carries the same message as
  # `ccm tmmbr` in the browsers' dialect, and until the rate-control lot 2 the mixer
  # had no switch for it — Chrome and Firefox offer `goog-remb` and never `ccm tmmbr`,
  # so nothing congestion-related ever left towards them. The server now has its own
  # mode (`remb`), TMMBR wins when a peer asks for both, and neither is emitted
  # un-negotiated (arbitrage A2): announcing it here is what turns it on.
  #
  # `transport-cc` is deliberately ABSENT: the attribute alone switches nothing on. Its
  # server-side property is keyed by the RTP header extension's URI and valued with the
  # negotiated extmap id (`transport_cc_props/1`), so it cannot ride this
  # attribute-to-switch table. It is still confirmed in the answer
  # (`answered_transport_cc_fb/1`).
  @supported_rtcp_fb %{
    "nack" => "useNACK",
    "nack pli" => "useRtcpFIR",
    "ccm fir" => "useRtcpFIR",
    "ccm tmmbr" => "tmmbr",
    "goog-remb" => "remb"
  }

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
         # the MCU's name, for logs only: this leg needs nothing from the entry's
         # configuration — the media address comes from the server itself (§16.5)
         mcu: conf.mcu,
         conf_uid: conf.uid,
         conf_id: conf.conf_id,
         part_ref: participant.ref,
         part_id: part_id,
         # medias requested by the scenario, capped to what this increment answers
         # what this leg answers: what the scenario asked for, intersected with what the
         # conference serves (§8.4 `medias`). Dropping a media from the conference is
         # what `text_codecs = []` used to mean, said once for all three.
         medias:
           Enum.filter(requested_medias(opts), &(&1 in Map.get(conf, :medias, @supported_medias))),
         # the conference's inline video profile as of the answer (§5.1): what the
         # mixer encodes towards this leg, and the cap on its b=AS:
         video: conf.video,
         # whether this scenario allows a DTLS/ICE leg at all (SDES needs no such
         # permission: it is what a plain SIP phone offers)
         webrtc: Keyword.get(opts, :webrtc_support, :if_offered),
         # whether the MCU may re-target its send address to where the RTP really
         # comes from (see set_rtp_properties/3). Off unless the script asks for
         # it: the reference `mcu.exs` does, a leg driven by some other script may
         # sit on a topology where following the source address is wrong.
         nat_latch: Keyword.get(opts, :nat_latch, false) == true,
         # RTP inactivity watchdog (§16.1), armed per media at the ACK. Config, not a
         # script knob: it describes the deployment's tolerance for a silent leg, not
         # this call's intent. 0 disables it, and so does a media server that predates
         # the `StartRTPTimeout` RPC.
         rtp_timeout_ms: Map.get(conf, :rtp_timeout_ms, 0),
         # security material, per leg: our SDES key per media, our ICE credentials
         # (one pair for the whole connection) and the server's DTLS fingerprint
         local_sdes: %{},
         local_ice: nil,
         local_dtls: nil,
         # the address the SDP answer advertises, as the media server reported it on
         # the first `StartReceiving` (§16.5). Server-wide, hence one value for the
         # whole leg rather than one per m= line.
         media_ip: nil,
         # what the server told this channel it can announce (§6.7), and the profile
         # this leg asked for — fixed on its first `StartReceiving`, then repeated
         # verbatim on every other RPC that carries one
         network_profiles: Client.network_profiles(client),
         address_profile: nil,
         # the profile of the LOCAL address this caller reached us on (FW-1
         # `local_ip:`), which is the preference among the families its offer names
         # — see `leg_profile/2`. nil on a leg we placed ourselves: it had no
         # transport when it was created.
         local_profile: local_profile(opts),
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

  # The local address of this leg states both halves of its profile, and neither is
  # configured: the address states its family, and `SIP.NetUtils.net_side/1` states
  # which side of the node's network it sits on, from the `internal` listeners'
  # networks. A leg we placed ourselves has no local address, so it has no profile
  # of its own to prefer.
  defp local_profile(opts) do
    case Keyword.get(opts, :address_profile) do
      stated when is_binary(stated) ->
        stated

      _ ->
        local_ip = Keyword.get(opts, :local_ip)

        case SIP.NetUtils.address_family(local_ip) do
          nil -> nil
          family -> profile_name(family, SIP.NetUtils.net_side(local_ip))
        end
    end
  end

  defp requested_medias(opts) do
    opts
    |> Keyword.get(:media, :audio_video)
    |> MediaServer.media_list()
    |> Enum.filter(&(&1 in @supported_medias))
  end

  defp fetch_conference(uid) do
    case Mcu.conference(uid) do
      {:ok, conf} -> {:ok, conf}
      :error -> {:error, :no_such_conference}
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
    # captured before `status` moves: a re-INVITE on an answered or attached leg is a
    # renegotiation, and hold/resume travels through exactly that path
    renegotiation? = state.status in [:answered, :attached]

    with {:ok, descs} <- parse_offer(sdp),
         {:ok, conf} <- fetch_conference(state.conf_uid),
         # re-read the profile: it is the conference's value *at answer time* that
         # this leg keeps for its life (§8.3)
         state = %{state | video: conf.video},
         {:ok, state} <- setup_local_security(state, descs),
         {:ok, state, negotiated} <- open_receive_plane(state, conf, descs),
         :ok <- ensure_any_media(negotiated) do
      answer =
        Sdp.build(%{
          ip: media_ip(state),
          # §6.3 rule 5: we advertise a=ice-lite and never gather reflexive
          # candidates. Session level, hence here rather than per media.
          ice_lite: state.local_ice != nil,
          # RFC 3264 §6: one answer m= per offered m=, in order. What we cannot
          # answer is declined with port 0 rather than omitted — except `m=text`
          # sections, which are OMITTED entirely when we do not serve them (see
          # omit_from_answer?/3).
          medias:
            descs
            |> Enum.reject(&omit_from_answer?(state, negotiated, &1))
            |> Enum.map(&answer_or_reject(state, negotiated, &1))
        })

      state = %{state | negotiated: negotiated, status: :answered}

      # A RE-negotiation adjusts the watchdog at the answer rather than waiting for an
      # ACK: the dialog is already established, so there is no ringing phase to avoid
      # surveilling — and the ACK path returns early on an attached leg, so waiting
      # for it would leave a resumed media unwatched for good.
      if renegotiation?, do: apply_rtp_timeouts(state)

      {:reply, {:ok, answer}, state}
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
        # §16.1: the watchdog is armed HERE and not at answer time. The ACK is the
        # first moment the 200 OK is known to have gone out, and arming from it is
        # what makes "answered but no media ever arrived" detectable while never
        # surveilling the ringing phase. A caller that never ACKs is the script's
        # idle timeout to catch, not ours.
        apply_rtp_timeouts(state)
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

  # ── local security material (§2 point 3, §6.2) ───────────────────────────────

  # Who generates what is not an implementation detail: for **SDES** the controller
  # generates the local key and pushes it (`SetLocalCryptoSDES`); for **ICE** the
  # controller generates ufrag/pwd (`SetLocalSTUNCredentials`); only the **DTLS**
  # fingerprint belongs to the server, and it is server-wide, so it is fetched once
  # per MCU and cached there.
  #
  # All of it goes in **before** `StartReceiving`: the receive plane must be keyed
  # before it opens, or the first packets arrive on a session that cannot decrypt
  # them.
  defp setup_local_security(state, descs) do
    answerable = Enum.filter(descs, &answerable?(&1, state.medias))

    with {:ok, state} <- setup_dtls(state, answerable),
         {:ok, state} <- setup_ice(state, answerable) do
      setup_sdes(state, answerable)
    end
  end

  defp setup_dtls(state, descs) do
    case Enum.find(descs, &match?({:dtls, _, _, _}, &1.crypto)) do
      nil ->
        {:ok, state}

      %{crypto: {:dtls, _setup, _hash, _fp}} ->
        if webrtc_allowed?(state) do
          case Client.dtls_fingerprint(state.client, @dtls_hash) do
            {:ok, fingerprint} -> {:ok, %{state | local_dtls: {@dtls_hash, fingerprint}}}
            {:error, _} = err -> err
          end
        else
          # the scenario said no: refusing is the honest answer, and it becomes a 488
          {:error, :secure_not_supported}
        end
    end
  end

  # One credential pair for the whole leg, pushed per media: that is what an offerer
  # expects to find in every m= section of our answer.
  #
  # A leg that already has its pair keeps it. This runs on every offer, and minting
  # fresh credentials mid-call **is** an ICE restart (RFC 8445 §9.1.1.1): the peer
  # must re-run connectivity checks, asked for by nothing but the fact that we are
  # answering again. Our candidates are fixed host candidates that never change, so
  # there is never anything on this side to restart. The peer's own credentials are
  # a different question, and `set_remote_security/3` pushes them on every offer —
  # so a restart the peer really asks for is still honoured.
  #
  # The capture of 2026-08-23 (09:22:36 → 09:22:58) is what this costs: three answers
  # in one dialog carried three ufrags, and the third answered a Linphone hold. The
  # handset never sent the resume — the re-INVITE simply never left it — and the user
  # hung up on a call frozen in pause.
  defp setup_ice(%{local_ice: %{}} = state, _descs), do: {:ok, state}

  defp setup_ice(state, descs) do
    if Enum.any?(descs, &(&1.ice != nil)) and webrtc_allowed?(state) do
      ice = %{ufrag: random_token(8), pwd: random_token(24)}

      descs
      |> Enum.reduce_while(:ok, fn desc, :ok ->
        case void_rpc(state, "SetLocalSTUNCredentials", [
               state.conf_id,
               state.part_id,
               media_int(desc.type),
               ice.ufrag,
               ice.pwd,
               @role_main
             ]) do
          :ok -> {:cont, :ok}
          err -> {:halt, err}
        end
      end)
      |> case do
        :ok -> {:ok, %{state | local_ice: ice}}
        err -> err
      end
    else
      {:ok, state}
    end
  end

  # SDES keys are per media (each stream gets its own), and ours is the one the answer
  # advertises — the peer decrypts what the mixer sends with it.
  #
  # The *selection* is the part that matters (RFC 4568 §6.2): an answerer picks **one**
  # of the offered `a=crypto` lines — one whose suite it actually supports — echoes that
  # line's **tag**, and keys its own direction with the same suite. So all three of
  # suite, tag and the peer's key come from the same offered line, and a leg whose
  # offered lines we all fail to support is refused rather than half-keyed.
  #
  # Reading only the first line (what this did) breaks on any modern client: Linphone
  # 6.2 offers four, `AEAD_AES_128_GCM` first — a suite this mixer does not do — so we
  # answered `AES_CM_128_HMAC_SHA1_80` while handing the server the GCM line's key. The
  # call established and neither side could decrypt the other.
  defp setup_sdes(state, descs) do
    descs
    |> Enum.filter(&(&1.crypto != :none and sdes_offered?(&1)))
    |> Enum.reduce_while({:ok, state}, fn desc, {:ok, st} ->
      case pick_sdes(desc) do
        nil ->
          Logger.warning(
            module: __MODULE__,
            message:
              "conference #{st.conf_uid}: #{desc.type} offers no SDES suite we support " <>
                "(#{desc.sdes_offers |> Enum.map(& &1.suite) |> Enum.join(", ")}); " <>
                "we do #{Enum.join(@sdes_suites, ", ")}"
          )

          {:halt, {:error, :no_common_sdes_suite}}

        %{tag: tag, suite: suite, key: peer_key} ->
          key = random_sdes_key()

          case void_rpc(st, "SetLocalCryptoSDES", [
                 st.conf_id,
                 st.part_id,
                 media_int(desc.type),
                 suite,
                 key,
                 @role_main
               ]) do
            :ok ->
              chosen = %{tag: tag, suite: suite, key: key, peer_key: peer_key}
              {:cont, {:ok, %{st | local_sdes: Map.put(st.local_sdes, desc.type, chosen)}}}

            err ->
              {:halt, err}
          end
      end
    end)
  end

  # An offer carrying `a=crypto` at all — `crypto` alone would be the DTLS tuple on a
  # leg that offers both, and DTLS wins there (§6.3.1 rule 2).
  defp sdes_offered?(desc), do: Map.get(desc, :sdes_offers, []) != []

  # The first offered line whose suite this mixer implements, in the OFFERER's order:
  # its preference, honoured, which is what an answerer owes it.
  defp pick_sdes(desc) do
    Enum.find(Map.get(desc, :sdes_offers, []), &(&1.suite in @sdes_suites))
  end

  # AES_CM_128 keying material is a 16-byte key plus a 14-byte salt, carried
  # base64 in the a=crypto line (RFC 4568 §6.1).
  defp random_sdes_key(), do: :crypto.strong_rand_bytes(30) |> Base.encode64()

  # ICE credentials, in the alphabet ICE actually defines for them: `ice-char =
  # ALPHA / DIGIT / "+" / "/"` (RFC 8839 §5.4, RFC 5245 §15.4 before it). Hex is a
  # strict subset, and it is what the field-proven gateway emits. Base64**url** —
  # which this used — produces `-` and `_`, outside that grammar: browsers happen not
  # to check, strict SDP parsers (the Glassfish gateway's among them) do, and a leg
  # rejected for a stray dash is a 488 no log explains.
  #
  # Lengths land where ICE wants them: 8 bytes → a 16-char ufrag, 24 → a 48-char pwd
  # (minimum 4 and 22 respectively).
  defp random_token(bytes),
    do: :crypto.strong_rand_bytes(bytes) |> Base.encode16(case: :lower)

  # `:no` refuses a DTLS/ICE leg outright; every other value accepts one when the
  # offer asks for it (this leg never *offers*, so there is nothing to force).
  defp webrtc_allowed?(%{webrtc: :no}), do: false
  defp webrtc_allowed?(_state), do: true

  # ── receive plane ────────────────────────────────────────────────────────────

  # Per media: negotiate, StartReceiving (whose return is the port the SDP answer
  # advertises), then the transport properties. Nothing is sent yet.
  defp open_receive_plane(state, conf, descs) do
    descs
    |> Enum.filter(&(answerable?(&1, state.medias) or ws_answerable?(&1, state.medias)))
    |> Enum.reduce_while({:ok, state, %{}}, fn desc, {:ok, st, acc} ->
      cond do
        # the verdict map is keyed by media type: an offer carrying TWO text
        # sections (an RTP one and a WS one, say) gets the first answered and
        # the other declined/omitted, instead of one verdict silently
        # overwriting the other
        Map.has_key?(acc, desc.type) ->
          {:cont, {:ok, st, acc}}

        true ->
          case open_receive(st, conf, desc) do
            {:ok, st, neg} -> {:cont, {:ok, st, Map.put(acc, desc.type, neg)}}
            # no codec in common on this media: declined (port 0), not a call failure
            :skip -> {:cont, {:ok, st, acc}}
            {:error, _} = err -> {:halt, err}
          end
      end
    end)
  end

  # ── the WebSocket text leg (S5) ──────────────────────────────────────────────
  #
  # The conference-API mirror of the JSR-309 adapter's WS path
  # (MediaServerMendoozeConn.open_offered_receive/2): ONE RPC — the media server
  # switches the participant's text plane to a WebSocket bridge at the text-mixer
  # seam and returns the full URL, scheme included (ws:// or wss://, its call:
  # TLS lives on the same port). Nothing else ever runs on this leg: no
  # StartReceiving/StartSending, no SetTextCodec, no crypto, no watchdog — and no
  # RED either, redundancy being a per-RTP-leg affair the mixer handles.
  defp open_receive(state, _conf, %{transport: :ws} = desc) do
    if Map.get(desc, :setup) == :passive do
      # RFC 4145: a peer that declares itself passive will never connect to us,
      # and we (the media server) never connect out. Nobody would ever dial the
      # WebSocket: the section is omitted, the call stands.
      Logger.warning(
        module: __MODULE__,
        message: "conference #{state.conf_uid}: peer offered a=setup:passive on its " <>
          "WS text section; omitting it (nobody would connect)"
      )

      :skip
    else
      token = ws_token()

      case rpc(state, "ConfigureParticipantMediaConnection", [
             state.conf_id,
             state.part_id,
             media_int(desc.type),
             @proto_ws,
             token
           ]) do
        {:ok, [url | _]} ->
          {attribute, value} = url |> to_string() |> Sdp.ws_url_attribute()

          {:ok, state,
           %{
             transport: :ws,
             ws_url: value,
             ws_attribute: attribute,
             # the m= line port is the WS server's (a nonzero port is all the
             # deployed client checks); `remote: nil` keeps media_summary honest
             rec_port: ws_url_port(to_string(url)),
             remote: nil,
             rtp_map: %{},
             send_map: %{},
             codecs: ["T140"],
             dtmf: false
           }}

        {:error, reason} ->
          # the media server cannot host the WebSocket (older binary, no
          # announced address…): the text is lost, not the call — the section
          # is omitted from the answer, audio/video stand (plan §D7)
          Logger.warning(
            module: __MODULE__,
            message: "conference #{state.conf_uid}: ConfigureParticipantMediaConnection " <>
              "failed (#{inspect(reason)}); the WS text section is omitted, the call stands"
          )

          :skip
      end
    end
  end

  defp open_receive(state, conf, desc) do
    # P8a: the offer IS the menu. We propose every payload type it names that our codec
    # table can turn into a Medooze constant, and the media server decides — it is the
    # party that knows what it supports, and the one that will encode.
    case Sdp.propose_all(desc, Map.get(conf, :dtmf, true)) do
      # nothing nameable to propose on this media: declined (port 0), not a call failure
      {:error, :no_common_codec} ->
        :skip

      {:ok, neg} ->
        media = desc.type
        m = media_int(media)

        # §6.3 rule 1: the answer reuses the offer's payload-type numbering, so both
        # rtpMaps are keyed with the OFFERED PTs — no local renumbering.
        rtp_map = neg.rtp_map

        # P8a: the offer's codec-level attributes, the part `rtpMap` cannot carry. A
        # struct with one member rather than a bare fmtp map, so the negotiator can
        # ask for more later without another positional parameter. `fmtp_raw` and not
        # the parsed structs: what goes on the wire must be what the peer wrote.
        offer = %{"fmtp" => Map.get(desc, :fmtp_raw, %{})}

        # Our own codec capability, pushed BEFORE StartReceiving because that is
        # when the negotiator reads it (§16.3.4 (a)): sent after, it would
        # negotiate against an empty map and announce the server's defaults.
        push_local_codec_props(state, m, media)

        with {:ok, state, profile} <- leg_profile(state, desc),
             {:ok, [rec_port | returned]} <-
               rpc(state, "StartReceiving", start_receiving_args(state, m, rtp_map, offer, profile)),
             {:ok, ip} <- announced_ip(state, returned),
             :ok <- set_remote_security(state, m, desc),
             :ok <- set_rtp_properties(state, m, desc) do
          # P8a: `returnVal[2]` is the negotiation verdict — every accepted payload
          # type is a key, empty value included, so presence IS the accept signal.
          # `nil` means a media server that predates the delegation, which selects the
          # legacy client-side construction (§16.3.3, the rolling-upgrade path).
          accepted =
            Sdp.accepted_pts(rtp_map, Enum.at(returned, 1))
            |> keep_answerable(state, desc, rtp_map)

          Logger.info(
            module: __MODULE__,
            message:
              "conf=#{state.conf_id} part=#{state.part_id} #{media}: " <>
                "proposed #{map_size(rtp_map)} pt, " <>
                if(accepted,
                  do: "accepted #{map_size(accepted)} negotiated-by=server",
                  else: "negotiated-by=local (media server predates P8a)"
                )
          )

          if accepted == %{} do
            # Nothing the verdict accepted can be stated in an answer to THIS offer
            # (see `keep_answerable/4`). Decline the media rather than answer a codec
            # the caller cannot match — and close the receive plane we just opened, or
            # the server holds a port for a media the answer says is off.
            void_rpc(state, "StopReceiving", [state.conf_id, state.part_id, m, @role_main])
            :skip
          else
            neg =
              Map.merge(neg, %{
                rec_port: rec_port,
                remote: {desc.ip, desc.port},
                # the offer's own format order, kept for the three places that must
                # agree about the caller's preference: the answer's rtpmap order, the
                # payload type we send on, and the codec the mixer encodes (§6.3 rule 1)
                fmt_order: Sdp.fmt_order(desc, @fmt_order_opts),
                # the server's verdict, or nil on a pre-P8a server
                accepted: accepted,
                # drives the receive watchdog (§16.1): a media we have no business
                # expecting RTP on must not be watched, or a hold hangs up the call.
                # The offered direction is kept alongside, because the NEXT offer reads
                # it to tell a hold from a one-way source.
                direction: Map.get(desc, :direction, :sendrecv),
                expect_rtp: expect_rtp?(state, desc),
                # the conference's own preference, which is the ONE thing that outranks
                # the caller's order below: it moves this codec first in the answer and
                # makes it what the mixer encodes (§6.3 rule 1)
                preferred_codec: preferred_code(state, conf, media, rtp_map, accepted)
              })

            {
              :ok,
              %{state | receiving: [media | state.receiving], media_ip: ip},
              # decided once, here, from the payload type we will actually send on: the
              # answer states that profile and the encoder is configured with it, so the
              # two cannot drift apart
              neg
              |> Map.put(:answered_profile_level_id, answered_profile_level_id(desc, neg))
              |> Map.put(:answered_video_fmtp, answered_video_fmtp(desc, neg))
            }
          end
        end
    end
  end

  # The conference's preferred video codec as a Medooze code, and `nil` as soon as this
  # leg cannot honour it. Dropped preferences are LOGGED, naming which side dropped it:
  # an operator who states a codec and watches it not happen must be able to tell "the
  # caller never offered it" from "the media server refused it" — the absence of that
  # answer is why the codec lists were removed rather than kept as preferences (§8.4).
  defp preferred_code(state, conf, :video, rtp_map, accepted) do
    with name when is_binary(name) <- Map.get(conf, :preferred_video_codec),
         {:ok, code} <- Sdp.codec_code(:video, name) do
      negotiated = if is_map(accepted), do: Map.take(rtp_map, Map.keys(accepted)), else: rtp_map

      cond do
        code in Map.values(negotiated) ->
          code

        code in Map.values(rtp_map) ->
          log_preference_dropped(state, name, "the media server did not accept it")

        true ->
          log_preference_dropped(state, name, "the offer does not carry it")
      end
    else
      _ -> nil
    end
  end

  defp preferred_code(_state, _conf, _media, _rtp_map, _accepted), do: nil

  defp log_preference_dropped(state, name, reason) do
    Logger.info(
      module: __MODULE__,
      message:
        "conf=#{state.conf_id} part=#{state.part_id} video: preferred codec #{name} " <>
          "not applied — #{reason}; the answer keeps the caller's own order"
    )

    nil
  end

  # What WE can decode, in the codecs' own vocabulary — the input side of the
  # negotiation, sent as `codec.*` properties (the media server routes them to
  # the negotiator and the RTP session ignores them).
  #
  # AV1's `level-idx` is the one entry so far, and it is derived rather than
  # configured (decided 2026-08-06): the parameter bounds what the PEER may
  # send us, so it has to describe the mosaic this conference really produces.
  # The server's static default 5 (level 3.1) covers 720p15 and becomes a lie at
  # 720p60 or 1080p — an operator moving `video.size` would otherwise announce a
  # capability the mixer exceeds, which is the H.264 `profile-level-id` incident
  # transposed. Nothing to say for H.264 (its profile comes from the offer) nor
  # for VP8 (no parameter).
  defp push_local_codec_props(state, m, :video) do
    with {width, height} <- Vocabulary.size_dimensions(state.video.size),
         level when is_integer(level) <- Sdp.av1_level_idx(width, height, state.video.fps) do
      void_rpc(state, "SetRTPProperties", [
        state.conf_id,
        state.part_id,
        m,
        %{"codec.av1.level-idx" => Integer.to_string(level)},
        @role_main
      ])
    else
      _ -> :ok
    end
  end

  defp push_local_codec_props(_state, _m, _media), do: :ok

  # ── the one thing kelixip checks in the server's verdict (§6.3 rule 12) ──────
  #
  # An answer may not describe, for a payload type, a codec the offer did not describe
  # for **that** payload type (RFC 3264 §6.1). That is an SDP-answerer duty and stays
  # kelixip's (§6.3.2) — it is not codec arbitration: nothing is chosen here, an entry
  # that cannot legally be stated is simply not stated.
  #
  # It bites on H.264, where a payload type's identity is its `profile-level-id` profile
  # plus its `packetization-mode` (RFC 6184 §8.2.2 — the *level* may legitimately
  # differ, that is what level asymmetry is for). A browser offers the same codec under
  # six or seven payload types precisely to enumerate those pairs, and answering one of
  # them with another pair's parameters describes a codec it never offered: libwebrtc
  # refuses the whole answer (`Failed to set remote video description send parameters`)
  # and the app hangs up right after the ACK.
  #
  # **The media server is what needs fixing** (P8c): it resolves H.264 per *codec* and
  # not per payload type — `RTPParticipant::StartReceiving` collapses the offer's
  # per-PT fmtp into one `h264.fmtp` property, so the last payload type iterated wins
  # and every accepted PT is answered with its parameters. Until then this guard keeps
  # the answer conformant, at the cost of the payload types that were misresolved.
  # The comparison itself (profile identity, the absent-packetization-mode rule) is
  # SDP interpretation and lives in one place, the shared SDP layer — this wrapper
  # only adds the conference context to the log.
  defp keep_answerable(accepted, state, desc, rtp_map) do
    {kept, dropped} = Sdp.conformant_pts(accepted, desc, rtp_map)

    Enum.each(dropped, fn %{pt: pt, offered: offered, answered: answered} ->
      Logger.warning(
        module: __MODULE__,
        message:
          "conf=#{state.conf_id} part=#{state.part_id} video: dropped pt #{pt} from " <>
            "the verdict — the media server answered H.264 #{answered} where the " <>
            "offer declared #{offered} for that payload type. Announcing it " <>
            "would be a codec the caller never offered (RFC 6184 §8.2.2), and a browser " <>
            "refuses the whole answer over it. Both come from the server's negotiation: " <>
            "check what it resolved for THIS payload type in its log"
      )
    end)

    kept
  end

  # The peer's own keys and ICE credentials, pushed **after** `StartReceiving`
  # (§6.2): the session exists by then, which is what these attach to.
  #
  # `setup` is normalised to the peer's *resolved* role — the complement of the one
  # our answer states — rather than forwarded as the literal `actpass`: the server
  # would otherwise have to resolve it the same way we did, and the two could
  # disagree about who initiates the handshake.
  defp set_remote_security(state, m, desc) do
    calls =
      case {desc.crypto, Map.get(state.local_sdes, desc.type)} do
        {{:dtls, setup, hash, fingerprint}, _} ->
          [
            {"SetRemoteCryptoDTLS",
             [@role_main, peer_setup(setup) |> to_string(), hash, fingerprint]}
          ]

        {_, %{suite: suite, peer_key: peer_key}} ->
          # the suite and key of the ONE line `setup_sdes/2` selected — never the first
          # line of the offer, which may name a suite we do not implement. `keyRank` is
          # the MKI rank, 0 for an offer that declares none, and it is the seventh
          # argument the MCU API asks for: `(iiissii)`. Sending six was the one arity
          # the server has no format string for (7 with role+rank, or the legacy 5
          # without either), so it answered a parse fault and the call became a 500.
          [{"SetRemoteCryptoSDES", [suite, peer_key, @role_main, @sdes_key_rank]}]

        _ ->
          []
      end

    # only when we answered with ICE ourselves: pushing the peer's credentials to a
    # session that has none of its own would leave the check pairs half-configured
    ice_calls =
      case {desc.ice, state.local_ice} do
        {%{ufrag: ufrag, pwd: pwd}, %{}} ->
          [{"SetRemoteSTUNCredentials", [ufrag, pwd, @role_main]}]

        _ ->
          []
      end

    Enum.reduce_while(calls ++ ice_calls, :ok, fn {method, args}, :ok ->
      case void_rpc(state, method, [state.conf_id, state.part_id, m | args]) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  # rtcp-mux is mirrored from the offer; the RTCP-feedback hints ride along on an
  # AVPF profile. `secure` is deliberately not sent: it is a no-op once the DTLS or
  # SDES keys are configured (the same audit finding the JSR-309 adapter records).
  #
  # `natLatch` asks the MCU to send back to where the RTP actually arrives from
  # rather than to `desc.ip`/`desc.port`, and it belongs here for the same reason
  # it exists at all: a conference leg only ever ANSWERS, so the destination is
  # always the caller's own idea of its address — a private one for every handset
  # behind a symmetric NAT. The server still ignores the request unless that
  # destination really is private and ICE is not in use, so it is a hint, not an
  # override. Opt-in per leg all the same (`state.nat_latch`), because the
  # topology is the deployment's business and not this adapter's to assume.
  defp set_rtp_properties(state, m, desc) do
    props =
      %{}
      |> put_if(Map.get(desc, :rtcp_mux, false), "rtcp-mux", "1")
      # §6.3.1 rule 4: exactly the switches behind the feedback types the ANSWER
      # advertises. Announcing `ccm fir` while never asking for RTCP FIR — which is
      # what the old `avpf?(desc)` pair did — tells the peer it has a capability
      # nothing implements.
      |> Map.merge(rtcp_fb_props(desc))
      |> Map.merge(transport_cc_props(desc))
      |> put_if(state.nat_latch, "natLatch", "1")
      |> merge_video_props(state, desc)

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

  # The server-side switch for each feedback type we answered, and nothing else.
  # `transport-cc` is dropped here rather than looked up: it is confirmed in the answer
  # but switched on by the extmap property below, whose value is an id and not "1".
  defp rtcp_fb_props(desc) do
    case answered_rtcp_fb(desc) do
      types when is_list(types) ->
        types
        |> Enum.reject(&(&1 == Sdp.transport_cc_fb()))
        |> Map.new(fn type -> {Map.fetch!(@supported_rtcp_fb, type), "1"} end)

      _ ->
        %{}
    end
  end

  # The transport-wide-cc extension, keyed by its URI and valued with the NEGOTIATED
  # id: that is what makes the server write a transport-wide sequence number on every
  # packet it sends this participant, pair the incoming fmt 15 reports with its own
  # send history and feed its sender-side bandwidth estimator.
  defp transport_cc_props(desc) do
    case Sdp.transport_cc_extmap(desc) do
      %{id: id} -> %{Sdp.transport_cc_uri() => Integer.to_string(id)}
      nil -> %{}
    end
  end

  # The H.264 profile is **not** pushed here, and that is a correction rather than
  # an omission (2026-08-01). It used to be, as `h264.profile-level-id`, and it
  # never arrived: `VideoStream::SetRTPProperties` only keeps keys prefixed
  # `codec.`, and the unprefixed one fell through to `RTPSession::SetProperties`,
  # which logged `Unknown RTP property`. Prefixing it is not enough either —
  # `SetVideoCodec` **replaces** the whole property map (`videoProperties =
  # properties`) and runs after us, at ACK time. The profile therefore travels in
  # `SetVideoCodec`'s own props map, which is the argument that reaches the encoder
  # (`set_codec/3`).
  defp merge_video_props(props, _state, _desc), do: props

  # The peer's profile if it stated one, else nothing. Reflection wins because
  # `profile-level-id` has to match for the two ends to decode each other (§6.3
  # rule 2), and a peer that states one has told us what it can handle. There is no
  # configured fallback any more (§8.4, decision 11): what the mixer can encode is the
  # media server's to declare, and on the delegated path it already did.
  defp h264_profile_level_id(%{type: :video} = desc) do
    offered =
      Map.get(desc, :fmtp, %{})
      |> Map.values()
      |> Enum.find_value(fn fmtp ->
        case Map.get(fmtp, :profile_level_id) do
          plid when is_integer(plid) -> hex6(plid)
          _ -> nil
        end
      end)

    offered
  end

  defp h264_profile_level_id(_desc), do: nil

  # What `SetVideoCodec` is told to encode with (§6.3 rule 9). On the delegated path
  # this is a RELAY, not a decision: the server already applied RFC 6184 §8.2.2 and put
  # the result in the fmtp it returned, so announced and encoded are the same string by
  # construction. Parsing it back out is the price of `SetVideoCodec` replacing the
  # stream's whole property map — send nothing and the negotiated profile is lost.
  # It is the profile of the **primary** payload type — the one `StartSending` will
  # stamp the stream with — and not "the first profile found in the verdict": with a
  # browser's several H.264 payload types those two differ, and the difference is a
  # stream whose SPS contradicts the payload type carrying it.
  defp answered_profile_level_id(%{type: :video} = desc, %{accepted: accepted} = neg)
       when is_map(accepted) do
    primary_plid =
      case primary_entry(neg) do
        {pt, _code} -> plid_of(Map.get(accepted, pt))
        nil -> nil
      end

    primary_plid || h264_profile_level_id(desc)
  end

  defp answered_profile_level_id(desc, _neg), do: h264_profile_level_id(desc)

  # Le fmtp que le serveur a rendu pour le payload type PRIMAIRE — celui sur lequel nous
  # émettrons. `encoder_props/1` y lit le mode de paquetisation ; le profil est déjà
  # extrait par `answered_profile_level_id/2`, qui applique la même règle du PT primaire.
  defp answered_video_fmtp(%{type: :video}, %{accepted: accepted} = neg) when is_map(accepted) do
    case primary_entry(neg) do
      {pt, _code} -> Map.get(accepted, pt)
      nil -> nil
    end
  end

  defp answered_video_fmtp(_desc, _neg), do: nil

  defp plid_of(params) when is_binary(params) do
    case Regex.run(~r/profile-level-id=([0-9a-fA-F]{6})/, params) do
      [_, plid] -> String.downcase(plid)
      nil -> nil
    end
  end

  defp plid_of(_params), do: nil

  # The `profile-level-id=` of the configured answer fmtp — the one place that string
  # is read, so the SDP and the RPC cannot disagree.
  # ── send plane + mixer join ──────────────────────────────────────────────────

  # In the leg's media order (audio first), never the negotiation map's: iterating a
  # map would leave the RPC sequence to term order, and this sequence is a documented
  # contract with the media server (§2 point 1) that a test pins down.
  # ── RTP inactivity watchdog (§16.1, P7) ──────────────────────────────────────

  # Whether RTP is owed to us on this media — the only thing a *receive* watchdog can
  # honestly alarm on.
  #
  # Three ways it is not. The peer declares it will not send (`a=recvonly`,
  # `a=inactive`); it blackholes the media (RFC 3264 §8.4, the legacy hold every old
  # handset uses); or it puts us **on hold**.
  #
  # A hold is a transition, not a direction. `a=sendonly` alone does not name one:
  # offered from the start it is a one-way source pushing into the conference, and that
  # is the case the watchdog protects best — a feed that dies is exactly what nothing
  # else would catch. The same `sendonly` arriving on a media we had established
  # `sendrecv` is a hold, and there silence is the expected state: RFC 3264 lets the
  # holder send music, and Linphone 6.2 sends nothing at all. Watching it reaps a
  # perfectly healthy held call after `rtp_timeout_ms` — 10 s, an ordinary consultation
  # transfer — and on an audio-only leg that is the ONLY watched media, so the call
  # dies (`Kelix.Mod.Mcu.SBB.Conference`, P7/S1).
  #
  # A held leg that then really dies is `idle_timeout`'s business (the G3 backstop), and
  # a peer that dies while silent is signalling's — RFC 4028, which we do not offer yet.
  defp expect_rtp?(state, desc) do
    direction = Map.get(desc, :direction, :sendrecv)
    was = get_in(state.negotiated, [desc.type, :direction])

    direction not in [:recvonly, :inactive] and
      not (direction == :sendonly and was == :sendrecv) and
      not Sdp.blackholed?(desc)
  end

  # Applies the watchdog to what the offer just said, per media: armed when RTP is owed
  # to us, **disarmed when it is not** (`expect_rtp?/2`). Without the disarming half, a
  # hold longer than `rtp_timeout_ms` reads as a dead leg and hangs up a working call —
  # ten seconds being an ordinary consultation transfer.
  #
  # Text is never armed at all: T.140 is legitimately silent between keystrokes, so
  # watching it would reap a leg the moment its user stops typing.
  # `rtp_timeout_ms = 0` disables the feature entirely.
  #
  # Best-effort on purpose: a server that predates §16.1 answers "method not found",
  # and a leg that carries media is worth more than a leg that is monitored. The
  # failure is logged rather than swallowed, so a fleet-wide "nothing is ever armed"
  # cannot pass for working.
  defp apply_rtp_timeouts(%{rtp_timeout_ms: ms} = state) when is_integer(ms) and ms > 0 do
    for {media, neg} <- state.negotiated, media != :text do
      timeout = if Map.get(neg, :expect_rtp, true), do: ms, else: 0

      case rpc(state, "StartRTPTimeout", [
             state.conf_id,
             state.part_id,
             media_int(media),
             timeout,
             @role_main
           ]) do
        {:ok, _} ->
          :ok

        {:error, reason} ->
          Logger.warning(
            module: __MODULE__,
            message:
              "conf=#{state.conf_id} part=#{state.part_id}: could not set the #{media} " <>
                "RTP watchdog to #{timeout} ms (#{inspect(reason)}) — a silent leg will " <>
                "only be caught by the script's idle timeout"
          )
      end
    end

    :ok
  end

  defp apply_rtp_timeouts(_state), do: :ok

  defp start_sending_all(state) do
    state.medias
    |> Enum.filter(&Map.has_key?(state.negotiated, &1))
    # a WS text leg has no send plane of ours: the media server owns the
    # WebSocket, and the server refuses StartSending(TEXT) after the switch
    # anyway (S5). SetTextCodec is skipped with it — no payload type exists.
    |> Enum.reject(&(Map.fetch!(state.negotiated, &1) |> Map.get(:transport) == :ws))
    |> Enum.reduce_while({:ok, state}, fn media, {:ok, st} ->
      case start_sending(st, media, Map.fetch!(st.negotiated, media)) do
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

    with :ok <- set_codec(state, media, neg),
         :ok <-
           void_rpc(state, "StartSending", start_sending_args(state, media, ip, port, neg)) do
      {:ok, %{state | sending: [media | state.sending]}}
    end
  end

  # The addressing profile this leg asks the media server for (API §6.7 bis), decided
  # ONCE — on its first `StartReceiving` — and then repeated verbatim: the server
  # fixes the profile per leg, because in symmetric RTP the socket is the same in
  # both directions, and it refuses a second, different one rather than rebind a
  # media under a port it has already published.
  #
  # **The node's configured family decides nothing**: it says what this node listens
  # on as a whole, and on a node bridging two families it would be right for one leg
  # and wrong for the other. A media server carrying both addresses answers a v4
  # caller in `IN IP4` and a v6 caller in `IN IP6` from one conference, which is the
  # whole point of asking. Three parties do decide, each asked only what it alone
  # knows:
  #
  #  * **the offer** says which families the peer can receive media on — the
  #    permission. It names one or two: a browser under ICE names both, its `c=`
  #    holding the default candidate it elected (a private VPN or LAN address as
  #    often as not) and its `a=candidate` lines naming the rest, public IPv6
  #    included. Reading the `c=` alone refused a whole conference on a v6-only node
  #    whose caller was offering v6 one line further down;
  #  * **the local address this call arrived on** (`local_profile`) says which of
  #    our interfaces this peer has a route to — the preference inside that
  #    permission, and the one thing the offer cannot say. It only ever REORDERS
  #    what the offer allows: announcing the family of our listener to a peer that
  #    never offered it would be media sent nowhere;
  #  * **the media server** says which profiles it carries (§6.7) — the
  #    availability.
  #
  # Nothing outside that intersection is served, and an empty one **fails the leg**:
  # a fallback would answer 200 with an address the caller cannot reach, and nothing
  # would say so until the peer noticed the silence (§6.7 bis). Choosing among the
  # families the peer itself published is not that fallback — ICE only ever pairs
  # candidates of one family, and a non-ICE offer names exactly one.
  #
  # Three cases where no profile is asked for at all, each leaving the server on its
  # own default — exactly what a controller that never heard of profiles obtains:
  #
  #  * the server does not carry the notion (`:unsupported`, an older binary);
  #  * the offer does not name an address of either family (a media blackholed from
  #    the start, no candidate to read) — there is no media to place;
  #  * this leg already fixed its profile, which is then reused rather than re-derived.
  defp leg_profile(%{address_profile: profile} = state, _desc) when is_binary(profile),
    do: {:ok, state, profile}

  defp leg_profile(%{network_profiles: profiles} = state, _desc) when not is_map(profiles),
    do: {:ok, state, nil}

  defp leg_profile(state, desc) do
    case Enum.map(Sdp.peer_families(desc), &profile_name(&1, side_of(state))) do
      [] ->
        {:ok, state, nil}

      offered ->
        case Enum.find(
               prefer_local(state, offered),
               &get_in(state.network_profiles, [&1, :available])
             ) do
          nil -> {:error, {:profile_unavailable, Enum.join(offered, ", ")}}
          name -> {:ok, %{state | address_profile: name}, name}
        end
    end
  end

  # The side every candidate of this leg carries: the one its local address sits
  # on. `local_profile` already holds the pair, so read it back rather than
  # deriving the side a second time.
  defp side_of(%{local_profile: local}) when is_binary(local) do
    if String.starts_with?(local, "internal"), do: :internal, else: :public
  end

  defp side_of(_state), do: :public

  defp prefer_local(%{local_profile: local}, offered) do
    if local in offered, do: Enum.uniq([local | offered]), else: offered
  end

  # The side is the LOCAL address's — ours, the one this peer reached — because an
  # offer says which families a peer can receive on and nothing about which side of
  # our network it sits on. The name itself is `MediaServer`'s to spell.
  defp profile_name(family, side), do: MediaServer.profile_name(family, side)

  # `profile` is positional and LAST in both calls (§6.7 bis), and omitted when
  # this leg has none to ask for: the RPC is then byte-for-byte the one a
  # controller that never heard of profiles makes.
  defp start_receiving_args(state, m, rtp_map, offer, nil),
    do: [state.conf_id, state.part_id, m, rtp_map, @role_main, @proto_rtp, offer]

  defp start_receiving_args(state, m, rtp_map, offer, profile),
    do: start_receiving_args(state, m, rtp_map, offer, nil) ++ [profile]

  defp start_sending_args(state, media, ip, port, neg) do
    args = [
      state.conf_id,
      state.part_id,
      media_int(media),
      ip,
      port,
      # P8a: we send on exactly the payload types the ANSWER announced, which on this
      # path is the accepted set — both maps being in the offerer's own numbering
      # (§6.3 rule 1), the restriction is per payload type and not per codec. Sending
      # on a PT the answer left out is a stream the peer discards: it happens as soon
      # as one codec is offered under several payload types and only some of them
      # survive (rule 12). A nil verdict leaves the map alone.
      send_map(media, neg),
      @role_main
    ]

    # The same profile as the receive side, because the socket is the same in both
    # directions: the server takes a second, different one as an error rather than
    # rebinding the media under a port it has already published.
    if state.address_profile, do: args ++ [state.address_profile], else: args
  end

  # What `StartSending` may use, in the offerer's numbering.
  #
  # **Video: exactly one payload type**, the primary. One encoder means one profile, and
  # leaving several H.264 payload types in the map would let the server pick which one
  # it stamps the stream with — a peer offering seven of them (a browser does) would
  # then read our High-profile frames as whatever that payload type declared. Audio and
  # text keep the whole accepted set: the mixer's codec is chosen by `SetAudioCodec` and
  # the extra entries are the telephone-event stream it rides alongside.
  defp send_map(:video, %{accepted: accepted, rtp_map: rtp_map} = neg) when is_map(accepted) do
    case primary_entry(neg) do
      {pt, _code} -> Map.take(rtp_map, [pt])
      nil -> Map.take(rtp_map, Map.keys(accepted))
    end
  end

  defp send_map(_media, %{accepted: accepted, rtp_map: rtp_map}) when is_map(accepted),
    do: Map.take(rtp_map, Map.keys(accepted))

  defp send_map(_media, %{rtp_map: rtp_map}), do: rtp_map

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

  # Video carries the conference's **inline profile** (§5.1): size, frame rate,
  # bitrate and intra period are the conference's, not the offer's — every leg is
  # encoded from the same mixed mosaic, so they cannot be per-participant. The `mode`
  # argument is the video size constant (§3.6).
  #
  # The profile is read at attach time, which is what "an existing participant keeps
  # its negotiated video profile" means (§8.3): a later `conference.update` moves new
  # legs, not this one.
  defp set_codec(state, :video, neg) do
    case primary_code(:video, neg) do
      nil ->
        {:error, :no_common_codec}

      code ->
        video = state.video

        void_rpc(state, "SetVideoCodec", [
          state.conf_id,
          state.part_id,
          code,
          video.size,
          video.fps,
          video.bitrate,
          video.intra_period,
          encoder_props(neg),
          @role_main
        ])
    end
  end

  # T.140. `SetTextCodec` takes the participant and the codec, nothing else: text has
  # no profile to impose (no size, no rate, no bitrate), which is why this clause is
  # the short one. `T140RED` is a codec here, not a modifier — the redundancy is the
  # server's to produce once it is told to use it.
  defp set_codec(state, :text, neg) do
    case primary_code(:text, neg) do
      nil ->
        {:error, :no_common_codec}

      code ->
        void_rpc(state, "SetTextCodec", [state.conf_id, state.part_id, code])
    end
  end

  defp set_codec(_state, media, _neg), do: {:error, {:media_not_supported, media}}

  # What the encoder is configured with, and the only place it can be: this map
  # becomes `VideoStream::videoProperties` wholesale, and `CreateEncoder` reads it at
  # `StartSending`, one RPC later.
  #
  # `h264.profile-level-id` (unprefixed here — the `codec.` prefix belongs to
  # `SetRTPProperties`, which strips it) makes the encoder emit, and write into every
  # SPS, the profile the SDP answer advertised. Without it it runs on its own default
  # `42801F` whatever we announced, and a handset that trusts the answer gets a
  # stream it may not decode — one-way video that looks like a network problem.
  # `h264.packetization-mode` travels by the same channel and for the same reason: it is
  # the only one that reaches the encoder. It decides the slice size the encoder produces
  # — hence whether the stream is mode-0 conformant, which forbids FU-A — and server-side
  # it forces the software encoder, VAAPI being unable to bound a slice.
  #
  # Reading it off the **announced** fmtp is not a shortcut: the server puts the peer's
  # mode there when the peer stated one, and 1 otherwise, so announced and emitted are
  # the same mode by construction — the same invariant the profile relay relies on.
  defp encoder_props(neg) do
    %{}
    |> put_encoder_prop("h264.profile-level-id", Map.get(neg, :answered_profile_level_id))
    |> put_encoder_prop(
      "h264.packetization-mode",
      packetization_mode_of(Map.get(neg, :answered_video_fmtp))
    )
  end

  defp put_encoder_prop(props, _key, nil), do: props
  defp put_encoder_prop(props, key, value), do: Map.put(props, key, value)

  defp packetization_mode_of(params) when is_binary(params) do
    case Regex.run(~r/packetization-mode=(\d+)/, params) do
      [_, mode] -> mode
      nil -> nil
    end
  end

  defp packetization_mode_of(_params), do: nil

  # The Medooze constant of a codec name, read off the shared codec tables (a
  # one-entry rtpMap is the table lookup those tables expose).
  # The one accepted payload type the mixer encodes towards this leg: the conference's
  # preferred codec when this leg carries it, else the caller's own first choice (offer
  # order), among what the server accepted — telephone-event excluded, that being a
  # stream the mixer never encodes towards anyone.
  #
  # It has to be **one payload type and not one codec**, because a peer may offer the
  # same codec under several payload types with different parameters: the profile we
  # configure the encoder with and the payload type we send on must be the same entry,
  # or we encode 42001f and stamp it with a payload type the peer reads as 4d001f.
  defp primary_entry(%{accepted: accepted} = neg) when is_map(accepted) do
    neg.rtp_map
    |> Map.take(Map.keys(accepted))
    |> Enum.reject(fn {_pt, code} -> code == @dtmf_code end)
    |> Enum.sort_by(
      &Sdp.preferred_rank(&1, Map.get(neg, :fmt_order), Map.get(neg, :preferred_codec))
    )
    |> List.first()
  end

  defp primary_entry(_neg), do: nil

  # The codec the mixer encodes towards this leg. It must come from the **accepted**
  # set when the server gave one: telling it to encode a codec it just filtered on
  # receive would produce a leg that negotiated successfully and decodes nothing. The
  # send map is restricted the same way (`start_sending/3`), so the two agree.
  defp primary_code(_media, %{accepted: accepted} = neg) when is_map(accepted) do
    case primary_entry(neg) do
      {_pt, code} -> code
      nil -> nil
    end
  end

  # Legacy (pre-P8a server, no verdict): the codec list `propose_all/2` built, in the
  # offer's order. The preference is applied here TOO and not only in the answer — the
  # SDP order and the encoded codec are one statement, and honouring it on one side only
  # would announce a codec the mixer is not producing.
  defp primary_code(media, neg) do
    codes =
      Enum.map(neg.codecs, fn name ->
        media |> Sdp.local_rtp_map([name], false) |> Map.values() |> List.first()
      end)

    prefer = Map.get(neg, :preferred_codec)

    if is_integer(prefer) and prefer in codes, do: prefer, else: List.first(codes)
  end

  # Audio joins the default **sidebar** (what the MCU API calls a sidebar is what
  # mcuGold's UI calls the audio mixer), video the default mosaic — the only two this
  # increment drives (decision 6b). Both are per-participant calls, hence here rather
  # than in the registry; the *layout* of the mosaic is conference-level and stays
  # with the registry (§4.2).
  #
  # **Text is absent on purpose**: the MCU wires every participant into the text
  # mixer at `CreateParticipant` (`multiconf.cpp`: `textMixer.CreateMixer` +
  # `SetTextInput`/`SetTextOutput` + `InitMixer`), so there is no text equivalent of
  # these two RPCs to call — and none to undo at teardown either.
  defp join_mixer(state) do
    [
      {:audio, "AddSidebarParticipant", @default_sidebar},
      {:video, "AddMosaicParticipant", @default_mosaic}
    ]
    |> Enum.reduce_while({:ok, state}, fn {media, method, group}, {:ok, st} ->
      if media in st.sending do
        case void_rpc(st, method, [st.conf_id, group, st.part_id]) do
          :ok -> {:cont, {:ok, st}}
          err -> {:halt, err}
        end
      else
        {:cont, {:ok, st}}
      end
    end)
  end

  # ── answer building ──────────────────────────────────────────────────────────

  defp answer_or_reject(state, negotiated, desc) do
    case {Map.get(desc, :transport, :rtp), Map.get(negotiated, desc.type)} do
      # only reached when the WS leg WAS configured (omit_from_answer?/3
      # removed it otherwise): answer with the URL, in the gateway's historical
      # form — proto mirrored, literal `t140`, the scheme in the attribute NAME
      # and a protocol-relative value, no rtpmap/fmtp/crypto (signalling only,
      # the client strips the section before setRemoteDescription)
      {:ws, %{transport: :ws} = neg} ->
        %{
          ws_text: neg.ws_url,
          ws_attribute: neg.ws_attribute,
          type: desc.type,
          port: neg.rec_port,
          protocol: desc.protocol,
          setup: :passive,
          direction: Sdp.reverse_direction(desc.direction),
          mid: Map.get(desc, :mid)
        }

      # a second text section when the first (WS) took the verdict: port 0
      {:rtp, %{transport: :ws}} ->
        reject_spec(desc)

      {_, nil} ->
        reject_spec(desc)

      {_, neg} ->
        answer_spec(state, desc, neg)
    end
  end

  # A deliberate RFC 3264 §6 violation, scoped to one section: the text-over-WebSocket
  # m= line is OMITTED from the answer, not declined with port 0. The Elioz/WebRTComm
  # client injects `m=text … TCP/WSS t140` into the wire SDP *after* setLocalDescription
  # and strips the answer's text section before setRemoteDescription — but its strip does
  # not recognize our port-0 echo (the legacy gateway answered that section for real,
  # WebSocketLeg), so the browser got three answer sections against its two-section local
  # offer and libwebrtc rejected the whole answer (kMlineMismatchInAnswer, verified in
  # edge://webrtc-internals, 2026-08-06). Omitting the section is what deployed clients
  # digest. Detection keys on the parsed `transport: :ws`, which covers all four
  # proto spellings (TCP/WS included — the one the deployed Elioz client emits; a
  # local protocol list here had missed it).
  #
  # Three omission cases, one behaviour (S5 plan §D7, decided 2026-08-08):
  #   1. the participant was admitted WITHOUT text (`:text` not in its media
  #      set): every text section goes — RTP T.140 included, never a port-0 echo;
  #   2. a WS text section whose configuration failed (media server that cannot
  #      host it, no announced address…): the text is lost, not the call;
  #   3. a WS text section whose peer declared `a=setup:passive` (nobody would
  #      ever connect) — it never reached the verdict map, same test as 2.
  # Port 0 remains the answer for rejected audio/video sections, and for a text
  # section we DO serve but could not negotiate (text admitted, no common codec).
  defp omit_from_answer?(state, negotiated, desc) do
    cond do
      desc.type == :text and :text not in state.medias ->
        true

      ws_text_section?(desc) ->
        not match?(%{transport: :ws}, Map.get(negotiated, desc.type))

      true ->
        false
    end
  end

  defp ws_text_section?(desc), do: Map.get(desc, :transport, :rtp) == :ws

  # A declined section keeps its place in the answer with port 0 and the offered
  # format list echoed verbatim (RFC 3264 §6): the m= line count must match. Its
  # `a=mid` is echoed for the same reason an accepted section's is (§6.3 rule 11) —
  # a browser's data-channel section is declined here, and it must still be named.
  defp reject_spec(desc) do
    %{
      type: desc.type,
      protocol: Map.get(desc, :protocol, "RTP/AVP"),
      reject_fmt: Map.get(desc, :raw_fmt, []),
      mid: Map.get(desc, :mid)
    }
  end

  defp answer_spec(state, desc, neg) do
    {rtpmaps, fmtp} = answer_codecs(desc, neg)

    %{
      type: desc.type,
      port: neg.rec_port,
      # the offerer's payload-type numbering (§6.3 rule 1)
      rtpmaps: rtpmaps,
      fmtp: fmtp,
      # rule 8: b=AS: on video is min(offered, the conference's profile)
      bandwidth: answer_bandwidth(state, desc),
      # sendrecv for a mixed participant; a one-way offer is mirrored (rule 7)
      direction: Sdp.reverse_direction(desc.direction),
      # mirror the transport of the offer (rule 4), unless we accept an RFC 5939
      # potential configuration that upgrades it
      protocol: answered_protocol(desc),
      acfg: accepted_capneg(desc),
      rtcp_mux: Map.get(desc, :rtcp_mux, false),
      # the feedback types actually agreed, per video PT (§6.3.1 rule 3)
      rtcp_fb: answered_rtcp_fb(desc),
      # RFC 8285 §5: the extension is confirmed with the offer's OWN id, never
      # renumbered. Empty unless transport-wide-cc is negotiated on this media.
      extmaps: List.wrap(Sdp.transport_cc_extmap(desc)),
      crypto: answer_crypto(state, desc),
      crypto_tag: answer_crypto_tag(state, desc),
      ice: state.local_ice,
      # §6.3 rule 11: the offer's `a=mid`, echoed verbatim. It is how a browser (and
      # anything else speaking JSEP, RFC 8829 §5.3.1) pairs our answer sections with
      # the transceivers it offered — never rebuilt from the media name, which would
      # name a section the peer does not have.
      mid: Map.get(desc, :mid),
      # §6.3 rule 3: host candidates on the receive port, from configuration (G2).
      # Component 2 (RTCP) only when the offer did not ask for rtcp-mux, as mcuGold.
      candidates: answer_candidates(state, desc, neg)
    }
  end

  # DELEGATED (P8a): the accepted payload types and their fmtp are the media server's,
  # copied out verbatim. This is the whole point of §16.3 — the party that will encode
  # is the one that says what it accepts and with which parameters, so kelixip stops
  # guessing H.264 profiles, DTMF ranges and RFC 4103 redundancy lists.
  #
  # `answer_rtpmaps/2` is reused with the rtp_map restricted to the accepted set, so
  # the ordering and the telephone-event special case stay exactly what they were.
  # An empty fmtp value means "accepted, no a=fmtp line" — the contract's other half,
  # and the reason the value is dropped rather than emitted as `a=fmtp:<pt> `.
  defp answer_codecs(desc, %{accepted: accepted} = neg) when is_map(accepted) do
    accepted_map = Map.take(neg.rtp_map, Map.keys(accepted))

    rtpmaps =
      Sdp.answer_rtpmaps(
        desc.type,
        # `dtmf_pts` is the offer's clock→PT map, and it has to travel with the
        # accepted set: the server picks which telephone-event PT it keeps, and the
        # answer must re-announce that PT with the clock the OFFER gave it. Chrome
        # offers one per clock (110@48000, 126@8000), so announcing the selected
        # audio codec's clock for whichever PT came back is a rate the peer never
        # proposed — silent DTMF, and a payload type libwebrtc discards.
        %{neg | rtp_map: accepted_map}
        |> Map.put(:dtmf_pts, Map.get(desc, :dtmf_pts, %{}))
        # the caller's own preference order (§6.3 rule 1): in an answer the order IS a
        # preference statement, and a mixer has none of its own to make
        |> Map.put(:fmt_order, Sdp.fmt_order(desc, @fmt_order_opts))
      )

    fmtp = for {pt, params} <- accepted, params != "", into: %{}, do: {pt, params}
    {rtpmaps, fmtp}
  end

  # LEGACY: a media server that predates the delegation returned no verdict, so the
  # answer is built the way it was before P8a. Kept intact rather than approximated —
  # it is the path every node takes for the duration of a rolling upgrade.
  defp answer_codecs(desc, neg) do
    rtpmaps =
      Sdp.answer_rtpmaps(
        desc.type,
        neg
        |> Map.put(:dtmf_pts, Map.get(desc, :dtmf_pts, %{}))
        |> Map.put(:fmt_order, Sdp.fmt_order(desc, @fmt_order_opts))
      )

    fmtp =
      dtmf_fmtp(neg)
      |> Map.merge(codec_fmtp(desc, rtpmaps))
      |> Map.merge(red_fmtp(desc.type, rtpmaps))

    {rtpmaps, fmtp}
  end

  # ── RTCP feedback and RFC 5939 (§6.3.1 rules 3-5) ────────────────────────────

  # We only take the AVPF upgrade on VIDEO. The caller may offer it on every media —
  # the capture that prompted this work does — but there is no audio or text feedback
  # to switch on, so accepting it there would announce a profile we do nothing with.
  # Acceptance is per media in RFC 5939, so this is legal as well as honest.
  defp accepted_capneg(%{type: :video} = desc) do
    case Map.get(desc, :capneg) do
      %{protocol: protocol} = capneg ->
        # only worth taking if it is a feedback profile AND the offer asks for feedback
        # we can honour; upgrading the profile to then answer nothing would be pointless
        if String.ends_with?(protocol, "F") and requested_rtcp_fb(desc) != [],
          do: capneg,
          else: nil

      _ ->
        nil
    end
  end

  defp accepted_capneg(_desc), do: nil

  defp answered_protocol(desc) do
    case accepted_capneg(desc) do
      %{protocol: protocol} -> protocol
      nil -> desc.protocol
    end
  end

  # The feedback the offer asks for on this media, wildcard included: `a=rtcp-fb:*`
  # (parsed as payload type -1) applies to every format of the section.
  defp requested_rtcp_fb(desc) do
    Enum.filter(offered_rtcp_fb(desc), &Map.has_key?(@supported_rtcp_fb, &1))
  end

  # The same list before that filter. `transport-cc` has no entry in
  # @supported_rtcp_fb — its server-side switch comes from the extmap, not from this
  # attribute — so confirming it needs the unfiltered reading.
  defp offered_rtcp_fb(desc) do
    Map.get(desc, :rtcp_fb, %{})
    |> Map.values()
    |> List.flatten()
    |> Enum.uniq()
  end

  # What the answer advertises: the INTERSECTION of what the offer asked for with what
  # we can do — deliberately NOT gated on a feedback profile. RFC 4585 §4 defines
  # `a=rtcp-fb` for AVPF, but real endpoints keep a plain RTP/AVP or RTP/SAVP profile
  # while listing `a=rtcp-fb` lines — Linphone 6.2.0 is the motivating one: its SRTP
  # offer (the mcu_secure_test fixture) says RTP/SAVP yet asks for `ccm tmmbr` and
  # `ccm fir` — and they drive their NACK/FIR/TMMBR off the answer's attributes, not
  # its profile string; refusing to confirm them cost those calls their loss
  # recovery. This is an assumed deviation from the RFC (same policy as
  # the H.264 packetization-mode default of §6.3). The profile we ANSWER is
  # untouched — RFC 3264 mirroring and the RFC 5939 capneg upgrade
  # (accepted_capneg/1) decide it as before; only the attribute emission is
  # decoupled from it, and the server-side switches (rtcp_fb_props/1) follow the
  # same set. A caller that asks for nothing gets nothing back.
  defp answered_rtcp_fb(desc) do
    if desc.type == :video,
      do: requested_rtcp_fb(desc) ++ answered_transport_cc_fb(desc),
      else: false
  end

  # `transport-cc` is confirmed only when BOTH halves of the mechanism are there: the
  # caller asked for the feedback message, and the extension it reports on is one we
  # negotiate (`Sdp.transport_cc_extmap/1` — video, `[mediaserver] transport_cc` on, a
  # usable direction). Appended rather than filtered in, because @supported_rtcp_fb
  # maps an attribute to the server switch that implements it and this one has none.
  defp answered_transport_cc_fb(desc) do
    if Sdp.transport_cc_extmap(desc) && Sdp.transport_cc_fb() in offered_rtcp_fb(desc),
      do: [Sdp.transport_cc_fb()],
      else: []
  end

  # Our side of the security handshake, as the answer states it: the server's
  # fingerprint with the role we take, or the SDES key we generated for this media.
  defp answer_crypto(%{local_dtls: {hash, fingerprint}}, desc),
    do: {:dtls, our_setup(desc.crypto), hash, fingerprint}

  defp answer_crypto(state, desc) do
    case Map.get(state.local_sdes, desc.type) do
      %{suite: suite, key: key} -> {:sdes, suite, key}
      nil -> :none
    end
  end

  # RFC 4568 §6.2: the answer carries the TAG of the offered line we accepted. Linphone
  # offers four lines and we take the second — answering `a=crypto:1` there names a line
  # the offerer keyed differently.
  defp answer_crypto_tag(state, desc) do
    case Map.get(state.local_sdes, desc.type) do
      %{tag: tag} -> tag
      nil -> 1
    end
  end

  defp answer_candidates(%{local_ice: nil}, _desc, _neg), do: []

  defp answer_candidates(state, desc, neg),
    do: Sdp.host_candidates(media_ip(state), neg.rec_port, Map.get(desc, :rtcp_mux, false))

  # §6.3 rule 6, settled against the JSR-309 adapter's browser interop on this same
  # daemon (2026-07-30): the MCU answers as the DTLS **server** — the role a browser
  # or gateway expects from the answerer — so `actpass` becomes `passive` rather than
  # RFC 5763 §5's `active` recommendation. An offer that already committed to a role
  # is mirrored, which is not a choice.
  defp our_setup({:dtls, :active, _hash, _fp}), do: :passive
  defp our_setup({:dtls, :passive, _hash, _fp}), do: :active
  defp our_setup(_crypto), do: :passive

  # The peer's **resolved** role, which is what the server is told (see
  # `set_remote_security/3`): its own choice when the offer made one, and the
  # complement of ours when it left the choice open. Never the literal `actpass` —
  # the server would then have to resolve it exactly as we did, and a disagreement
  # about who initiates the handshake produces a DTLS stall neither side reports.
  defp peer_setup(:actpass), do: :active
  defp peer_setup(role), do: role

  # Only video carries a bandwidth line here: an audio b=AS: would cap the mixer for
  # no benefit, and the conference profile has no audio bitrate to cap it with.
  defp answer_bandwidth(state, %{type: :video} = desc),
    do: Sdp.negotiate_bandwidth(desc.bandwidth, state.video.bitrate)

  defp answer_bandwidth(_state, _desc), do: nil

  # H.264 interop on the no-verdict path: `profile-level-id` must match for the two ends
  # to decode each other, so the offered value is reflected (with `packetization-mode`
  # when the offer states one). Deliberately NOT reflected: `sprop-parameter-sets`,
  # which describes the offerer's own encoder — sending it back would advertise their
  # SPS/PPS as ours.
  #
  # An offer that states **nothing** is answered with nothing: there is no configured
  # profile to fall back on since §8.4 (decision 11) — what the mixer can encode is the
  # media server's to declare, and a server that declares it is a server that returns a
  # verdict, which is the other branch of `answer_codecs/3`. Reflection is therefore all
  # this path does, uniformly across medias and payload types.
  defp codec_fmtp(desc, rtpmaps) do
    offered = Map.get(desc, :fmtp, %{})

    Enum.reduce(rtpmaps, %{}, fn %{pt: pt}, acc ->
      case reflected_params(Map.get(offered, Integer.to_string(pt))) do
        "" -> acc
        params -> Map.put(acc, Integer.to_string(pt), params)
      end
    end)
  end

  defp reflected_params(%{profile_level_id: plid} = fmtp) when is_integer(plid) do
    ["profile-level-id=" <> hex6(plid)]
    |> then(fn acc ->
      case Map.get(fmtp, :packetization_mode) do
        mode when is_integer(mode) -> acc ++ ["packetization-mode=#{mode}"]
        _ -> acc
      end
    end)
    |> Enum.join(";")
  end

  defp reflected_params(_fmtp), do: ""

  # profile-level-id is three hex bytes, lower-case, zero-padded (RFC 6184 §8.1)
  defp hex6(value),
    do: value |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(6, "0")

  # RFC 4733: the telephone-event PT carries the tone range it accepts.
  defp dtmf_fmtp(%{dtmf: true, dtmf_pt: pt}) when is_integer(pt),
    do: %{Integer.to_string(pt) => "0-16"}

  defp dtmf_fmtp(_neg), do: %{}

  # RFC 4103 §5: `red` carries an fmtp listing its generations, each naming the
  # T.140 payload type — primary plus two redundant, as the framework's own offer
  # builder emits. Two rules follow from the answer being in the **offerer's**
  # numbering (§6.3 rule 1): the payload types quoted are the caller's, and the
  # fmtp is emitted only when T.140 itself is answered alongside — `red` naming a
  # payload type absent from the answer is not something a peer can decode.
  defp red_fmtp(:text, rtpmaps) do
    with %{pt: red_pt} <- Enum.find(rtpmaps, &(&1.encoding == "red")),
         %{pt: t140_pt} <- Enum.find(rtpmaps, &(&1.encoding == "t140")) do
      %{Integer.to_string(red_pt) => "#{t140_pt}/#{t140_pt}/#{t140_pt}"}
    else
      _ -> %{}
    end
  end

  defp red_fmtp(_media, _rtpmaps), do: %{}

  # The address the answer advertises, set by `open_receive/3` from the media
  # server's own `StartReceiving` return (§16.5, G2 closed). Never nil here: the
  # answer is only built once at least one media was opened, and `ensure_audio/1`
  # refuses the call otherwise.
  defp media_ip(%{media_ip: ip}), do: ip

  # `StartReceiving` returns `[recPort, ip]`. The address is the media server's
  # own (`--public-ip`, else auto-detected), which is the only party that knows
  # it: it is not derivable from the control channel, and behind a NAT it differs
  # from the address we reach the server at. A server that returns the port alone
  # predates that work, and there is deliberately no fallback — guessing produces
  # an answer whose media silently goes nowhere.
  defp announced_ip(_state, [ip | _]) when is_binary(ip) and ip != "", do: {:ok, ip}

  defp announced_ip(state, _returned) do
    Logger.error(
      module: __MODULE__,
      message:
        "conference #{state.conf_uid}: mcu #{state.mcu} returned no media IP from " <>
          "StartReceiving — upgrade the media server (it must announce its SDP " <>
          "address, see docs/design/mcu_server_evolutions.md)"
    )

    {:error, :no_media_ip}
  end

  # ── guards ───────────────────────────────────────────────────────────────────

  defp parse_offer(sdp) do
    case Sdp.parse(sdp) do
      {:ok, descs} -> {:ok, descs}
      # an unparsable offer is a 400 on the SIP side (§6.5)
      {:error, reason} -> {:error, {:bad_offer, reason}}
    end
  end

  # No audio ⇒ no conference leg. Video-only would need P3 anyway.
  # §6.3 rule 2: a media with nothing accepted is declined with port 0; only a leg
  # where EVERY offered media came back empty is a 488, there being nothing to
  # establish at all.
  #
  # This lifts the audio-mandatory guard `ensure_audio/1` deliberately: with the server
  # arbitrating, "no audio" is no longer evidence of a misconfiguration worth refusing
  # a call over, and a video-only leg — a display wall, a recording viewer — is a
  # legitimate participant. It joins the mosaic and not the audio mixer.
  defp ensure_any_media(negotiated) do
    if negotiated == %{}, do: {:error, :no_common_codec}, else: :ok
  end

  # The RTP gate. `transport: :ws` sections take their own path (S5): they are
  # negotiated by `ws_answerable?/2` + the WS clause of `open_receive/3`, not
  # by the codec machinery below.
  defp answerable?(desc, medias) do
    Map.get(desc, :transport, :rtp) == :rtp and
      Map.get(desc, :supported?, false) and desc.type in medias
  end

  # A text-over-WebSocket section we can serve: text admitted, and the media
  # server will say for itself whether it can host the WebSocket (a failure
  # omits the section, never the call).
  defp ws_answerable?(desc, medias) do
    Map.get(desc, :transport, :rtp) == :ws and
      Map.get(desc, :supported?, false) and desc.type in medias
  end

  # One token per (re)configuration, UUID-shaped, hex from a CSPRNG — same
  # scheme as the JSR-309 adapter. It travels in the SDP and gates the
  # WebSocket, so it must not be guessable.
  defp ws_token do
    <<a::binary-size(4), b::binary-size(2), c::binary-size(2), d::binary-size(2),
      e::binary-size(6)>> = :crypto.strong_rand_bytes(16)

    [a, b, c, d, e]
    |> Enum.map(&Base.encode16(&1, case: :lower))
    |> Enum.join("-")
  end

  # The port of the WS server, for the answer's m= line — a nonzero port is all
  # the deployed client checks (its liveness lock). The URL always carries one
  # in practice; the scheme default is the belt.
  defp ws_url_port(url) do
    case URI.parse(url) do
      %URI{port: port} when is_integer(port) and port > 0 -> port
      %URI{scheme: "wss"} -> 443
      _ -> 80
    end
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
         codec: summary_codec(media, neg),
         rec_port: neg.rec_port,
         send: neg.remote,
         dtmf: Map.get(neg, :dtmf, false)
       }}
    end)
  end

  # What the mixer ENCODES towards this leg, and not the first codec we proposed: the
  # two part company as soon as the server's verdict or the conference's preference
  # moved the choice, and this map is what `participant.show` reports.
  defp summary_codec(media, neg) do
    case primary_code(media, neg) do
      nil -> List.first(neg.codecs)
      code -> Sdp.codec_name(media, code) || List.first(neg.codecs)
    end
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
