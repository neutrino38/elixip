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
  # telephone-event's Medooze codec constant (§3.6): a payload type the mixer never
  # encodes towards anyone, so it can never be a primary codec.
  @dtmf_code 100
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
  # `nack pli` is deliberately absent: it has no distinct switch, and a keyframe request
  # already has a path through `ccm fir` (the FPU flow of §6.4). `goog-remb` likewise —
  # `tmmbr` is the `ccm` one, and announcing congestion feedback the mixer never sends
  # invites the peer to wait for it.
  @supported_rtcp_fb %{"nack" => "useNACK", "ccm fir" => "useRtcpFIR", "ccm tmmbr" => "tmmbr"}

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
          # answer is declined with port 0 rather than omitted — except the
          # WebSocket text section, which is omitted (see ws_text_section?/1).
          medias:
            descs
            |> Enum.reject(&ws_text_section?/1)
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

        with {:ok, [rec_port | returned]} <-
               rpc(state, "StartReceiving", [
                 state.conf_id,
                 state.part_id,
                 m,
                 rtp_map,
                 @role_main,
                 @proto_rtp,
                 offer
               ]),
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
                fmt_order: Map.get(desc, :raw_fmt, []),
                # the server's verdict, or nil on a pre-P8a server
                accepted: accepted,
                # drives the receive watchdog (§16.1): a media the peer says it will not
                # send must not be watched, or a hold hangs up the call
                peer_sends: peer_sends?(desc)
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
  defp rtcp_fb_props(desc) do
    case answered_rtcp_fb(desc) do
      types when is_list(types) ->
        Map.new(types, fn type -> {Map.fetch!(@supported_rtcp_fb, type), "1"} end)

      _ ->
        %{}
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

  # Whether the PEER will send RTP to us on this media — the only thing a *receive*
  # watchdog can observe, and a narrower question than "is this call on hold".
  #
  # A caller holding with `a=sendonly` keeps sending (music on hold), so its RTP never
  # stops and the watchdog must stay armed. What actually starves our reception is the
  # peer declaring it will not send — `a=recvonly`, `a=inactive` — or blackholing the
  # media with `c=0.0.0.0` (RFC 3264 §8.4, the legacy hold every old handset uses).
  defp peer_sends?(desc) do
    Map.get(desc, :direction, :sendrecv) not in [:recvonly, :inactive] and
      Map.get(desc, :ip) != "0.0.0.0"
  end

  # Applies the watchdog to what the offer just said, per media: armed when the peer
  # will send, **disarmed when it will not**. Without the disarming half, a hold
  # longer than `rtp_timeout_ms` reads as a dead leg and hangs up a working call —
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
      timeout = if Map.get(neg, :peer_sends, true), do: ms, else: 0

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
    m = media_int(media)

    with :ok <- set_codec(state, media, neg),
         :ok <-
           void_rpc(state, "StartSending", [
             state.conf_id,
             state.part_id,
             m,
             ip,
             port,
             # P8a: we send on exactly the payload types the ANSWER announced, which on
             # this path is the accepted set — both maps being in the offerer's own
             # numbering (§6.3 rule 1), the restriction is per payload type and not per
             # codec. Sending on a PT the answer left out is a stream the peer discards:
             # it happens as soon as one codec is offered under several payload types and
             # only some of them survive (rule 12). A nil verdict leaves the map alone.
             send_map(media, neg),
             @role_main
           ]) do
      {:ok, %{state | sending: [media | state.sending]}}
    end
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
  # The one accepted payload type the mixer encodes towards this leg: the caller's own
  # first choice (offer order) among what the server accepted, telephone-event excluded
  # — that is a stream the mixer never encodes towards anyone.
  #
  # It has to be **one payload type and not one codec**, because a peer may offer the
  # same codec under several payload types with different parameters: the profile we
  # configure the encoder with and the payload type we send on must be the same entry,
  # or we encode 42001f and stamp it with a payload type the peer reads as 4d001f.
  defp primary_entry(%{accepted: accepted} = neg) when is_map(accepted) do
    neg.rtp_map
    |> Map.take(Map.keys(accepted))
    |> Enum.reject(fn {_pt, code} -> code == @dtmf_code end)
    |> Enum.sort_by(&Sdp.pt_rank(&1, Map.get(neg, :fmt_order)))
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

  defp primary_code(media, neg) do
    case neg.codecs do
      [name | _] -> media |> Sdp.local_rtp_map([name], false) |> Map.values() |> List.first()
      [] -> nil
    end
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
    case Map.get(negotiated, desc.type) do
      nil -> reject_spec(desc)
      neg -> answer_spec(state, desc, neg)
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
  # digest. Only these WS transports are concerned — a text section offered over RTP is
  # real T.140 and keeps the standard echo (and, one day, a real answer: chantier TC).
  @ws_text_protocols ~w(TCP/WSS TLS/WSS TLS/WS)
  defp ws_text_section?(desc),
    do: desc.type == :text and Map.get(desc, :protocol) in @ws_text_protocols

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
        |> Map.put(:fmt_order, Map.get(desc, :raw_fmt, []))
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
        |> Map.put(:fmt_order, Map.get(desc, :raw_fmt, []))
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
    fb = Map.get(desc, :rtcp_fb, %{})

    fb
    |> Map.values()
    |> List.flatten()
    |> Enum.uniq()
    |> Enum.filter(&Map.has_key?(@supported_rtcp_fb, &1))
  end

  # What the answer advertises: the INTERSECTION of what the offer asked for with what
  # we can do, and only under a feedback profile — `a=rtcp-fb` is defined for AVPF
  # (RFC 4585 §4), so emitting it under plain AVP is not merely useless but wrong.
  # A caller that asks for nothing gets nothing back.
  defp answered_rtcp_fb(desc) do
    if desc.type == :video and String.ends_with?(answered_protocol(desc), "F"),
      do: requested_rtcp_fb(desc),
      else: false
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
          "address, see docs/design/mcu_module.md §16.5)"
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
