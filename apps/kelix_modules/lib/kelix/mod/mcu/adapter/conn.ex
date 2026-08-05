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

  # Total conversation: audio, video and text. Anything else offered (an
  # `application` section for BFCP, say) is declined with port 0.
  @supported_medias [:audio, :video, :text]

  # The hash the DTLS fingerprint is fetched and advertised under (§6.3 rule 6).
  @dtls_hash "SHA-256"

  # SDES suites, in our preference order. The first is what an offer we do not
  # recognise gets answered with; anything the offer states and we know is mirrored.
  @sdes_suites ["AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32"]

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
         medias: requested_medias(opts),
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
         :ok <- ensure_audio(negotiated) do
      answer =
        Sdp.build(%{
          ip: media_ip(state),
          # §6.3 rule 5: we advertise a=ice-lite and never gather reflexive
          # candidates. Session level, hence here rather than per media.
          ice_lite: state.local_ice != nil,
          # RFC 3264 §6: one answer m= per offered m=, in order. What we cannot
          # answer is declined with port 0 rather than omitted.
          medias: Enum.map(descs, &answer_or_reject(state, negotiated, &1))
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

  # SDES keys are per media (each stream gets its own), and ours is the one the
  # answer advertises — the peer decrypts what the mixer sends with it.
  defp setup_sdes(state, descs) do
    descs
    |> Enum.filter(&match?({:sdes, _, _}, &1.crypto))
    |> Enum.reduce_while({:ok, state}, fn desc, {:ok, st} ->
      {:sdes, offered_suite, _key} = desc.crypto
      suite = answer_suite(offered_suite)
      key = random_sdes_key()

      case void_rpc(st, "SetLocalCryptoSDES", [
             st.conf_id,
             st.part_id,
             media_int(desc.type),
             suite,
             key,
             @role_main
           ]) do
        :ok -> {:cont, {:ok, %{st | local_sdes: Map.put(st.local_sdes, desc.type, {suite, key})}}}
        err -> {:halt, err}
      end
    end)
  end

  # Mirror the offered suite when we support it: the answerer picks *one* of the
  # offered crypto lines (RFC 4568 §6.2), it does not propose its own.
  defp answer_suite(offered) do
    if offered in @sdes_suites, do: offered, else: hd(@sdes_suites)
  end

  # AES_CM_128 keying material is a 16-byte key plus a 14-byte salt, carried
  # base64 in the a=crypto line (RFC 4568 §6.1).
  defp random_sdes_key(), do: :crypto.strong_rand_bytes(30) |> Base.encode64()

  defp random_token(bytes),
    do: :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)

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

        # P8a: the offer's codec-level attributes, the part `rtpMap` cannot carry. A
        # struct with one member rather than a bare fmtp map, so the negotiator can
        # ask for more later without another positional parameter. `fmtp_raw` and not
        # the parsed structs: what goes on the wire must be what the peer wrote.
        offer = %{"fmtp" => Map.get(desc, :fmtp_raw, %{})}

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
          accepted = Sdp.accepted_pts(rtp_map, Enum.at(returned, 1))

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

          {:ok, %{state | receiving: [media | state.receiving], media_ip: ip},
           Map.merge(neg, %{
             rec_port: rec_port,
             remote: {desc.ip, desc.port},
             # decided once, here: the answer states it and the encoder is
             # configured with it, so the two cannot drift apart
             answered_profile_level_id: h264_profile_level_id(state, desc),
             # the server's verdict, or nil on a pre-P8a server
             accepted: accepted,
             # drives the receive watchdog (§16.1): a media the peer says it will not
             # send must not be watched, or a hold hangs up the call
             peer_sends: peer_sends?(desc)
           })}
        end
    end
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
      case desc.crypto do
        {:dtls, setup, hash, fingerprint} ->
          [
            {"SetRemoteCryptoDTLS",
             [@role_main, peer_setup(setup) |> to_string(), hash, fingerprint]}
          ]

        {:sdes, suite, key} ->
          [{"SetRemoteCryptoSDES", [suite, key, @role_main]}]

        :none ->
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
      |> put_if(avpf?(desc), "useNACK", "1")
      |> put_if(avpf?(desc), "tmmbr", "1")
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

  # The peer's profile if it stated one, else ours. Reflection wins because
  # `profile-level-id` has to match for the two ends to decode each other (§6.3
  # rule 2), and a peer that states one has told us what it can handle.
  defp h264_profile_level_id(state, %{type: :video} = desc) do
    offered =
      Map.get(desc, :fmtp, %{})
      |> Map.values()
      |> Enum.find_value(fn fmtp ->
        case Map.get(fmtp, :profile_level_id) do
          plid when is_integer(plid) -> hex6(plid)
          _ -> nil
        end
      end)

    offered || configured_profile_level_id(state)
  end

  defp h264_profile_level_id(_state, _desc), do: nil

  # The `profile-level-id=` of the configured answer fmtp — the one place that string
  # is read, so the SDP and the RPC cannot disagree.
  defp configured_profile_level_id(state) do
    case Regex.run(~r/profile-level-id=([0-9a-fA-F]{6})/, configured_video_fmtp(state)) do
      [_, plid] -> String.downcase(plid)
      nil -> nil
    end
  end

  defp configured_video_fmtp(state), do: Map.get(state.video, :fmtp) || ""

  defp avpf?(%{protocol: protocol}), do: String.ends_with?(protocol, "F")

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
             # P8a: never send a codec the server filtered on receive. Symmetric-codec
             # assumption, which is what a mixer does anyway; a nil verdict leaves the
             # map untouched.
             Sdp.restrict_send_map(neg.rtp_map, neg.rtp_map, Map.get(neg, :accepted)),
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
  defp encoder_props(neg) do
    case Map.get(neg, :answered_profile_level_id) do
      plid when is_binary(plid) -> %{"h264.profile-level-id" => plid}
      _ -> %{}
    end
  end

  # The Medooze constant of a codec name, read off the shared codec tables (a
  # one-entry rtpMap is the table lookup those tables expose).
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

  # A declined section keeps its place in the answer with port 0 and the offered
  # format list echoed verbatim (RFC 3264 §6): the m= line count must match.
  defp reject_spec(desc) do
    %{
      type: desc.type,
      protocol: Map.get(desc, :protocol, "RTP/AVP"),
      reject_fmt: Map.get(desc, :raw_fmt, [])
    }
  end

  defp answer_spec(state, desc, neg) do
    {rtpmaps, fmtp} = answer_codecs(state, desc, neg)

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
      # mirror the transport of the offer (rule 4)
      protocol: desc.protocol,
      rtcp_mux: Map.get(desc, :rtcp_mux, false),
      # an AVPF offer gets the feedback types advertised back per video PT, which is
      # what makes the peer's PLI/FIR requests legitimate
      rtcp_fb: desc.type == :video and avpf?(desc),
      crypto: answer_crypto(state, desc),
      ice: state.local_ice,
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
  defp answer_codecs(_state, desc, %{accepted: accepted} = neg) when is_map(accepted) do
    accepted_map = Map.take(neg.rtp_map, Map.keys(accepted))
    rtpmaps = Sdp.answer_rtpmaps(desc.type, %{neg | rtp_map: accepted_map})
    fmtp = for {pt, params} <- accepted, params != "", into: %{}, do: {pt, params}
    {rtpmaps, fmtp}
  end

  # LEGACY: a media server that predates the delegation returned no verdict, so the
  # answer is built the way it was before P8a. Kept intact rather than approximated —
  # it is the path every node takes for the duration of a rolling upgrade.
  defp answer_codecs(state, desc, neg) do
    rtpmaps = Sdp.answer_rtpmaps(desc.type, neg)

    fmtp =
      dtmf_fmtp(neg)
      |> Map.merge(codec_fmtp(state, desc, rtpmaps))
      |> Map.merge(red_fmtp(desc.type, rtpmaps))

    {rtpmaps, fmtp}
  end

  # Our side of the security handshake, as the answer states it: the server's
  # fingerprint with the role we take, or the SDES key we generated for this media.
  defp answer_crypto(%{local_dtls: {hash, fingerprint}}, desc),
    do: {:dtls, our_setup(desc.crypto), hash, fingerprint}

  defp answer_crypto(state, desc) do
    case Map.get(state.local_sdes, desc.type) do
      {suite, key} -> {:sdes, suite, key}
      nil -> :none
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

  # H.264 interop: `profile-level-id` must match for the two ends to decode each
  # other, so the offered value is reflected (with `packetization-mode` when the offer
  # states one). Deliberately NOT reflected: `sprop-parameter-sets`, which describes
  # the offerer's own encoder — sending it back would advertise their SPS/PPS as ours.
  #
  # When the offer states **nothing** — a gateway or a phone that lists `H264/90000`
  # and no `a=fmtp` — the answer states the conference's own profile rather than
  # staying silent: silence means RFC 6184's default (Baseline level 1.0) to the peer,
  # while the mixer is encoding HD720p, and video that "connects" without displaying
  # is the result. The same value is pushed to the encoder (`merge_video_props/3`).
  #
  # This is the local guesswork limitation L4 in miniature: kelixip decides what the
  # MCU will encode. §16.3 (P8) makes the server authoritative and deletes it.
  defp codec_fmtp(state, desc, rtpmaps) do
    offered = Map.get(desc, :fmtp, %{})

    Enum.reduce(rtpmaps, %{}, fn %{pt: pt} = entry, acc ->
      case answered_params(state, desc, entry, Map.get(offered, Integer.to_string(pt))) do
        "" -> acc
        params -> Map.put(acc, Integer.to_string(pt), params)
      end
    end)
  end

  # Reflection first; ours only for an H.264 payload type the offer said nothing
  # usable about.
  defp answered_params(state, %{type: :video}, %{encoding: "H264"}, offered) do
    case reflected_params(offered) do
      "" -> configured_video_fmtp(state)
      reflected -> reflected
    end
  end

  defp answered_params(_state, _desc, _entry, offered), do: reflected_params(offered)

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
