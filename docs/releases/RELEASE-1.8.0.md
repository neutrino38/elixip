# Release 1.8.0

2026-10-21 — since 1.7.0 (2026-10-07). Theme: captioned calls — what one party
says is written to the other, what the other types is spoken.

1.8.0 includes 1.7.1 (2026-10-18), which had no release note of its own: 1.7.0
merged with the whole 1.6.4 maintenance line (revisions 1 to 8, Microsoft Teams
Direct Routing among them) and the 1.6.5 one (revisions 1 to 5). Those are
summarised under [1.7.1](#171-1) below.

Needs **mediaserver 1.19.0** for the SpeechProcessor, for AMR-WB on the wire and
for the speech availability check.

## 1.8.0-2

2026-10-21. Theme: speech refused cleanly when it cannot be served.

### Speech availability

- **A call that asks for speech is refused with `503 Speech Processing
  Unavailable`** when the media server cannot serve it: speech-server not
  configured, not running, or Mistral not answering. The media server is asked
  before anything is dialled, so nothing reaches the trunk, and the reason is
  in the log.
- **Speech lost during a call keeps the call.** The audio and text relays keep
  working, the media server reopens the stream on its own, and the log says
  when speech goes and when it comes back.
- **A SpeechProcessor that cannot be created on the answer gives the caller a
  503 at once**, instead of a 488 after 32 s waiting for an ACK.
- `media_speech_available()` (elixipp, scenarios): whether the media server can
  serve speech now. An older mediaserver than 1.19.0 is only asked whether
  speech is configured.

### Scripts

- `speech_bot.exs` answers 503 without a media server, instead of nothing.
- `call-captioning.exs` challenges on the `visioassistance.net` realm, and
  offers PCMU after AMR-WB and PCMA.
- **The scenario scripts are `%config(noreplace)`** in the RPMs: a script
  edited on the node survives the upgrade, and the packaged one lands next to
  it as `.rpmnew`.

### Upgrading

- `dnf upgrade kelixip` from 1.8.0-1. No configuration change.
- After the upgrade, look for `.rpmnew` files under `/etc/kelixip/scripts`.

## 1.8.0-1

2026-10-21. Theme: the SpeechProcessor.

### Captioned calls (`speech:` in the media tuple)

A B2BUA call can put a **SpeechProcessor** between its legs. It is meant for a
deaf caller and a hearing callee:

- what one leg says is written to the other as T.140 text (`transcribe: true`);
- what one leg types is spoken to the other (`speak: true`, in a `voice` from
  speech-server's configuration).

Audio and text go through the SpeechProcessor; video stays endpoint to
endpoint. Text goes through it on whichever leg carries it, so a callee that
declines text still has its voice captioned. `speech:` implies audio
transcoding. The full description is in [B2BUA.md](../../B2BUA.md).

### Voice dialogue with a caller

`start_speech`, `say`, `stop_speaking` and `stop_speech` hold a voice dialogue
with a caller; the voices are read from speech-server. elixipp gets the same
verbs (`media_start_speech`, `media_say`, `media_stop_speaking`,
`media_stop_speech`, `media_voices`) and the `speech_bot` scenario.

### Reference script `call-captioning.exs`

A challenged call relayed through the `sip-trunk-prod` trunk with audio and
text only, AMR-WB then PCMA. The callee's voice is captioned and the caller's
typing is spoken. The script answers 488 when the caller offers no text.

### Codecs

- **AMR-WB** joins the codec vocabulary.
- A conference that places a call without `codec_order` offers audio as OPUS,
  AMR-WB, SPEEX, G722, PCMA, PCMU, instead of in alphabetical order.

### Upgrading

- `dnf upgrade kelixip` from 1.7.1. Upgrade the media server to 1.19.0 first.
- User-Agent: `Kelixip/1.8.0`, `Elixipp-1.8.0`.

## 1.7.1-1

2026-10-18. 1.7.0 (chat attachments) merged with the 1.6.4 and 1.6.5
maintenance lines, which were built for production while 1.7.0 was being
prepared.

### From 1.6.4-1 to 1.6.4-8

Described revision by revision in [RELEASE-1.6.4.md](RELEASE-1.6.4.md). In
short:

- **Unified Plan**: several video streams and BUNDLE on a WebRTC leg, so screen
  sharing goes through the B2BUA.
- **Security incidents for fail2ban**: `[security] log_file`, filters and a
  jail example under `/usr/share/kelixip/fail2ban/`.
- **New module `sip_servers`** (subpackage `kelixip-mod-sip_servers`): the
  remote application servers, proxies and trunks of a domain, with OPTIONS
  liveness, trunk registration, `tertiary_uri`, `source_networks`,
  `use_fqdn_contact`, `publish_contact_host` and `ext_domain` — what Teams
  Direct Routing needs.
- `config.toml [tls]` takes `cert` and `key`: the client certificate for a peer
  that demands one (mutual TLS).
- A registration binding keeps the REGISTER's User-Agent, Call-ID and CSeq; a
  published presence reports `received_time`.
- `trust_asserted_identity/1`, and the SHA-256 digest spelling of RFC 8760.

### From 1.6.5-1 to 1.6.5-5

- **A P-Asserted-Identity holding two bracketed values on one line**
  (`<tel:…>,<sip:…>`, as the Microsoft PSTN hub sends it) is refused as one URI
  instead of raising. Every Teams Direct Routing call died before its script
  ran.
- **The 2xx that establishes an outbound dialog names its remote tag**, even
  when a 1xx gave the early dialog another one (RFC 3261 §13.2.2.4). The PSTN
  hub answers from another leg than the one that rang: its ICE re-INVITE got a
  481 and the call was hung up.
- **A conference places calls** (dial-out): `Kelix.Mod.Mcu.dial_out/4`, with
  `Kelix.Mod.SipServers.dial_target/3` for the Request-URI. A dial-out leg
  keeps the media server's default addressing profile across the far end's
  re-INVITE.
- `Kelix.Mod.Mcu.admit/3` takes the conference number as an option (`did:`),
  for a script that computes it.
- **A script starts on demand**, with no SIP request behind it:
  `kelictl run <script> <domain> [key=value…]` or `POST /scripts/<name>/run`.
  The arguments reach the instance as `run_args`.
- `sip_servers`: a trunk's keepalive OPTIONS comes from its account, and its
  Contact always carries a user part.
- No module sends outbound SIP before the listeners are bound.
- `compile_and_restart_all` keeps the installed distribution cookie.

### Upgrading

- `dnf upgrade kelixip` from 1.7.0 or from any 1.6.4 / 1.6.5 revision.
- Install `kelixip-mod-sip_servers` and add a `[module.sip_servers]` block to
  `config.toml` only on a node that talks to remote SIP servers.
- User-Agent: `Kelixip/1.7.1`, `Elixipp-1.7.1`.
