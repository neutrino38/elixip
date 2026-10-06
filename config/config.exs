import Config

config :logger,
  backends: [:console, {LoggerFileBackend, :file_log}]

config :logger, :console,
  format: "[$level] $message\n",
  metadata: [:pid, :module, :function, :file, :line],
  level: :warning

config :logger, :file_log,
  path: "elixip.log",
  format: "$time [$level] $message \n",
  # Niveau de journalisation souhaité (par exemple, :info, :warn, :error, :debug, etc.)
  level: :info

config :elixip2,
  useragent: "Elixipp-1.6.3",
  optionkeepaliveperiod: 15,
  # The largest inbound SIP message accepted, in BYTES. Past it a request is
  # answered 513 (Message too large) instead of being parsed; a response and an
  # ACK, which are never answered, are dropped with a log line.
  #
  # A memory bound of ours, not a protocol one: RFC 3261 §18.1.1 bounds a message
  # for UDP only and names TCP as the way out. Keep it an order of magnitude above
  # normal traffic — a WebRTC offer with four m-sections weighs about 13 kB.
  max_message_size: 64_000,
  # When true, an unparseable incoming SIP message is dumped verbatim (inspected,
  # so CRLF/empty frames are visible) at warning level — useful to diagnose a
  # peer sending non-canonical or malformed SIP. Off by default (noisy: e.g.
  # WebSocket keep-alives would be logged).
  dump_unparsed_sip: false,
  # WebSocket ping period, in seconds, on every WSS connection (RFC 6455 §5.5.2).
  # A SIP-over-WSS flow is idle between two REGISTER refreshes and the boxes on the
  # path reap it long before then — nginx and most load balancers at 60 s, a home
  # NAT sooner. The peer's WebSocket stack answers without waking the SIP client.
  # Three unanswered periods close the connection, so this is also how fast a
  # half-open socket is noticed. Set to 0 to disable.
  wss_keepalive_period: 30,
  # TLS/WSS cipher suites (charlists). Mozilla "intermediate" profile — all
  # provide PFS via ephemeral ECDHE key exchange. Override here to restrict or
  # extend the negotiable suites; if unset, the default baked into the transport
  # (SIP.Transport.ImplHelpers @tls_ciphers) is used.
  tls_ciphers: [
    ~c"ECDHE-ECDSA-AES256-GCM-SHA384",
    ~c"ECDHE-RSA-AES256-GCM-SHA384",
    ~c"ECDHE-ECDSA-CHACHA20-POLY1305",
    ~c"ECDHE-RSA-CHACHA20-POLY1305",
    ~c"ECDHE-ECDSA-AES128-GCM-SHA256",
    ~c"ECDHE-RSA-AES128-GCM-SHA256"
  ]

# RFC 4028 session timers, negotiated by each call dialog with its own peer
# (SIP.DialogImpl.SessionTimer). Off by default: no Session-Expires is stated on
# a 2xx and no peer is held to a refresh.
config :elixip2, :session_timer,
  enabled: false,
  # The interval we ask for or accept, in seconds (RFC 4028 recommends 1800).
  expires: 1800,
  # The smallest interval we accept; below it a request is answered 422. The RFC
  # floor is 90.
  min_se: 90,
  # Who refreshes when the peer leaves us the choice: :local or :remote.
  refresher: :local

# Media server used by scenarios calling media_connect/0 (the zero-argument,
# config-driven form). :module is :mockup, :mendooze or a module name; can be
# overridden per scenario (config block) or per run (external JSON header).
config :elixip2, :mediaserver,
  module: :mockup,
  url: "sip:localhost:8080"

# Mendooze JSR309 adapter tuning (used when :mediaserver selects :mendooze)
config :elixip2, MediaServer.Mendooze,
  # A control RPC to a media server on the same host answers in milliseconds;
  # two seconds is the point past which it is not slow but broken, and waiting
  # longer only keeps the scenario from acting on its own (see XmlRpc).
  xmlrpc_timeout_ms: 2_000,
  rtp_timeout_ms: 10_000,
  poller_retry_ms: 1_000,
  poller_max_failures: 5

# Environment-specific configuration (e.g. config/test.exs)
if File.exists?(Path.join(__DIR__, "#{config_env()}.exs")) do
  import_config "#{config_env()}.exs"
end
