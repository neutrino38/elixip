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
  useragent: "Elixipp-0.2",
  optionkeepaliveperiod: 15,
  # When true, an unparseable incoming SIP message is dumped verbatim (inspected,
  # so CRLF/empty frames are visible) at warning level — useful to diagnose a
  # peer sending non-canonical or malformed SIP. Off by default (noisy: e.g.
  # WebSocket keep-alives would be logged).
  dump_unparsed_sip: false,
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

# Media server used by scenarios calling media_connect/0 (the zero-argument,
# config-driven form). :module is :mockup, :mendooze or a module name; can be
# overridden per scenario (config block) or per run (external JSON header).
config :elixip2, :mediaserver,
  module: :mockup,
  url: "sip:localhost:8080"

# Mendooze JSR309 adapter tuning (used when :mediaserver selects :mendooze)
config :elixip2, MediaServer.Mendooze,
  xmlrpc_timeout_ms: 10_000,
  rtp_timeout_ms: 10_000,
  poller_retry_ms: 1_000,
  poller_max_failures: 5

# Environment-specific configuration (e.g. config/test.exs)
if File.exists?(Path.join(__DIR__, "#{config_env()}.exs")) do
  import_config "#{config_env()}.exs"
end
