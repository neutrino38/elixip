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
  level: :debug  # Niveau de journalisation souhaité (par exemple, :info, :warn, :error, :debug, etc.)

config :elixip2,
  useragent: "Elixipp-0.2",
  optionkeepaliveperiod: 15,
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

# Environment-specific configuration (e.g. config/test.exs)
if File.exists?(Path.join(__DIR__, "#{config_env()}.exs")) do
  import_config "#{config_env()}.exs"
end
