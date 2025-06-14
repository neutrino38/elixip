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
  level: :info  # Niveau de journalisation souhaité (par exemple, :info, :warn, :error, :debug, etc.)

config :elixip2,
  useragent: "Elixipp-0.2",
  optionkeepaliveperiod: 15
