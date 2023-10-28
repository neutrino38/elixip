import Config
config :logger, :console,
  format: "[$level] $message\n",
  metadata: [:pid, :module, :function, :file, :line],
  level: :info

config :logger, :file,
  path: "elixip.log",
  level: :debug  # Niveau de journalisation souhaité (par exemple, :info, :warn, :error, :debug, etc.)
