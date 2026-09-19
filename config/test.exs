import Config

# The suite's own report is the console output. The SIP stack logs a full message
# dump per exchange, so the console is muted here and everything is written to
# test.log instead. The path is absolute because each app's tests run from its own
# directory: a relative one would scatter the file across apps/.
#
# Muted, not removed, and :emergency rather than :none: both dropping :console from
# the backends and setting it to :none take the :default :logger handler with them,
# and Kelix.Config.apply_logger — which pushes [log].level down to that very handler
# — is asserted on in apps/kelixip/test/config_test.exs. Nothing here logs above
# :critical, so the handler stays installed and silent.
config :logger, :console, level: :emergency

config :logger, :file_log,
  path: Path.expand("../test.log", __DIR__),
  format: "$time [$level] $message \n",
  level: :info

# A failing test still shows the log lines it produced: ExUnit captures them per
# test and re-emits them under the failure report.
config :ex_unit, capture_log: true

# Local UDP bind port for the suite. The transport defaults to 5060, which is
# routinely taken on a developer host (kamailio, another softswitch, …) — the bind
# then fails with :eaddrinuse and every `:live` test that needs a real socket dies
# on it, for a reason that has nothing to do with the code under test.
#
# Override when 5070 is busy too — notably while a manually-run kelixip is holding
# it, since that is the port its documented dev config uses:
#
#     ELIXIP_TEST_UDP_PORT=5075 mix test --include live
config :elixip2,
       :udp_local_port,
       String.to_integer(System.get_env("ELIXIP_TEST_UDP_PORT", "5070"))

# Centralized SIP account used across the test suite.
# Read in tests via: Application.compile_env(:elixip2, :test_account)
config :elixip2, :test_account, %{
  username: "33970262546",
  authusername: "33970262546",
  displayname: "Test User",
  domain: "visioassistance.net",
  proxy: "sip.djanah.com",
  passwd: "TestKam1"
}
