import Config

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
