import Config

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
