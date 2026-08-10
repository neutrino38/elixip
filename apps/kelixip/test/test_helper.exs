# SIP.Test.Wait lives with the shared library's tests; the umbrella apps reach
# across for it the same way registrar_test.exs reaches for the captured
# SIP-REGISTER-REBIND fixture.
Code.require_file("../../elixip2/test/support/wait.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

ExUnit.start(exclude: [:skip])
