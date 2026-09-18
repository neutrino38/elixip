# SIP.Test.Wait lives with the shared library's tests; the umbrella apps reach
# across for it the same way registrar_test.exs reaches for the captured
# SIP-REGISTER-REBIND fixture.
Code.require_file("../../elixip2/test/support/wait.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)
Code.require_file("support/app_boot.exs", __DIR__)
Kelix.Test.AppBoot.ensure_started!()

ExUnit.start(exclude: [:skip])

Code.require_file("../../elixip2/test/support/test_log.exs", __DIR__)
SIP.Test.Log.setup()
