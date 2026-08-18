# Route ";unittest=…" R-URIs to the mockup transport (see SIP.Transport.Selector
# and apps/elixip2/test/support/transport_mockup.ex). The module is compiled with
# :elixip2 in the :test env, but the app env is per-run, so each app's suite sets
# it for itself.
Application.put_env(:elixip2, :unittest_transport, SIP.Test.Transport.Mockup)

Code.require_file("support/mcu_stub.exs", __DIR__)
Code.require_file("../../elixip2/test/support/wait.exs", __DIR__)
Code.require_file("../../kelixip/test/support/fixtures.exs", __DIR__)

ExUnit.start(exclude: [:skip])
