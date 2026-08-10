Code.require_file("support/mcu_stub.exs", __DIR__)
Code.require_file("../../elixip2/test/support/wait.exs", __DIR__)
Code.require_file("../../kelixip/test/support/fixtures.exs", __DIR__)

ExUnit.start(exclude: [:skip])
