defmodule Kelix.OptionsTest do
  use ExUnit.Case, async: false

  @moduledoc """
  The answer kelixip gives to an out-of-dialog OPTIONS — the liveness ping upstream
  uses to decide whether this node takes traffic.

  Getting this wrong is not cosmetic: before it was answered at all, kelixip replied
  403 (a crash in the dialog layer, turned into "Denied" by the transaction layer),
  which an upstream proxy reads as a broken node.
  """

  alias Kelix.Control

  setup do
    on_exit(fn -> Control.undrain() end)
    :ok
  end

  describe "in service" do
    test "answers 200 and advertises what this server implements" do
      assert {:reply, 200, "OK", fields} = Kelix.Options.on_options(%{method: :OPTIONS}, self())
      assert {"Allow", allow} = List.keyfind(fields, "Allow", 0)

      # The registrar and OPTIONS itself. INVITE joins the list when the call function
      # lands — a probe would catch the lie until then.
      assert allow == "OPTIONS, REGISTER"
      assert allow =~ "REGISTER"
      assert allow =~ "OPTIONS"
      refute allow =~ "INVITE"
    end

    test "the advertised list is the one Kelix.Options exposes" do
      {:reply, 200, _, fields} = Kelix.Options.on_options(%{method: :OPTIONS}, self())
      assert List.keyfind(fields, "Allow", 0) == {"Allow", Kelix.Options.allow()}
    end
  end

  describe "draining" do
    test "answers 503 so upstream stops sending new traffic" do
      :ok = Control.drain()

      assert {:reply, 503, reason, fields} =
               Kelix.Options.on_options(%{method: :OPTIONS}, self())

      assert reason =~ "Unavailable"
      # No Retry-After: we cannot honestly say when this node returns, and upstream
      # would honour whatever number we invented.
      assert fields == []
    end
  end

  describe "registration" do
    test "Kelix.Router registers it, so the framework does not answer 500" do
      {:ok, _} = SIP.Session.ConfigRegistry.start()
      prev = SIP.Session.ConfigRegistry.get_options_processing_module()
      on_exit(fn -> SIP.Session.ConfigRegistry.set_options_processing_module(prev) end)

      :ok = SIP.Session.ConfigRegistry.set_options_processing_module(nil)
      assert :ignore = Kelix.Router.register_processing_modules()
      assert SIP.Session.ConfigRegistry.get_options_processing_module() == Kelix.Options
    end
  end
end
