defmodule SIP.Test.Register do
  use ExUnit.Case
  require SIP.Dialog
  doctest SIP.Dialog

  setup_all do
    # Initialize transaction and transport layers
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    :ok = SIP.Session.ConfigRegistry.start()
  end

end
