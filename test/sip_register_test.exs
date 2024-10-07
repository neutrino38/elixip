defmodule SIP.Test.Register do
  use ExUnit.Case
  require SIP.Dialog
  doctest SIP.Dialog

  defmodule Registrar do
    use SIP.Session.Registrar

    defp registrar_process_loop(state) do
      receive do
        { :REGISTER, reg } ->
          registrar_process_loop(state)

        :stop -> nil
      end
    end


    @impl true
    def on_new_registration(dialog_id, register) do
      case Process.whereis(:test_registrar) do
        nil ->
          state = %{ dialogid: dialog_id }
          new_reg_pid = spawn_link(fn state -> registrar_process_loop(state) end)
          Process.register(new_reg_pid, :test_registrar)
          { :accept, registrar_pid }

        registrar_pid when is_pid(registrar_pid) ->
          { :accept, registrar_pid }
      end
    end

  end

  setup_all do
    # Initialize transaction and transport layers
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    :ok = SIP.Session.ConfigRegistry.start()
  end

end
