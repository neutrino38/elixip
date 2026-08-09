defmodule TestRegistrar do
  use SIP.Session.Registrar
  require Logger
  @behaviour SIP.Session.Registrar

  defp build_aor(reg) do
    # A REGISTER may carry several contacts; this dummy registrar only
    # grants the first binding.
    aor = SIP.Uri.first_contact(reg.contact)
    expires = case SIP.Uri.get_uri_param(aor, "expires") do
      { :ok, value } ->
        value = String.to_integer(value)
        value = if value > 300 or value < 60, do: 300, else: value
        Integer.to_string(value)

      _ -> "300"
    end
    SIP.Uri.set_uri_param(aor, "expires", expires)
  end

  defp registrar_process_loop(state) do
    receive do
      { :REGISTER, reg, _trans_pid, dialog_pid } ->
        # If a register message is received, replay 200 OK
        Logger.info("REGISTRAR: replying to REGISTER")
        aor = build_aor(reg)
        SIP.Dialog.reply(dialog_pid, reg, 200, "OK", [ contact: aor ])
        Logger.info("REGISTRAR: processed an inbound REGISTER")
        # then increase the register counter
        registrar_process_loop(%{state | registered: state.registered + 1 })

      { :stop, caller_pid } ->
        send(caller_pid, state.registered)
        nil
    end
  end

  @impl true
  def on_new_registration(dialog_id, _register, _transaction_id) do
    Logger.info("on_new_registration called in test")
    case Process.whereis(:test_registrar) do
      nil ->
        state = %{ registered: 0, dialogid: dialog_id }
        new_reg_pid = spawn_link(fn -> registrar_process_loop(state) end)
        Logger.info("Created dummy registrar process #{inspect(new_reg_pid)}")
        # Register the process
        Process.register(new_reg_pid, :test_registrar)
        { :accept, new_reg_pid }

      registrar_pid when is_pid(registrar_pid) ->
        { :accept, registrar_pid }
    end
  end

  @impl true
  def on_registration_expired(_dialog_pid, _app_pid) do
    nil
  end
end

defmodule SIP.Test.B2bua.InboundDialogStub do
  @moduledoc """
  Stands in for a B2BUA's inbound-leg dialog: records the replies sent on it and
  forwards them to the test process as `{:replied, code, reason, req, fields}`.

  Shared by the B2BUA suites. A stub rather than a real dialog because both legs
  would otherwise land on the *same* UDP mockup instance — every `unittest` URI
  resolves to one destination — which would tangle the two directions.
  """
  use GenServer

  def start_link(test_pid), do: GenServer.start_link(__MODULE__, test_pid)

  @impl true
  def init(test_pid), do: {:ok, test_pid}

  @impl true
  def handle_call({:replyreq, req, code, reason, fields}, _from, test_pid) do
    send(test_pid, {:replied, code, reason, req, fields})
    {:reply, :ok, test_pid}
  end
end

ExUnit.start(exclude: [:skip])
