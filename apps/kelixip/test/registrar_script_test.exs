defmodule Kelix.RegistrarScriptTest do
  # Drives a REGISTER through a spawned instance of the reference registrar
  # script, with a mock dialog capturing the SIP reply — the whole script logic
  # (save → compose 200 OK) minus the transport/transaction/dialog layers.
  use ExUnit.Case, async: false

  alias Kelix.Mod.Registrar

  # a mock dialog: records the reply (SIP.Dialog.reply/5 → {:replyreq, …}) and
  # forwards it to the test process.
  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    path = Path.expand("../scripts/registrar.exs", __DIR__)
    %{scenario: SIP.Scenario.Loader.load_file!(path)}
  end

  setup do
    start_supervised!(Registrar)
    :ok
  end

  defp register(user, contact_host, expires \\ 3600) do
    %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: user, domain: "example.com"},
      ruri: %SIP.Uri{userpart: user, domain: "example.com", destip: {1, 2, 3, 4}, destport: 5060, destproto: "UDP"},
      contact: %SIP.Uri{userpart: user, domain: contact_host, port: 5060},
      expires: expires,
      callid: "call-#{user}"
    }
  end

  defp spawn_registrar(module, dialog, req) do
    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(module,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: "example.com"]
      )

    on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)
    pid
  end

  test "a REGISTER is stored and answered with 200 OK", %{scenario: module} do
    {:ok, dialog} = MockDialog.start_link(self())
    req = register("alice", "10.0.0.9")

    pid = spawn_registrar(module, dialog, req)
    send(pid, {:REGISTER, req, nil, dialog})

    assert_receive {:replied, 200, "OK", _fields, _req}, 1000
    assert [_binding] = Registrar.bindings("example.com", "alice")
  end

  test "an un-REGISTER (expires 0) is answered 200 and clears the binding", %{scenario: module} do
    {:ok, dialog} = MockDialog.start_link(self())

    # first register…
    pid = spawn_registrar(module, dialog, register("bob", "10.0.0.9"))
    send(pid, {:REGISTER, register("bob", "10.0.0.9"), nil, dialog})
    assert_receive {:replied, 200, "OK", _, _}, 1000
    assert [_] = Registrar.bindings("example.com", "bob")

    # …then un-register
    send(pid, {:REGISTER, register("bob", "10.0.0.9", 0), nil, dialog})
    assert_receive {:replied, 200, "OK", _, _}, 1000
    assert Registrar.bindings("example.com", "bob") == []
  end
end
