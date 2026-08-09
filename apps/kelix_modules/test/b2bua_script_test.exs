defmodule Kelix.B2buaScriptTest do
  @moduledoc """
  The registrar-driven B2BUA (`apps/kelixip/scripts/b2bua.exs`, design §3.2):
  a call placed to whatever contact the location service says the AOR has.

  This is the seam the umbrella is arranged around — `elixip2` never references
  the module; the *script*, which runs where the module is loaded, does the
  lookup and hands plain `%SIP.Uri{}` to a `%SIP.B2bua.Peer{}`. So it is tested
  here, in the only app where both halves exist (CLAUDE.md, umbrella layout).

  The callee is reached through the in-process UDP mockup: the registered
  contact carries the `unittest` marker, which `SIP.Transport.Selector` honours
  above everything else. The caller's dialog is a mock capturing what the B2BUA
  answers on it.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mod.Registrar
  alias SIP.Test.Transport.UDPMockup

  @domain "example.com"
  @callee "bob"

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
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()

    %{
      scenario:
        SIP.Scenario.Loader.load_file!(Path.expand("../../kelixip/scripts/b2bua.exs", __DIR__))
    }
  end

  setup do
    start_supervised!(Registrar)
    :ok
  end

  # Bob's handset, registered at an address that routes to the mockup.
  defp contact(host) do
    %SIP.Uri{userpart: @callee, domain: host, port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "1")
  end

  defp register_callee(host \\ "10.0.0.9", opts \\ []) do
    req = %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: apply_q(contact(host), Keyword.get(opts, :q)),
      expires: 3600,
      callid: Keyword.get(opts, :callid, "reg-#{host}")
    }

    {:ok, _granted} = Registrar.save(req, @domain)
    :ok
  end

  defp apply_q(uri, nil), do: uri
  defp apply_q(uri, q), do: SIP.Uri.set_uri_param(uri, "q", to_string(q))

  # An INVITE arriving for bob@example.com.
  defp invite do
    %{
      "Max-Forwards" => 70,
      method: :INVITE,
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      from: %SIP.Uri{userpart: "alice", domain: @domain, params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: %SIP.Uri{userpart: "alice", domain: "10.0.0.1", port: 5060},
      callid: SIP.Msg.Ops.generate_branch_value(),
      cseq: [1, :INVITE],
      contentlength: 0
    }
  end

  defp spawn_b2bua(module, dialog, req) do
    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(module,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain]
      )

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    pid
  end

  defp mockup_pid do
    SIP.Transport.Selector.select_transport(contact("10.0.0.9")).tp_pid
  end

  test "a call to a registered subscriber is relayed to the contact the store holds",
       %{scenario: module} do
    :ok = register_callee()

    tp_pid = mockup_pid()
    :ok = GenServer.call(tp_pid, :settestapp)

    {:ok, dialog} = MockDialog.start_link(self())
    req = invite()
    pid = spawn_b2bua(module, dialog, req)
    send(pid, {:INVITE, req, self(), dialog})

    # The caller is acknowledged immediately…
    assert_receive {:replied, 100, "Trying", _fields, _req}, 5_000

    # …and the call goes out to the registered contact, in a dialog of its own.
    assert_receive {:invite_sent, fwd}, 5_000
    assert fwd.ruri.userpart == @callee
    assert fwd.ruri.domain == "10.0.0.9"
    assert fwd.callid != req.callid

    # The callee answers; the caller gets that answer.
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _fields, _req}, 5_000
  end

  test "the highest-q contact is the one dialled", %{scenario: module} do
    :ok = register_callee("10.0.0.9", q: 0.2, callid: "reg-low")
    :ok = register_callee("10.0.0.42", q: 0.9, callid: "reg-high")

    tp_pid = mockup_pid()
    :ok = GenServer.call(tp_pid, :settestapp)

    {:ok, dialog} = MockDialog.start_link(self())
    req = invite()
    pid = spawn_b2bua(module, dialog, req)
    send(pid, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _fields, _req}, 5_000
    assert_receive {:invite_sent, fwd}, 5_000
    assert fwd.ruri.domain == "10.0.0.42"
  end

  test "an AOR nobody registered is answered 480, and no call goes out",
       %{scenario: module} do
    tp_pid = mockup_pid()
    :ok = GenServer.call(tp_pid, :settestapp)

    {:ok, dialog} = MockDialog.start_link(self())
    req = invite()
    pid = spawn_b2bua(module, dialog, req)
    send(pid, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _fields, _req}, 5_000
    assert_receive {:replied, 480, "Temporarily Unavailable", _fields, _req}, 5_000
    refute_receive {:invite_sent, _fwd}, 500
  end

  test "the script declares the module it needs, so a node without it refuses to load it",
       %{scenario: module} do
    assert module.__scenario_type__() == :uas_invite
    assert module.__scenario_config__()[:uses_modules] == [:registrar]
  end
end
