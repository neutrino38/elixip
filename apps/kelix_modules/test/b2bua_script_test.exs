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

  # Bob's handset, registered at an address that routes to the mockup. `peer:`
  # names the mockup instance, so two registered devices really are two
  # processes — which is what a hunt needs.
  defp contact(host, peer) do
    %SIP.Uri{userpart: @callee, domain: host, port: 5060}
    |> SIP.Uri.set_uri_param("unittest", peer)
  end

  defp register_callee(host \\ "10.0.0.9", opts \\ []) do
    req = %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: apply_q(contact(host, Keyword.get(opts, :peer, "1")), Keyword.get(opts, :q)),
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

  defp mockup_pid(peer \\ "1") do
    tp = SIP.Transport.Selector.select_transport(contact("10.0.0.9", peer)).tp_pid
    :ok = GenServer.call(tp, :settestapp)
    tp
  end

  test "a call to a registered subscriber is relayed to the contact the store holds",
       %{scenario: module} do
    :ok = register_callee()

    tp_pid = mockup_pid()

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

    _tp_pid = mockup_pid()

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
    _tp_pid = mockup_pid()

    {:ok, dialog} = MockDialog.start_link(self())
    req = invite()
    pid = spawn_b2bua(module, dialog, req)
    send(pid, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _fields, _req}, 5_000
    assert_receive {:replied, 480, "Temporarily Unavailable", _fields, _req}, 5_000
    refute_receive {:invite_sent, _fwd}, 500
  end

  # P2a + P2b together, and the payoff of both: a subscriber with two devices
  # registered. The preferred one refuses, and the call goes on to the other —
  # over the SAME outbound leg, as another branch of its dialog.
  test "a device that refuses sends the call on to the subscriber's other device",
       %{scenario: module} do
    :ok = register_callee("10.0.0.9", q: 0.9, peer: "hunt_a", callid: "reg-a")
    :ok = register_callee("10.0.0.42", q: 0.2, peer: "hunt_b", callid: "reg-b")

    a = mockup_pid("hunt_a")
    _b = mockup_pid("hunt_b")

    {:ok, dialog} = MockDialog.start_link(self())
    req = invite()
    pid = spawn_b2bua(module, dialog, req)
    send(pid, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _fields, _req}, 5_000

    # The q=0.9 device is tried first…
    assert_receive {:invite_sent, first}, 5_000
    assert first.ruri.domain == "10.0.0.9"

    # …it is busy, so the other one is tried. The caller is told nothing yet:
    # one device saying no is not the call failing.
    GenServer.cast(a, {:simulate, 486, 100})

    assert_receive {:invite_sent, second}, 5_000
    assert second.ruri.domain == "10.0.0.42"
    refute_receive {:replied, 486, _, _, _}, 300

    # Same call throughout: both branches carry the dialog's Call-ID, not the
    # caller's and not one each.
    assert second.callid == first.callid
    refute second.callid == req.callid
  end

  test "the script declares the module it needs, so a node without it refuses to load it",
       %{scenario: module} do
    assert module.__scenario_type__() == :uas_invite
    assert module.__scenario_config__()[:uses_modules] == [:registrar]
  end
end
