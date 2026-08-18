defmodule Kelix.DirectCallScriptTest do
  @moduledoc """
  The reference call script (`apps/kelixip/scripts/direct-call.exs`) once its
  establishment states became one `SBB.Call.call/1`.

  The two CANCEL races are the point. They are tested elsewhere too, on
  `B2BUA.Basic` — the scenario that deliberately stays raw FSL — and the same
  assertions run here against the same behaviour expressed as a block call. That
  is what makes the two comparable: a regression in `SBB.Call.Establish` shows up
  as a difference between them, not as a scenario that was always odd.

  Tested in this app for the same reason the authenticated variant is: it is the
  only one where both halves exist, the script and the `registrar` module it
  calls.
  """
  use ExUnit.Case, async: false

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  alias Kelix.Mod.Registrar

  @domain "example.com"
  @caller "alice"
  @callee "bob"

  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    # A dialog also ORIGINATES: what the callee sends is relayed onto this leg.
    def handle_call({:newreq, req}, _from, test) do
      send(test, {:sent_on_inbound, req})
      {:reply, {:ok, self()}, test}
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
        SIP.Scenario.Loader.load_file!(
          Path.expand("../../kelixip/scripts/direct-call.exs", __DIR__)
        )
    }
  end

  setup do
    start_supervised!(Registrar)
    :ok
  end

  # Bob's handset, registered at an address that routes to the mockup.
  defp contact(peer),
    do:
      %SIP.Uri{userpart: @callee, domain: "10.0.0.9", port: 5060}
      |> SIP.Uri.set_uri_param("unittest", peer)

  defp register_callee(peer) do
    req = %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: contact(peer),
      expires: 3600,
      callid: "reg-#{peer}"
    }

    {:registered, _granted} = Registrar.save(req, @domain)
    :ok
  end

  defp mockup_pid(peer) do
    tp = SIP.Transport.Selector.select_transport(contact(peer)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp invite(callid) do
    %{
      "Max-Forwards" => 70,
      method: :INVITE,
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      from: %SIP.Uri{userpart: @caller, domain: @domain, params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: %SIP.Uri{userpart: @caller, domain: "10.0.0.1", port: 5060},
      callid: callid,
      cseq: [1, :INVITE],
      body: [],
      contentlength: 0
    }
  end

  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  # One instance of the script, in its own process (an FSM blocks on receive, so
  # it cannot share the test process), with its VERDICT surfaced: what the script
  # names each of the block's outcomes is what these tests are about, and a
  # scenario that crashed would otherwise be indistinguishable from one that
  # concluded.
  defp start_instance(module, dialog, req) do
    test = self()

    {pid, ref} =
      spawn_monitor(fn ->
        outcome =
          SIP.Scenario.Runner.run_instance(module,
            dialog_pid: dialog,
            inbound_request: req,
            config_overrides: [domain: @domain]
          )

        send(test, {:instance_done, outcome})
      end)

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    {pid, ref}
  end

  # ── The cancel race (RFC 3261 §16.7) ────────────────────────────────────────

  # Cancelling ASKS; it does not decide. Ending on the CANCEL is right until the
  # callee's answer crosses it on the wire — so the block waits for the final,
  # and the script names what that final meant.
  test "a CANCEL waits for the callee's final before ending the call", %{scenario: module} do
    :ok = register_callee("dc-cancel")
    tp = mockup_pid("dc-cancel")
    {:ok, dialog} = MockDialog.start_link(self())

    req = invite("call-cancel-1")
    {instance, ref} = start_instance(module, dialog, req)
    send(instance, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _f, _r}, 5_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000
    Manual.simulate(tp, 180, 100)
    assert_receive {:replied, 180, _reason, _f, _r}, 5_000

    # The caller gives up. The mockup answers the relayed CANCEL the way a UA
    # does: 200 to the CANCEL, then 487 to the INVITE it cancels.
    send(instance, {:CANCEL, in_dialog(:CANCEL, req), self(), dialog})

    # It ends on the 487, not on the CANCEL — and it does end, rather than
    # sitting in the block's `cancelling` state until its 32 s deadline. The
    # block answers `{:call, :cancelled, _}`; the script calls that an abort.
    assert_receive {:instance_done, {:aborted, "caller cancelled, callee confirmed"}}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # The race itself, and the reason the state exists: the callee picked up before
  # the CANCEL reached it. Nobody is left to talk to, so the 2xx must be ACKed —
  # §13.2.2.4 puts that ACK in the UAC core, and a 2xx nobody acknowledges leaves
  # the callee off-hook retransmitting it — and then ended with a BYE (§15).
  test "a callee answering after the CANCEL is acknowledged and hung up",
       %{scenario: module} do
    :ok = register_callee("dc-race")
    tp = mockup_pid("dc-race")
    {:ok, dialog} = MockDialog.start_link(self())

    req = invite("call-cancel-2")
    {instance, ref} = start_instance(module, dialog, req)
    send(instance, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _f, _r}, 5_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

    # The caller gives up…
    send(instance, {:CANCEL, in_dialog(:CANCEL, req), self(), dialog})

    # …and the callee answers anyway, ahead of the 487 the mockup schedules for
    # the CANCEL: the answer crossed the cancellation.
    Manual.simulate(tp, 200, 0)

    # Both, in this order, and neither is optional.
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 5_000

    # A call that happened, briefly — not an abort. That distinction is the one
    # somebody bills on, and it is the script that draws it.
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # ── What the block relays on the way there ──────────────────────────────────

  test "the provisionals and the answer are relayed, and the ACK crosses",
       %{scenario: module} do
    :ok = register_callee("dc-ok")
    tp = mockup_pid("dc-ok")
    {:ok, dialog} = MockDialog.start_link(self())

    req = invite("call-ok-1")
    {instance, ref} = start_instance(module, dialog, req)
    send(instance, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _f, _r}, 5_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

    Manual.simulate(tp, 180, 50)
    assert_receive {:replied, 180, _reason, _f, _r}, 5_000

    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _f, _r}, 5_000

    # The caller ACKs, and the block relays it rather than answering it itself.
    send(instance, {:ACK, in_dialog(:ACK, req), self(), dialog})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    # The call is up: the script is out of the block and in `connected`, so a BYE
    # from the caller now ends it.
    send(instance, {:BYE, in_dialog(:BYE, req), self(), dialog})
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # A callee that refuses ends the call, and the refusal reaches the caller.
  test "a final ≥ 300 is relayed and ends the call", %{scenario: module} do
    :ok = register_callee("dc-busy")
    tp = mockup_pid("dc-busy")
    {:ok, dialog} = MockDialog.start_link(self())

    req = invite("call-busy-1")
    {instance, ref} = start_instance(module, dialog, req)
    send(instance, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _f, _r}, 5_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

    Manual.simulate(tp, 486, 50)
    assert_receive {:replied, 486, _reason, _f, _r}, 5_000

    # The block hands back the code it relayed; the script decides that a callee
    # saying no is a call that worked.
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
