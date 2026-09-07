defmodule Kelix.Mod.McuConferenceSbbTest do
  @moduledoc """
  `Kelix.Mod.Mcu.SBB.conference/1` — a conference leg's life in the mix as a
  service building block (design `docs/design/DESIGN-MCU.md`).

  Tested here rather than in `:elixip2` for the reason the block lives here: it
  needs a mix, and a mix needs the module and a media server. The host is a
  purpose-built scenario reporting every outcome to a probe, so the assertions
  are on the block's **public API** — the `{:conference, outcome, data}` it hands
  back — and not on what one reference script happens to do with it.

  What the reference scripts do with it is `mcu_call_test.exs`, which drives
  `mcu.exs` end to end and covers the first ACK / retransmitted ACK split, the
  RPC order, and the FPU both ways through the block.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Conference, Config}

  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]
  @domain "example.com"

  @offer """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8\r
  a=rtpmap:8 PCMA/8000\r
  a=sendrecv\r
  """

  defmodule MockDialog do
    @moduledoc "Captures what the host and the block put on the wire."
    use GenServer

    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    def handle_call({:newreq, req}, _from, test) do
      send(test, {:sent_request, Map.get(req, :method), req})
      {:reply, {:ok, self()}, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
    def handle_cast(_msg, test), do: {:noreply, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  # The smallest host that can hold a conference leg: admit, answer, enter the
  # block — then report what it hands back. What it does with a renegotiation is
  # the test's to choose (`:renegotiation_reply`), because that decision is
  # exactly the one the block refuses to make.
  defmodule Gate do
    use SIP.Scenario
    use SIP.Session.CallUAS
    use Kelix.Mod.Mcu

    uas(:invite)

    state initial_state do
      on_events do
        {:INVITE, req, _trans, dialog_pid} ->
          admit(req, dialog_pid)
          media_connect()
          goto(answering)
      after
        5_000 -> scenario_failure("no INVITE")
      end
    end

    state answering do
      reply_invite_with_sdp(200, media: :tc, webrtc: :if_offered)
      goto(in_conference)
    end

    state in_conference do
      Mcu.SBB.conference(args: %{idle_timeout: ctx_get(:idle_timeout)})

      on_events do
        {:conference, :renegotiation, %{method: method} = data} ->
          report({:outcome, :renegotiation, Map.take(data, [:method])})

          # `nil` answers nothing at all, which is what proves the block handed
          # the request back UNANSWERED rather than answering it itself.
          #
          # The reply macros rebind `sip_ctx`, and a rebinding inside a `case`
          # clause is lost with the clause — so the branch's value is what carries
          # it out. A real script answers at the top of its arm and never meets
          # this; a copy that wraps the answer in a condition does.
          reply = ctx_get(:renegotiation_reply)

          sip_ctx =
            cond do
              is_nil(reply) ->
                sip_ctx

              reply == 200 ->
                reply_invite_with_sdp(200, media: :tc, webrtc: :if_offered)
                sip_ctx

              true ->
                reply_invite(reply, "Not Acceptable Here")
                sip_ctx
            end

          goto(loop, "#{method} renegotiated")

        {:conference, :message, %{envelope: envelope}} ->
          report({:outcome, :message, %{kind: envelope.kind}})
          goto(loop, "collaboration message")

        {:conference, outcome, data} ->
          report({:outcome, outcome, data})
          scenario_success("#{outcome}")
      end
    end

    on_shutdown do
      report({:on_shutdown, :ran})
      scenario_aborted("stopped")
    end

    defp report(what) do
      case Process.whereis(:mcu_sbb_probe) do
        nil -> :ok
        pid -> send(pid, what)
      end
    end

    defp do_admit(sip_ctx, req, _dialog_pid, domain) do
      Kelix.Mod.Mcu.admit(sip_ctx, domain, req, displayname: :auto)
    end
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    :ok
  end

  setup do
    {:ok, config} = Config.parse(%{"did_range" => "8000-8009", "dtmf" => true})
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self()),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_for_client()
    Process.register(self(), :mcu_sbb_probe)

    {:ok, %{uid: uid, did: did}} =
      Mcu.handle_control("conference.create", %{"domain" => @domain, "name" => "Weekly"})

    _setup_rpcs = TestStub.rpc_order()
    %{uid: uid, did: did}
  end

  defp wait_for_client(attempts \\ 100) do
    case Mcu.mediaserver("mcu1") do
      {:ok, %{status: :up, client: pid}} when is_pid(pid) -> :ok
      _ when attempts > 0 -> Process.sleep(10) && wait_for_client(attempts - 1)
      _ -> flunk("the mcu1 client never came up")
    end
  end

  defp invite(did) do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: did, domain: @domain},
      from: %SIP.Uri{userpart: "alice", domain: "phone.example.com"},
      to: %SIP.Uri{userpart: did, domain: @domain},
      callid: "call-#{System.unique_integer([:positive])}",
      cseq: [1, :INVITE],
      body: @offer,
      contenttype: "application/sdp"
    }
  end

  defp reoffer(method, did) do
    did |> invite() |> Map.put(:method, method) |> Map.put(:cseq, [2, method])
  end

  # In the mix: the call is answered and the ACK has attached the leg.
  defp start_in_mix(did, overrides \\ []) do
    {:ok, dialog} = MockDialog.start_link(self())
    req = invite(did)

    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(Gate,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain] ++ overrides
      )

    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    send(pid, {:INVITE, req, nil, dialog})
    assert_receive {:replied, 200, _reason, _fields, _req}, 2000

    send(pid, {:ACK, %{method: :ACK}, nil, dialog})
    assert wait_for(fn -> attached?(TestStub.rpc_order()) end)

    {pid, dialog}
  end

  # Only the ACK-time sequence starts sending: it is what puts the leg in the mix.
  defp attached?(rpcs), do: "StartSending" in rpcs

  defp participants(uid) do
    {:ok, conf} = Mcu.conference(uid)
    Conference.participants(conf)
  end

  defp wait_for(fun, attempts \\ 200) do
    case fun.() do
      falsy when falsy in [nil, false] and attempts > 0 ->
        Process.sleep(10)
        wait_for(fun, attempts - 1)

      value ->
        value
    end
  end

  describe "a renegotiation comes back unanswered" do
    test "a re-INVITE is handed back, and the block answers nothing", ctx do
      {pid, dialog} = start_in_mix(ctx.did)

      send(pid, {:INVITE, reoffer(:INVITE, ctx.did), nil, dialog})
      assert_receive {:outcome, :renegotiation, %{method: :INVITE}}, 2000

      # The host chose to answer nothing, so nothing was answered: composing a
      # response to an offer is not the block's to do.
      refute_receive {:replied, _code, _reason, _fields, _req}, 300
    end

    test "an UPDATE is handed back the same way", ctx do
      {pid, dialog} = start_in_mix(ctx.did)

      send(pid, {:UPDATE, reoffer(:UPDATE, ctx.did), nil, dialog})
      assert_receive {:outcome, :renegotiation, %{method: :UPDATE}}, 2000
      refute_receive {:replied, _code, _reason, _fields, _req}, 300
    end
  end

  describe "coming back in" do
    # The phase the block keeps in the SHARED appdata is what makes re-entry
    # correct without the host saying anything. Keyed on the sandbox it would be
    # cleared on every entry, and the ACK-time sequence would re-run each time.
    test "a re-INVITE answered 200 puts the phase back: its own ACK re-attaches", ctx do
      {pid, dialog} = start_in_mix(ctx.did, renegotiation_reply: 200)

      send(pid, {:INVITE, reoffer(:INVITE, ctx.did), nil, dialog})
      assert_receive {:outcome, :renegotiation, %{method: :INVITE}}, 2000
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      _drain = TestStub.rpc_order()

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert wait_for(fn -> attached?(TestStub.rpc_order()) end)
    end

    # RFC 3311: an UPDATE's 200 concludes the offer/answer, so no ACK follows and
    # nothing would ever re-attach if the block waited for one.
    test "an UPDATE answered 200 re-attaches on re-entry, with no ACK involved", ctx do
      {pid, dialog} = start_in_mix(ctx.did, renegotiation_reply: 200)
      _drain = TestStub.rpc_order()

      send(pid, {:UPDATE, reoffer(:UPDATE, ctx.did), nil, dialog})
      assert_receive {:outcome, :renegotiation, %{method: :UPDATE}}, 2000

      assert wait_for(fn -> attached?(TestStub.rpc_order()) end)
    end

    # The ACK of a non-2xx is absorbed by the server transaction (RFC 3261
    # §17.2.1), so nothing re-attaches — and the leg keeps the media it had,
    # which is what a refusal means.
    test "a re-INVITE refused 488 stays in the mix, and leaves no event behind", ctx do
      {pid, dialog} = start_in_mix(ctx.did, renegotiation_reply: 488)
      joined = wait_for(fn -> List.first(participants(ctx.uid)) end)
      _drain = TestStub.rpc_order()

      send(pid, {:INVITE, reoffer(:INVITE, ctx.did), nil, dialog})
      assert_receive {:outcome, :renegotiation, %{method: :INVITE}}, 2000
      assert_receive {:replied, 488, _reason, _fields, _req}, 2000

      refute attached?(TestStub.rpc_order())
      assert [row] = participants(ctx.uid)
      assert row.state == :connected
      assert row.joined_at == joined.joined_at

      # …and the block is back in the mix rather than sitting on an event nobody
      # will match: an INFO is still answered.
      send(pid, {:INFO, %{method: :INFO}, nil, dialog})
      assert_receive {:replied, 200, "OK", _fields, _req}, 2000
    end

    # The rule that fails SILENTLY if it regresses: a handed-back message must not
    # look like a fresh entry, or every collaboration message re-attaches the leg.
    test "a collaboration message resumes without a second attach", ctx do
      {pid, _dialog} = start_in_mix(ctx.did)
      joined = wait_for(fn -> List.first(participants(ctx.uid)) end)
      _drain = TestStub.rpc_order()

      envelope = %{
        msg_id: "m1",
        seq: 1,
        from: %{part_id: 7, display_name: "bob"},
        kind: "hand.raised",
        payload: "",
        sent_at: DateTime.utc_now()
      }

      send(pid, {:mcu_message, envelope})
      assert_receive {:outcome, :message, %{kind: "hand.raised"}}, 2000

      refute attached?(TestStub.rpc_order())
      assert [row] = participants(ctx.uid)
      assert row.joined_at == joined.joined_at
    end
  end

  describe "the leg is out" do
    test "a BYE is answered, the leg released, and the reason named", ctx do
      {pid, dialog} = start_in_mix(ctx.did)
      _drain = TestStub.rpc_order()

      send(pid, {:BYE, %{method: :BYE}, nil, dialog})
      assert_receive {:replied, 200, "OK", _fields, _req}, 2000
      assert_receive {:outcome, :caller_hung_up, %{reason: :bye}}, 2000

      assert wait_for(fn -> "DeleteParticipant" in TestStub.rpc_order() end)
      assert participants(ctx.uid) == []
    end

    test "a dialog that ends on its own carries why", ctx do
      {pid, dialog} = start_in_mix(ctx.did)

      send(pid, {:dialog_terminated, dialog, :timeout})
      assert_receive {:outcome, :caller_hung_up, %{reason: :timeout}}, 2000
    end

    test "a CANCEL around the answer: the teardown is ours, the 487 was not", ctx do
      {pid, dialog} = start_in_mix(ctx.did)

      send(pid, {:CANCEL, %{method: :CANCEL}, nil, dialog})
      assert_receive {:outcome, :cancelled, %{}}, 2000
      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end

    # P7/S1: the module only sends this once EVERY media of the leg has gone
    # silent, so one dead media does not get us here.
    test "media_timeout hangs up, and says whether the BYE was answered", ctx do
      {pid, dialog} = start_in_mix(ctx.did)

      send(pid, {:mcu_event, :media_timeout, :audio})
      assert_receive {:sent_request, :BYE, _req}, 2000

      send(pid, {200, %{}, nil, dialog})

      assert_receive {:outcome, :media_timeout, %{media: :audio, bye_answered: true}}, 2000
      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end

    test "the G3 idle backstop fires as an outcome, not as a silence", ctx do
      {pid, dialog} = start_in_mix(ctx.did, idle_timeout: 200)

      assert_receive {:sent_request, :BYE, _req}, 2000
      send(pid, {200, %{}, nil, dialog})
      assert_receive {:outcome, :idle_timeout, %{bye_answered: true}}, 2000
    end
  end

  describe "a dead media server, by either route" do
    # The module relays `:server_disconnected` because it watches the server on
    # behalf of every leg; the `:ms_event` is what our OWN media connection
    # reports. Both reach us and neither is guaranteed to be first.
    test "the module's route ends the call once, and says which route it was", ctx do
      {pid, dialog} = start_in_mix(ctx.did)

      send(pid, {:mcu_event, :server_disconnected})
      assert_receive {:sent_request, :BYE, _req}, 2000
      send(pid, {200, %{}, nil, dialog})

      assert_receive {:outcome, :mcu_lost, %{via: :mcu_event, bye_answered: true}}, 2000
    end

    test "the media connection's route does the same", ctx do
      {pid, dialog} = start_in_mix(ctx.did)

      send(pid, {:ms_event, self(), :server_disconnected})
      assert_receive {:sent_request, :BYE, _req}, 2000
      send(pid, {200, %{}, nil, dialog})

      assert_receive {:outcome, :mcu_lost, %{via: :ms_event, bye_answered: true}}, 2000
    end

    # Both routes fire for one dead server. The second one lands while we are
    # already hanging up, where the clause `on_events` would otherwise inject
    # turns it into a shutdown — and the outcome this teardown exists to report
    # would be lost.
    test "both routes together still end the call once, with its own outcome", ctx do
      {pid, dialog} = start_in_mix(ctx.did)

      send(pid, {:mcu_event, :server_disconnected})
      send(pid, {:ms_event, self(), :server_disconnected})
      assert_receive {:sent_request, :BYE, _req}, 2000
      send(pid, {200, %{}, nil, dialog})

      assert_receive {:outcome, :mcu_lost, %{via: :mcu_event}}, 2000
      refute_receive {:on_shutdown, :ran}, 300
      refute_receive {:outcome, :mcu_lost, _}, 300
    end
  end

  describe "a cooperative shutdown" do
    # DESIGN-SBB invariant 8: ending the scenario from inside the block would skip
    # the block where a script frees what the call reserved. The engine unwinds
    # the block and re-applies the shutdown as the transition the host state would
    # have written.
    test "reaching the block runs the HOST's on_shutdown", ctx do
      {pid, _dialog} = start_in_mix(ctx.did)

      send(pid, {:scenario_ctl, :shutdown, :kicked})
      assert_receive {:on_shutdown, :ran}, 2000
    end
  end
end
