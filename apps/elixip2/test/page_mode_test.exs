defmodule SIP.Test.PageMode do
  @moduledoc """
  Page-mode messaging verbs (docs/design/chat-basic-plan.md, C3): a scenario
  answers the MESSAGE that created it (`reply_message/2`) and sends one that
  belongs to no dialog (`send_page/4`), whose answer comes back as a
  `{:page, …}` outcome.

  Everything goes through `SIP.Test.Transport.Mockup`: a `;unittest=loop` peer
  turns every MESSAGE the stack sends into an inbound one, so a UAC scenario and
  a UAS scenario page each other inside one VM.
  """
  use ExUnit.Case, async: false

  alias SIP.Scenario.SequenceDiagram
  alias SIP.Test.Transport.Mockup

  @test_name :page_mode_test

  # ── Fixtures ────────────────────────────────────────────────────────────────

  defmodule Loopback do
    @moduledoc """
    The far end as the local stack itself: a MESSAGE sent here comes back in as
    a new inbound request, and the answer to that one goes back out as the
    answer to the first. Call-ID and branch are redrawn on the way in, or the
    inbound transaction and dialog would be taken for the outbound ones.
    """
    use SIP.Test.Peer

    @impl true
    def on_request(%{method: :MESSAGE} = req, state) do
      callid = "loop-" <> req.callid
      branch = SIP.Msg.Ops.generate_branch_value()
      via = Enum.map(req.via, &Regex.replace(~r/branch=[^;,\s]+/, &1, "branch=" <> branch))
      {[{:inject, %{req | callid: callid, via: via}, 0}], Map.put(state, callid, req)}
    end

    def on_request(req, state), do: default_request(req, state)

    @impl true
    def on_response(%{callid: callid} = rsp, state) do
      case Map.get(state, callid) do
        %{} = orig when rsp.response >= 200 ->
          back = %{rsp | callid: orig.callid, via: orig.via, from: orig.from, cseq: orig.cseq}
          {[{:inject, back, 0}], Map.delete(state, callid)}

        _provisional_or_unknown ->
          {[], state}
      end
    end
  end

  defmodule Recipient do
    @moduledoc "A device that accepts every MESSAGE with a 200."
    use SIP.Test.Peer

    @impl true
    def on_request(%{method: :MESSAGE} = req, state), do: {[reply(req, 200, "OK", [], 0)], state}
    def on_request(req, state), do: default_request(req, state)
  end

  defmodule ChatUAS do
    @moduledoc "One instance of the registered scenario per inbound out-of-dialog MESSAGE."
    @behaviour SIP.Session.Chat

    def serve(module) do
      :persistent_term.put({__MODULE__, :scenario}, module)
      :ok = SIP.Session.ConfigRegistry.set_chat_processing_module(__MODULE__)
    end

    @impl true
    def on_message(dialog_pid, req, _transaction_id) do
      module = :persistent_term.get({__MODULE__, :scenario})

      {pid, _ref} =
        SIP.Scenario.Runner.spawn_uas_instance(module,
          dialog_pid: dialog_pid,
          inbound_request: req
        )

      send(:page_mode_test, {:instance, inspect(pid)})
      {:accept, pid}
    end
  end

  defmodule Pager do
    @moduledoc false
    use SIP.Scenario
    config(username: "alice", domain: "unit.test")

    state initial_state do
      send_page("sip:bot@unit.test;unittest=loop", "hello bot", "text/plain",
        headers: [{"Subject", "greetings"}]
      )

      goto(wait_answer)
    end

    state wait_answer do
      on_events do
        {:page, :answered, %{code: 202}} -> scenario_success("delivered")
        {:page, :answered, %{code: code}} -> scenario_failure("answered #{code}")
        {:page, :failed, %{reason: reason}} -> scenario_failure("failed #{inspect(reason)}")
      after
        5_000 -> scenario_failure("no answer")
      end
    end
  end

  defmodule Bot do
    @moduledoc false
    use SIP.Scenario
    uas(:message)

    state initial_state do
      goto(wait_message)
    end

    state wait_message do
      on_events do
        {:MESSAGE, req, _trans, _dlg} ->
          send(:page_mode_test, {:bot_got, req})
          reply_message(202)
          scenario_success("answered")
      after
        5_000 -> scenario_failure("no MESSAGE")
      end
    end
  end

  # Answers the MESSAGE, then carries it on to Carol. `debug: true` keeps a
  # journal, written as a sequence diagram when the instance ends.
  defmodule Forwarder do
    @moduledoc false
    use SIP.Scenario
    uas(:message)
    config(domain: "unit.test", debug: true)

    state initial_state do
      goto(wait_message)
    end

    state wait_message do
      on_events do
        {:MESSAGE, _req, _trans, _dlg} ->
          reply_message(202)
          send_page("sip:carol@unit.test;unittest=carol", last_uas_req())
          goto(wait_delivery)
      after
        5_000 -> scenario_failure("no MESSAGE")
      end
    end

    state wait_delivery do
      on_events do
        {:page, :answered, %{code: code}} ->
          send(:page_mode_test, {:forwarded, code})
          scenario_success("forwarded")

        {:page, :failed, %{reason: reason}} ->
          send(:page_mode_test, {:forward_failed, reason})
          scenario_failure("not forwarded")
      after
        5_000 -> scenario_failure("no answer from carol")
      end
    end
  end

  setup_all do
    SIP.Test.AppEnv.preserve_proxy()
    SIP.Test.AppEnv.preserve([:sequence_output])
    :ok = SIP.Scenario.start_stack()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  setup do
    Process.register(self(), @test_name)
    Application.delete_env(:elixip2, :sequence_output)
    :ok
  end

  # ── page_request/2 ──────────────────────────────────────────────────────────

  describe "SIP.MsgTemplate.page_request/2" do
    setup do
      {:ok, received} = SIPMsg.parse(inbound_wire(), fn _, _, _, _ -> :ok end)
      %{received: received}
    end

    test "rebuilds: identities, content and allowlisted headers, nothing of the transaction",
         %{received: received} do
      req = SIP.MsgTemplate.page_request(received, ruri: "sip:bob@10.0.0.9:5070")
      out = SIPMsg.serialize(%{req | callid: "new-call"} |> Map.put(:cseq, [1, :MESSAGE]))

      assert req.method == :MESSAGE
      assert to_string(req.ruri) == "sip:bob@10.0.0.9:5070"
      assert req.from.userpart == "alice"
      refute Map.has_key?(req.from.hparams, "tag")
      refute Map.has_key?(req.to.hparams, "tag")
      assert req.to.userpart == "bob"
      assert req.body == "Rendez-vous jeudi"
      assert req.contenttype == "text/plain;charset=UTF-8"

      refute Map.has_key?(req, :via)
      refute Map.has_key?(req, :route)
      refute Map.has_key?(req, :contact)
      refute Map.has_key?(req, :cseq)
      assert req.callid == nil

      assert out =~ "Subject: jeudi"
      assert out =~ "Conversation-ID: conv-42"
      refute out =~ "X-Private"
      refute out =~ "old-call-id"
    end

    test "writes the arrival time as a Date header", %{received: received} do
      {:ok, at, 0} = DateTime.from_iso8601("2026-09-29T14:05:09Z")
      req = SIP.MsgTemplate.page_request(received, date: at)
      assert req["Date"] == "Tue, 29 Sep 2026 14:05:09 GMT"
    end

    test "composes from a bare map, addressed to its To" do
      req =
        SIP.MsgTemplate.page_request(%{
          from: "sip:alice@unit.test",
          to: "sip:bob@unit.test",
          contenttype: "text/plain",
          body: "hi"
        })

      assert to_string(req.ruri) == "sip:bob@unit.test"
      assert req.contentlength == 2
      refute Map.has_key?(req, "Date")
    end
  end

  # ── The verbs, end to end ───────────────────────────────────────────────────

  test "a UAC scenario pages a UAS scenario, which answers it" do
    loop = Mockup.instance!("sip:mockup@unit.test;unittest=loop")
    :ok = Mockup.set_peer(loop, Loopback)
    ChatUAS.serve(Bot)

    assert Pager.run(false) == :ok

    assert_receive {:bot_got, req}, 1_000
    assert SIP.Msg.Ops.body_string(req) == "hello bot"
    assert SIP.Msg.Ops.from_username(req) == "alice"
    assert SIP.Msg.Ops.message_kind(req) == :im
    assert Enum.any?(req, fn {k, v} -> k == "Subject" and v == "greetings" end)
  end

  test "a UAS scenario carries the MESSAGE it answered on, rebuilt" do
    carol = Mockup.instance!("sip:mockup@unit.test;unittest=carol")
    :ok = Mockup.set_peer(carol, Recipient)
    :ok = Mockup.attach_probe(carol)
    ChatUAS.serve(Forwarder)

    callid = inject_message("fwd")
    assert await_response(callid).response == 202
    assert_receive {:instance, instance}, 1_000

    assert_receive {:sip_mockup, {:request_sent, :MESSAGE, out}}, 2_000
    assert_receive {:forwarded, 200}, 2_000

    # The sender's identity, a transaction of its own.
    assert SIP.Msg.Ops.from_username(out) == "alice"
    assert SIP.Msg.Ops.to_username(out) == "fwd"
    assert out.ruri.userpart == "carol"
    assert out.callid != callid
    assert [_seq, :MESSAGE] = out.cseq
    assert out.cseq != [77, :MESSAGE]
    refute Map.has_key?(out, :route)
    refute Enum.any?(out.via, &String.contains?(&1, "z9hG4bKinjected"))
    assert SIP.Msg.Ops.body_string(out) == "Rendez-vous jeudi"
    assert Enum.any?(out, fn {k, v} -> k == "Subject" and v == "jeudi" end)
    refute Enum.any?(out, fn {k, _v} -> k == "X-Private" end)

    # The journal holds both transactions, the text in neither.
    path = SequenceDiagram.filename(%{scenario: inspect(Forwarder), pid: instance})
    on_exit(fn -> File.rm(path) end)
    assert eventually(fn -> File.exists?(path) end)
    content = File.read!(path)

    assert content =~ ~r/-> local : \+\d+ms MESSAGE #77/
    assert content =~ ~r/local --> \w+ : \+\d+ms 202 [^\/]*\/ 77 MESSAGE/
    assert content =~ ~r/local -> \w+ : \+\d+ms MESSAGE #\d+/
    assert content =~ ~r/\w+ --> local : \+\d+ms 200 OK \/ \d+ MESSAGE/
    refute content =~ "Rendez-vous"
  end

  test "a page whose request cannot leave is reported as failed" do
    defmodule Unroutable do
      @moduledoc false
      use SIP.Scenario
      config(username: "alice", domain: "unit.test")

      state initial_state do
        send_page("sip:nobody@unresolvable.invalid", "x", "text/plain")
        goto(wait_answer)
      end

      state wait_answer do
        on_events do
          {:page, :failed, %{to: to}} ->
            send(:page_mode_test, {:failed_to, to})
            scenario_success("failed")

          {:page, :answered, %{code: code}} ->
            send(:page_mode_test, {:answered, code})
            scenario_success("answered")
        after
          40_000 -> scenario_failure("no outcome")
        end
      end
    end

    assert Unroutable.run(false) == :ok

    receive do
      {:failed_to, to} -> assert to == "sip:nobody@unresolvable.invalid"
      # A resolver that answers but a destination that does not: RFC 3261
      # §8.1.3.1 reports it as a 503 (or a 408 on timeout).
      {:answered, code} -> assert code in [408, 503]
    after
      1_000 -> flunk("no outcome reported")
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp inbound_wire(user \\ "bob") do
    body = "Rendez-vous jeudi"

    "MESSAGE sip:#{user}@unit.test SIP/2.0\r\n" <>
      "Via: SIP/2.0/UDP 82.184.8.2:53936;branch=z9hG4bKinjected1\r\n" <>
      "Route: <sip:proxy.unit.test;lr>\r\n" <>
      "Max-Forwards: 69\r\n" <>
      "From: <sip:alice@unit.test>;tag=a1b2c3\r\n" <>
      "To: <sip:#{user}@unit.test>\r\n" <>
      "Call-ID: old-call-id\r\n" <>
      "CSeq: 77 MESSAGE\r\n" <>
      "Contact: <sip:alice@82.184.8.2:53936>\r\n" <>
      "Subject: jeudi\r\n" <>
      "Conversation-ID: conv-42\r\n" <>
      "X-Private: do-not-forward\r\n" <>
      "Content-Type: text/plain;charset=UTF-8\r\n" <>
      "Content-Length: #{byte_size(body)}\r\n\r\n" <> body
  end

  # Inject an out-of-dialog MESSAGE for `user`, on a mockup instance of its own.
  defp inject_message(user) do
    {:ok, req} = SIPMsg.parse(inbound_wire(user), fn _, _, _, _ -> :ok end)
    callid = SIP.Msg.Ops.generate_from_or_to_tag()
    branch = "z9hG4bKinjected" <> SIP.Msg.Ops.generate_from_or_to_tag()

    {:ok, uri} = SIP.Uri.parse("sip:#{user}@unit.test")
    ruri = SIP.Uri.set_uri_param(uri, "unittest", "inj")
    routed = SIP.Transport.Selector.select_transport(ruri)
    :ok = Mockup.attach_probe(routed.tp_pid)

    req = %{
      req
      | ruri: ruri,
        callid: callid,
        via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"]
    }

    Mockup.inject(routed.tp_pid, req)
    callid
  end

  defp await_response(callid) do
    receive do
      {:sip_mockup, {:response_sent, code, %{callid: ^callid} = rsp}} when code >= 200 -> rsp
      {:sip_mockup, {:response_sent, _code, %{callid: ^callid}}} -> await_response(callid)
    after
      3_000 -> flunk("no final response to the MESSAGE on call #{callid}")
    end
  end

  defp eventually(fun, tries \\ 50) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true -> Process.sleep(50) && eventually(fun, tries - 1)
    end
  end
end
