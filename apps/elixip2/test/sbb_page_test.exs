defmodule SIP.Test.SbbPage do
  @moduledoc """
  `SBB.Page` — one inbound MESSAGE fanned out to every device of the recipient,
  one outcome (docs/design/chat-basic-plan.md, C4).

  Each device is a `SIP.Test.Transport.Mockup` instance of its own
  (`;unittest=alice-phone`, `;unittest=alice-desk`…) behind a peer answering
  a fixed code after a fixed delay, or never.
  """
  use ExUnit.Case, async: false

  alias SIP.Test.Transport.Mockup

  @test_name :sbb_page_test

  # ── Fixtures ────────────────────────────────────────────────────────────────

  defmodule Device do
    @moduledoc "A device answering every MESSAGE with `code` after `delay` ms; `code: nil` never answers."
    use SIP.Test.Peer

    @impl true
    def on_request(%{method: :MESSAGE} = req, state) do
      send(:sbb_page_test, {:device_got, state.name, req})

      case state.code do
        nil -> {[], state}
        code -> {[reply(req, code, "Answer", [], Map.get(state, :delay, 0))], state}
      end
    end

    def on_request(req, state), do: default_request(req, state)
  end

  defmodule ChatUAS do
    @moduledoc "One instance of the relay per inbound out-of-dialog MESSAGE."
    @behaviour SIP.Session.Chat

    def serve(peer) do
      :persistent_term.put({__MODULE__, :peer}, peer)
      :ok = SIP.Session.ConfigRegistry.set_chat_processing_module(__MODULE__)
    end

    @impl true
    def on_message(dialog_pid, req, _transaction_id) do
      {pid, _ref} =
        SIP.Scenario.Runner.spawn_uas_instance(SIP.Test.SbbPage.Relay,
          dialog_pid: dialog_pid,
          inbound_request: req
        )

      send(:sbb_page_test, {:instance, inspect(pid)})
      {:accept, pid}
    end
  end

  # The reference relay, reduced: page every device, answer the sender with
  # what came back, and stay a moment to show that no late answer leaks in.
  defmodule Relay do
    @moduledoc false
    use SIP.Scenario
    use SBB.Page
    uas(:message)
    config(domain: "unit.test", debug: true)

    state initial_state do
      on_events do
        {:MESSAGE, _req, _trans, _dlg} -> goto(relay)
      after
        5_000 -> scenario_failure("no MESSAGE")
      end
    end

    state relay do
      page(args: %{peer: :persistent_term.get({SIP.Test.SbbPage.ChatUAS, :peer}), timeout: 3_000})

      on_events do
        {:page, :delivered, %{code: code} = data} ->
          reply_message(code)
          send(:sbb_page_test, {:outcome, :delivered, data})
          goto(linger)

        {:page, :refused, %{code: code} = data} ->
          reply_message(code)
          send(:sbb_page_test, {:outcome, :refused, data})
          goto(linger)

        {:page, :unreachable, data} ->
          reply_message(480)
          send(:sbb_page_test, {:outcome, :unreachable, data})
          goto(linger)
      end
    end

    state linger do
      on_events do
        {:page, outcome, data} ->
          send(:sbb_page_test, {:leaked, outcome, data})
          stay("leaked")
      after
        600 -> scenario_success("relayed")
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

  # The relay's journal comes here, unrendered, rather than to a file in the
  # working directory.
  setup do
    Process.register(self(), @test_name)
    Application.put_env(:elixip2, :sequence_output, {__MODULE__, :journal})
    :ok
  end

  def journal(events, meta) do
    if pid = Process.whereis(@test_name), do: send(pid, {:journal, to_string(meta.pid), events})
    :kept
  end

  # ── The reading of the answers ──────────────────────────────────────────────

  describe "SBB.Page.decide/2" do
    test "a 2xx other than 202 wins with devices still silent" do
      assert SBB.Page.decide(%{"a" => 200}, 2) == {:delivered, 200}
    end

    test "a 202 waits for every device, and is not upgraded" do
      assert SBB.Page.decide(%{"a" => 202}, 1) == :wait
      assert SBB.Page.decide(%{"a" => 202, "b" => 480}, 0) == {:delivered, 202}
      assert SBB.Page.decide(%{"a" => 202, "b" => 200}, 0) == {:delivered, 200}
    end

    test "a refusal outranks not-now, and a 6xx outranks a 4xx" do
      assert SBB.Page.decide(%{"a" => 415, "b" => 480}, 0) == {:refused, 415}
      assert SBB.Page.decide(%{"a" => 415, "b" => 603}, 0) == {:refused, 603}
    end

    test "failures and not-now codes are unreachable" do
      assert SBB.Page.decide(%{"a" => 408, "b" => {:failed, :timeout}, "c" => 503}, 0) ==
               {:unreachable, nil}

      assert SBB.Page.decide(%{}, 0) == {:unreachable, nil}
    end

    test "served: every device that gave a final verdict" do
      served = SBB.Page.served(%{"a" => 200, "b" => 603, "c" => 480, "d" => {:failed, :x}})
      assert Enum.sort(served) == ["a", "b"]
    end
  end

  describe "SBB.Page.devices/1" do
    test "flattens the q groups of a registrar peer, one entry per device" do
      {:ok, phone} = SIP.Uri.parse(~s(<sip:alice@10.0.0.1>;+sip.instance="<urn:uuid:AB>"))
      {:ok, moved} = SIP.Uri.parse(~s(<sip:alice@10.0.0.9>;+sip.instance="<urn:uuid:ab>"))
      {:ok, desk} = SIP.Uri.parse("sip:alice@10.0.0.2")

      peer = %SIP.B2bua.Peer{uris: [[phone, moved], [desk]], fork: :parallel}

      assert [{"urn:uuid:ab", ^phone}, {"sip:alice@10.0.0.2", ^desk}] = SBB.Page.devices(peer)
    end

    test "a provider has no device list" do
      assert SBB.Page.devices(%SIP.B2bua.Peer{provider: SomeQueue}) == []
    end
  end

  # ── The fan-out, end to end ─────────────────────────────────────────────────

  test "200 and 480: the sender gets the 200" do
    # The 200 concludes at once, so the 480 must land first to be in `answers`.
    devices(phone: [code: 200, delay: 100], desk: [code: 480])
    callid = inject_message()

    assert_receive {:outcome, :delivered, %{code: 200, served: served, answers: answers}}, 3_000
    assert await_response(callid).response == 200
    assert served == [key(:phone)]
    assert answers == %{key(:phone) => 200, key(:desk) => 480}

    # Both devices got the message, rebuilt: the sender's identity, a
    # transaction of its own each.
    assert_receive {:device_got, :phone, to_phone}
    assert_receive {:device_got, :desk, to_desk}
    assert SIP.Msg.Ops.from_username(to_phone) == "alice"
    assert SIP.Msg.Ops.body_string(to_desk) == "Rendez-vous jeudi"
    refute to_phone.callid == to_desk.callid
    refute to_phone.callid == callid
  end

  test "202 and 480: a 202, not upgraded" do
    devices(phone: [code: 202], desk: [code: 480, delay: 100])
    callid = inject_message()

    assert_receive {:outcome, :delivered, %{code: 202, served: [_phone]}}, 3_000
    assert await_response(callid).response == 202
  end

  test "603 and 480: refused, with the 603" do
    devices(phone: [code: 603], desk: [code: 480])
    callid = inject_message()

    assert_receive {:outcome, :refused, %{code: 603, served: served}}, 3_000
    assert served == [key(:phone)]
    assert await_response(callid).response == 603
  end

  test "three 480s: unreachable" do
    devices(phone: [code: 480], desk: [code: 480], tablet: [code: 480])
    callid = inject_message()

    assert_receive {:outcome, :unreachable, %{served: [], answers: answers}}, 3_000
    assert map_size(answers) == 3
    assert await_response(callid).response == 480
  end

  test "a device that never answers does not delay the 200 the other one earned" do
    devices(phone: [code: 200, delay: 50], desk: [code: nil])
    started = System.monotonic_time(:millisecond)
    _callid = inject_message()

    assert_receive {:outcome, :delivered, %{code: 200, answers: answers}}, 3_000
    assert System.monotonic_time(:millisecond) - started < 1_000
    assert answers == %{key(:phone) => 200}
  end

  test "an answer arriving after the outcome is not reported" do
    devices(phone: [code: 200], desk: [code: 480, delay: 200])
    _callid = inject_message()

    assert_receive {:outcome, :delivered, %{code: 200}}, 3_000
    refute_receive {:leaked, _outcome, _data}, 800
  end

  test "each device's page is a lane of its own in the journal, labelled with the device" do
    devices(phone: [code: 200], desk: [code: 480])
    _callid = inject_message()

    assert_receive {:instance, instance}, 1_000
    assert_receive {:outcome, :delivered, _data}, 3_000
    # An earlier test's instance may still be finishing: its journal is not this one.
    assert_receive {:journal, ^instance, events}, 3_000

    lanes =
      for %{kind: :message, party: "page " <> device, lane: lane} <- events,
          into: %{},
          do: {device, lane}

    assert Map.keys(lanes) |> Enum.sort() == ["alice@desk.unit.test", "alice@phone.unit.test"]
    assert lanes["alice@desk.unit.test"] != lanes["alice@phone.unit.test"]
    assert Enum.all?(events, &(&1[:body] == nil or not (&1.body =~ "Rendez-vous")))
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # One Mockup instance per device, and the relay's peer listing them all.
  defp devices(specs) do
    uris =
      for {name, opts} <- specs do
        uri = "sip:alice@#{name}.unit.test;unittest=alice-#{name}"
        :ok = Mockup.set_peer(Mockup.instance!(uri), Device, [name: name] ++ opts)
        uri
      end

    ChatUAS.serve(%SIP.B2bua.Peer{uris: [uris], fork: :parallel})
  end

  defp key(name), do: "sip:alice@#{name}.unit.test;unittest=alice-#{name}"

  defp inbound_wire do
    body = "Rendez-vous jeudi"

    "MESSAGE sip:alice@unit.test SIP/2.0\r\n" <>
      "Via: SIP/2.0/UDP 82.184.8.2:53936;branch=z9hG4bKinjected1\r\n" <>
      "Max-Forwards: 69\r\n" <>
      "From: <sip:alice@unit.test>;tag=a1b2c3\r\n" <>
      "To: <sip:alice@unit.test>\r\n" <>
      "Call-ID: old-call-id\r\n" <>
      "CSeq: 77 MESSAGE\r\n" <>
      "Content-Type: text/plain;charset=UTF-8\r\n" <>
      "Content-Length: #{byte_size(body)}\r\n\r\n" <> body
  end

  # Inject an out-of-dialog MESSAGE, on a mockup instance of its own.
  defp inject_message do
    {:ok, req} = SIPMsg.parse(inbound_wire(), fn _, _, _, _ -> :ok end)
    callid = SIP.Msg.Ops.generate_from_or_to_tag()
    branch = "z9hG4bKinjected" <> SIP.Msg.Ops.generate_from_or_to_tag()

    {:ok, uri} = SIP.Uri.parse("sip:alice@unit.test")
    ruri = SIP.Uri.set_uri_param(uri, "unittest", "sender")
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
end
