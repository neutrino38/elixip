defmodule SIP.Test.PageScenarios do
  @moduledoc """
  The built-in page-mode scenarios, `UAC.Page` and `UAS.Page`
  (docs/design/chat-basic-plan.md, C7), against `SIP.Test.Transport.Mockup`
  peers — with the options elixipp's command line gives them, as config
  overrides.
  """
  use ExUnit.Case, async: false

  alias SIP.Test.Transport.Mockup

  @test_name :page_scenarios_test

  defmodule Recipient do
    @moduledoc """
    Answers each MESSAGE with `code`; with `challenge: true`, challenges one
    that carries no credentials with a 407 first. Reports every MESSAGE.
    """
    use SIP.Test.Peer

    @impl true
    def on_request(%{method: :MESSAGE} = req, state) do
      send(:page_scenarios_test, {:recipient_got, req})

      action =
        if Map.get(state, :challenge, false) and not Map.has_key?(req, :proxyauthorization),
          do: challenge(req, 407),
          else: reply(req, Map.get(state, :code, 200), "Answer", [], 0)

      {[action], state}
    end

    def on_request(req, state), do: default_request(req, state)
  end

  defmodule ChatUAS do
    @moduledoc "One UAS.Page instance per inbound MESSAGE, as elixipp's server mode spawns them."
    @behaviour SIP.Session.Chat

    @impl true
    def on_message(dialog_pid, req, _transaction_id) do
      {pid, _ref} =
        SIP.Scenario.Runner.spawn_uas_instance(UAS.Page,
          dialog_pid: dialog_pid,
          inbound_request: req,
          config_overrides: :persistent_term.get({__MODULE__, :overrides}, [])
        )

      {:accept, pid}
    end
  end

  setup_all do
    SIP.Test.AppEnv.preserve_proxy()
    :ok = SIP.Scenario.start_stack()
    :ok
  end

  setup do
    Process.register(self(), @test_name)
    :ok
  end

  @target "sip:bob@unit.test;unittest=page-bob"

  defp recipient(opts) do
    :ok = Mockup.set_peer(Mockup.instance!(@target), Recipient, opts)
  end

  # In a process of its own: the scenario reads its mailbox, and would take the
  # recipient's reports to the test for its own events.
  defp run_uac(overrides) do
    fn ->
      SIP.Scenario.Runner.run_instance(UAC.Page,
        config_overrides:
          [
            username: "alice",
            authusername: "alice",
            domain: "unit.test",
            proxyuri: @target,
            page_to: @target
          ] ++ overrides
      )
    end
    |> Task.async()
    |> Task.await(30_000)
  end

  describe "UAC.Page" do
    test "N pages at an interval, each checked against the expected code" do
      recipient(code: 202)

      assert :ok =
               run_uac(
                 page_body: "code 4321",
                 page_count: 3,
                 page_interval_ms: 50,
                 page_expect: 202,
                 page_expires: 120
               )

      for _ <- 1..3 do
        assert_receive {:recipient_got, req}
        assert SIP.Msg.Ops.body_string(req) == "code 4321"
        assert SIP.Msg.Ops.content_expires(req) == 120
        assert SIP.Msg.Ops.address_of_record(req, :from) == "alice@unit.test"
      end
    end

    test "a challenge is answered once, with the account's credentials" do
      recipient(challenge: true, code: 200)

      assert :ok = run_uac([])
      assert_receive {:recipient_got, first}
      refute Map.has_key?(first, :proxyauthorization)
      assert_receive {:recipient_got, second}
      assert %{"username" => "alice"} = second.proxyauthorization
    end

    test "an answer other than the expected one fails the run" do
      recipient(code: 480)
      assert {:error, reason} = run_uac([])
      assert reason =~ "got 480, expected 200"
    end
  end

  describe "UAS.Page" do
    test "answers with the chosen code, and reports the message without its text" do
      :persistent_term.put({ChatUAS, :overrides}, page_code: 415)
      on_exit(fn -> :persistent_term.erase({ChatUAS, :overrides}) end)
      :ok = SIP.Session.ConfigRegistry.set_chat_processing_module(ChatUAS)

      callid = inject_message("Rendez-vous jeudi")

      assert await_response(callid).response == 415
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp inject_message(body) do
    wire =
      "MESSAGE sip:bob@unit.test SIP/2.0\r\n" <>
        "Via: SIP/2.0/UDP 82.184.8.2:53936;branch=z9hG4bKpage1\r\n" <>
        "Max-Forwards: 69\r\n" <>
        "From: <sip:alice@unit.test>;tag=a1b2c3\r\n" <>
        "To: <sip:bob@unit.test>\r\n" <>
        "Call-ID: page-call-id\r\n" <>
        "CSeq: 1 MESSAGE\r\n" <>
        "Content-Type: text/plain\r\n" <>
        "Content-Length: #{byte_size(body)}\r\n\r\n" <> body

    {:ok, req} = SIPMsg.parse(wire, fn _, _, _, _ -> :ok end)
    callid = SIP.Msg.Ops.generate_from_or_to_tag()
    branch = "z9hG4bKpage" <> SIP.Msg.Ops.generate_from_or_to_tag()

    {:ok, uri} = SIP.Uri.parse("sip:bob@unit.test")
    ruri = SIP.Uri.set_uri_param(uri, "unittest", "page-sender")
    routed = SIP.Transport.Selector.select_transport(ruri)
    :ok = Mockup.attach_probe(routed.tp_pid)

    Mockup.inject(routed.tp_pid, %{
      req
      | ruri: ruri,
        callid: callid,
        via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"]
    })

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
