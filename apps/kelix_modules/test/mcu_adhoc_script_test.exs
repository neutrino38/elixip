defmodule Kelix.Mod.McuAdhocScriptTest do
  @moduledoc """
  The ad-hoc reference script (design `docs/design/mcu_module.md` §17.5): the first
  caller on a DID nobody booked creates the room, later callers join that same room,
  and the room goes away with its last participant — or with the call that made it, if
  nobody ever joined.

  Driven the way `mcu_call_test.exs` drives `mcu.exs`: real instances, real adapter,
  recording MCU transport.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Conference, Config}

  # The media servers the module drives now come from [mediaserver.pool.*], decoded
  # by Kelix.Config; the registry takes the resulting list directly so a test needs
  # no config file.
  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]

  @domain "example.com"
  @rec_port 52_014
  # the address the media server itself reports on StartReceiving (§16.5) —
  # what the answer must advertise, and no longer a config value
  @media_ip "203.0.113.12"

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

  setup_all do
    %{
      scenario:
        SIP.Scenario.Loader.load_file!(
          Path.expand("../../kelixip/scripts/mcu_adhoc.exs", __DIR__)
        )
    }
  end

  setup do
    {:ok, config} =
      Config.parse(%{
        "did_range" => "8000-8009",
        "audio_codecs" => ["PCMA", "PCMU"]
      })

    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), %{"StartReceiving" => {:ok, [@rec_port, @media_ip]}}),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_until(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)
    _setup_rpcs = TestStub.rpc_order()
    :ok
  end

  defp wait_until(fun, attempts \\ 200) do
    case fun.() do
      truthy when truthy not in [nil, false] ->
        truthy

      _ when attempts > 0 ->
        Process.sleep(10)
        wait_until(fun, attempts - 1)

      _ ->
        flunk("condition never became true")
    end
  end

  defp invite(did) do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: did, domain: @domain},
      from: %SIP.Uri{
        userpart: "caller#{System.unique_integer([:positive])}",
        domain: "phone.test"
      },
      to: %SIP.Uri{userpart: did, domain: @domain},
      callid: "call-#{System.unique_integer([:positive])}",
      cseq: [1, :INVITE],
      body: @offer,
      contenttype: "application/sdp"
    }
  end

  defp start_call(scenario, did) do
    {:ok, dialog} = MockDialog.start_link(self())
    req = invite(did)

    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(scenario,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain]
      )

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    send(pid, {:INVITE, req, nil, dialog})
    {pid, dialog}
  end

  defp rooms(), do: Mcu.conferences(@domain)

  defp participants(uid) do
    case Mcu.conference(uid) do
      {:ok, conf} -> Conference.participants(conf)
      :error -> []
    end
  end

  test "the first caller creates the room and joins it", ctx do
    assert rooms() == []

    {pid, dialog} = start_call(ctx.scenario, "8042")
    assert_receive {:replied, 180, "Ringing", _fields, _req}, 2000
    assert_receive {:replied, 200, _reason, _fields, _req}, 2000

    assert [room] = rooms()
    assert room.did == "8042"
    assert room.name == "Ad-hoc 8042"
    # the ad-hoc options: it goes with its last participant
    assert room.destroy_when_empty == true

    send(pid, {:ACK, %{method: :ACK}, nil, dialog})
    assert wait_until(fn -> Enum.find(participants(room.uid), &(&1.state == :connected)) end)
  end

  test "a second caller joins the same room, and does not create a second one", ctx do
    {pid1, dialog1} = start_call(ctx.scenario, "8042")
    assert_receive {:replied, 200, _reason, _fields, _req}, 2000
    send(pid1, {:ACK, %{method: :ACK}, nil, dialog1})
    assert [room] = rooms()
    assert wait_until(fn -> length(participants(room.uid)) == 1 end)
    # everything the first call did, including its CreateConference
    _first_call = TestStub.rpc_order()

    {pid2, dialog2} = start_call(ctx.scenario, "8042")
    assert_receive {:replied, 200, _reason, _fields, _req}, 2000
    send(pid2, {:ACK, %{method: :ACK}, nil, dialog2})

    # one room, two legs…
    assert [second] = rooms()
    assert second.uid == room.uid
    assert wait_until(fn -> length(participants(room.uid)) == 2 end)
    # …and the second caller created nothing: it joined
    refute "CreateConference" in TestStub.rpc_order()
  end

  test "the room goes away with its last participant", ctx do
    {pid, dialog} = start_call(ctx.scenario, "8042")
    assert_receive {:replied, 200, _reason, _fields, _req}, 2000
    send(pid, {:ACK, %{method: :ACK}, nil, dialog})
    assert [room] = rooms()
    assert wait_until(fn -> Enum.find(participants(room.uid), &(&1.state == :connected)) end)

    send(pid, {:BYE, %{method: :BYE}, nil, dialog})
    assert_receive {:replied, 200, "OK", _fields, _req}, 2000

    assert wait_until(fn -> rooms() == [] end)
    assert Mcu.lookup_did(@domain, "8042") == :error
  end

  test "a caller who hangs up before joining takes the empty room with it (§17.3)", ctx do
    {pid, _dialog} = start_call(ctx.scenario, "8042")
    assert_receive {:replied, 200, _reason, _fields, _req}, 2000
    assert [room] = rooms()
    # it never ACKed: the leg is ringing, nobody is in the mix
    assert [%{state: :ringing}] = participants(room.uid)

    Process.exit(pid, :kill)

    # the room was this instance's: with no participant left it goes too, rather than
    # sitting on the media server until someone notices
    assert wait_until(fn -> rooms() == [] end)
  end

  test "two callers arriving together produce one room", ctx do
    calls =
      for _ <- 1..4 do
        {:ok, dialog} = MockDialog.start_link(self())
        req = invite("8042")

        {pid, _ref} =
          SIP.Scenario.Runner.spawn_uas_instance(ctx.scenario,
            dialog_pid: dialog,
            inbound_request: req,
            config_overrides: [domain: @domain]
          )

        {pid, dialog, req}
      end

    # every INVITE at once: the atomic ensure_conference/3 is what keeps this to one
    for {pid, dialog, req} <- calls, do: send(pid, {:INVITE, req, nil, dialog})

    for _ <- calls, do: assert_receive({:replied, 200, _reason, _fields, _req}, 3000)

    assert [room] = rooms()
    assert room.did == "8042"

    for {pid, dialog, _req} <- calls, do: send(pid, {:ACK, %{method: :ACK}, nil, dialog})
    assert wait_until(fn -> length(participants(room.uid)) == 4 end)

    for {pid, _dialog, _req} <- calls,
        do: if(Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}))
  end

  test "mcu.exs still answers 404 on the same unknown DID (§17.4)" do
    booked = SIP.Scenario.Loader.load_file!(Path.expand("../../kelixip/scripts/mcu.exs", __DIR__))

    {_pid, _dialog} = start_call(booked, "8042")

    assert_receive {:replied, 404, "Not Found", _fields, _req}, 2000
    # the module created nothing by itself: that is the whole distinction
    assert rooms() == []
  end
end
