defmodule Kelix.Mod.McuMessageTest do
  @moduledoc """
  The collaboration channel of design `docs/design/DESIGN-MCU.md` (P10): a
  participant's script addressing its peers' scripts.

  Every leg here is admitted by **its own process**, because that process is what the
  registry records as the leg's scenario and therefore what the bus delivers to — a
  test that admitted both legs from the test process could not tell `:others` from
  `:all`. The guards of §20.5 are asserted one by one: they are the whole feature.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Adapter, Client, Config}

  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]
  @domain "example.com"
  @rec_port 52_014
  @media_ip "203.0.113.12"
  @kinds ["hand.raised", "floor.request"]

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

  setup do
    start_mcu()
  end

  defp start_mcu(opts \\ []) do
    block =
      Map.merge(
        %{"did_range" => "8000-8009", "message_kinds" => @kinds},
        Keyword.get(opts, :block, %{})
      )

    {:ok, config} = Config.parse(block)
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport:
         TestStub.transport(self(), %{
           "StartReceiving" => {:ok, [@rec_port, @media_ip]},
           # a distinct id per leg, unlike the stub's fixed 7: this file addresses one
           # participant *by* its id, which two legs sharing one id cannot express
           "CreateParticipant" => fn _params ->
             {:ok, [:erlang.unique_integer([:positive, :monotonic])]}
           end
         }),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    until!(fn -> match?({:ok, %{status: :up}}, Mcu.mediaserver("mcu1")) end)

    {:ok, %{uid: uid}} = Mcu.handle_control("conference.create", %{"domain" => @domain})
    _ = TestStub.rpc_order()
    %{uid: uid}
  end

  # A leg whose scenario is a process of its own, forwarding everything it receives to
  # the test as {:leg, user, message} — so an assertion can name *which* leg got what.
  # `accept?: false` leaves the leg undeclared, which is what G-2 is about.
  defp join(uid, user, opts \\ []) do
    test = self()
    drain? = Keyword.get(opts, :drain, true)

    pid =
      spawn_link(fn ->
        {:ok, conf} = Mcu.conference(uid)
        {:ok, ^conf, part} = Mcu.admit(@domain, invite(conf, user))
        Kernel.send(test, {:admitted, user, part})
        if drain?, do: forward(test, user), else: Process.sleep(:infinity)
      end)

    part =
      receive do
        {:admitted, ^user, part} -> part
      after
        2_000 -> flunk("leg #{user} was never admitted")
      end

    if Keyword.get(opts, :attach, true), do: attach(part)
    if Keyword.get(opts, :accept, true), do: :ok = Mcu.accept_messages(part)

    %{pid: pid, part: part, user: user}
  end

  defp attach(part) do
    {:ok, conf} = Mcu.conference(part.conf_uid)
    {:ok, client} = Adapter.connect("mcu://" <> conf.mcu)

    {:ok, conn} =
      Adapter.create_peer_connection(client, self(), mcu_participant: part, media: :audio)

    {:ok, _answer} = Adapter.set_remote_offer(conn, @offer)
    :ok = Mcu.attach(part)
    _ = TestStub.rpc_order()
    :ok
  end

  defp forward(test, user) do
    receive do
      message ->
        Kernel.send(test, {:leg, user, message})
        forward(test, user)
    end
  end

  defp invite(conf, user) do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: conf.did, domain: @domain},
      from: %SIP.Uri{userpart: user, domain: "phone.example.com"},
      to: %SIP.Uri{userpart: conf.did, domain: @domain}
    }
  end

  defp received(user) do
    receive do
      {:leg, ^user, {:mcu_message, envelope}} -> {:ok, envelope}
    after
      200 -> :none
    end
  end

  # ── addressing (§20.4) ───────────────────────────────────────────────────────

  describe "targets" do
    setup ctx do
      %{alice: join(ctx.uid, "alice"), bob: join(ctx.uid, "bob")}
    end

    test ":others reaches the peers and not the sender", ctx do
      assert {:ok, %{delivered: 1, skipped: []}} =
               Mcu.send_message(ctx.alice.part, :others, "hand.raised", "")

      assert {:ok, %{from: %{part_id: _}}} = received("bob")
      assert received("alice") == :none
    end

    test ":all includes the sender", ctx do
      assert {:ok, %{delivered: 2}} = Mcu.send_message(ctx.alice.part, :all, "hand.raised", "")
      assert {:ok, _} = received("alice")
      assert {:ok, _} = received("bob")
    end

    test "one participant, by part_id and by name", ctx do
      part_id = ctx.bob.part |> Mcu.participant() |> elem(1) |> Map.get(:part_id)

      assert {:ok, %{delivered: 1}} =
               Mcu.send_message(ctx.alice.part, {:part_id, part_id}, "hand.raised", "")

      assert {:ok, _} = received("bob")

      # by its user part, which is what a human types
      assert {:ok, %{delivered: 1}} =
               Mcu.send_message(ctx.alice.part, {:name, "bob"}, "hand.raised", "")

      assert {:ok, _} = received("bob")
      assert received("alice") == :none
    end

    test "an unknown target is refused, and nothing is delivered", ctx do
      assert {:error, :no_such_target} =
               Mcu.send_message(ctx.alice.part, {:part_id, 999}, "hand.raised", "")

      assert {:error, :no_such_target} =
               Mcu.send_message(ctx.alice.part, {:name, "carol"}, "hand.raised", "")

      assert received("bob") == :none
    end

    test "a handle of another conference cannot address this one", ctx do
      {:ok, %{uid: other_uid}} =
        Mcu.handle_control("conference.create", %{"domain" => "other.example.com"})

      ghost = %{ctx.alice.part | conf_uid: other_uid}

      assert {:error, :no_such_participant} =
               Mcu.send_message(ghost, :all, "hand.raised", "")

      assert received("bob") == :none
    end
  end

  # ── the guards (§20.5) ───────────────────────────────────────────────────────

  describe "guards" do
    setup ctx do
      %{alice: join(ctx.uid, "alice")}
    end

    test "G-2: a leg that declared nothing is skipped, not delivered to", ctx do
      _bob = join(ctx.uid, "bob", accept: false)

      assert {:ok, %{delivered: 0, skipped: [%{reason: :not_accepted}]}} =
               Mcu.send_message(ctx.alice.part, :others, "hand.raised", "")

      assert received("bob") == :none
    end

    test "G-3: a leg whose mailbox is backed up is skipped", ctx do
      # a leg that never drains: exactly the wedged scenario the guard exists for
      bob = join(ctx.uid, "bob", drain: false)
      for n <- 1..150, do: Kernel.send(bob.pid, {:junk, n})

      assert {:ok, %{delivered: 0, skipped: [%{reason: :backpressure}]}} =
               Mcu.send_message(ctx.alice.part, :others, "hand.raised", "")
    end

    test "G-4: over its rate, a sender is refused — and accepted again after a refill",
         _ctx do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)
      ctx2 = start_mcu(block: %{"message_rate" => 1, "message_kinds" => @kinds})
      alice = join(ctx2.uid, "alice")
      _bob = join(ctx2.uid, "bob")

      # burst is 2 x rate
      assert {:ok, _} = Mcu.send_message(alice.part, :others, "hand.raised", "")
      assert {:ok, _} = Mcu.send_message(alice.part, :others, "hand.raised", "")
      assert {:error, :rate_limited} = Mcu.send_message(alice.part, :others, "hand.raised", "")

      Process.sleep(1_100)
      assert {:ok, _} = Mcu.send_message(alice.part, :others, "hand.raised", "")
    end

    test "G-5: the payload is bounded, UTF-8, and its kind declared", ctx do
      _bob = join(ctx.uid, "bob")

      assert {:error, :too_large} =
               Mcu.send_message(
                 ctx.alice.part,
                 :others,
                 "hand.raised",
                 String.duplicate("x", 2000)
               )

      assert {:error, :bad_payload} =
               Mcu.send_message(ctx.alice.part, :others, "hand.raised", <<0xFF, 0xFE>>)

      assert {:error, :unknown_kind} =
               Mcu.send_message(ctx.alice.part, :others, "chat.message", "hello")

      # nothing was delivered by any of the three
      assert received("bob") == :none
    end

    test "G-5: with no declared kind, the channel is closed", _ctx do
      stop_supervised!(:client_mcu1)
      stop_supervised!(Mcu)
      ctx2 = start_mcu(block: %{"message_kinds" => []})
      alice = join(ctx2.uid, "alice")
      _bob = join(ctx2.uid, "bob")

      assert {:error, :channel_closed} =
               Mcu.send_message(alice.part, :others, "hand.raised", "")
    end

    test "G-7: the same msg_id is fanned out once", ctx do
      _bob = join(ctx.uid, "bob")

      assert {:ok, %{delivered: 1}} =
               Mcu.send_message(ctx.alice.part, :others, "hand.raised", "", msg_id: "m-fixed")

      assert {:error, :duplicate_message} =
               Mcu.send_message(ctx.alice.part, :others, "hand.raised", "", msg_id: "m-fixed")

      assert {:ok, _} = received("bob")
      assert received("bob") == :none
    end

    test "G-8: a leg that is still ringing is not addressed", ctx do
      _bob = join(ctx.uid, "bob", attach: false)

      assert {:ok, %{delivered: 0, skipped: []}} =
               Mcu.send_message(ctx.alice.part, :others, "hand.raised", "")

      assert received("bob") == :none

      # …unless the caller insists
      assert {:ok, %{delivered: 1}} =
               Mcu.send_message(ctx.alice.part, :others, "hand.raised", "", include_ringing: true)

      assert {:ok, _} = received("bob")
    end
  end

  # ── the envelope (§20.4, §20.5 G-9) ──────────────────────────────────────────

  describe "envelope" do
    test "carries a display name and never the AOR, and a monotonic seq", ctx do
      alice = join(ctx.uid, "alice")
      bob = join(ctx.uid, "bob")

      assert {:ok, _} = Mcu.send_message(alice.part, {:name, "bob"}, "hand.raised", "raised")
      assert {:ok, first} = received("bob")

      assert first.kind == "hand.raised"
      assert first.payload == "raised"
      assert first.from.display_name == "alice"
      refute first.from.display_name =~ "@"
      assert is_binary(first.msg_id)
      assert %DateTime{} = first.sent_at

      # the sequence is per conference, across senders
      assert {:ok, _} = Mcu.send_message(bob.part, {:name, "alice"}, "floor.request", "")
      assert {:ok, second} = received("alice")
      assert second.seq > first.seq
    end
  end

  # ── declaration + housekeeping ───────────────────────────────────────────────

  describe "accept_messages/1" do
    test "is required, idempotent, and refused for a leg that does not exist", ctx do
      alice = join(ctx.uid, "alice")
      assert :ok = Mcu.accept_messages(alice.part)
      assert {:ok, row} = Mcu.participant(alice.part)
      assert row.accepts_messages

      assert {:error, :no_such_participant} =
               Mcu.accept_messages(%{alice.part | ref: make_ref()})
    end
  end

  test "a leg's rate bucket goes away with the leg", ctx do
    alice = join(ctx.uid, "alice")
    bob = join(ctx.uid, "bob")
    assert {:ok, _} = Mcu.send_message(alice.part, :others, "hand.raised", "")

    key = {:tokens, ctx.uid, alice.part.ref}
    assert [{^key, _tokens, _last}] = :ets.lookup(:kelix_mcu_bus, key)

    :ok = Mcu.leave(alice.part)
    until!(fn -> :ets.lookup(:kelix_mcu_bus, key) == [] end)

    # …and the conference's own rows go with the conference
    :ok = Mcu.leave(bob.part)
    {:ok, _} = Mcu.handle_control("conference.delete", %{"uid" => ctx.uid})
    assert :ets.lookup(:kelix_mcu_bus, {:seq, ctx.uid}) == []
  end

  test "the event carries the size, never the payload", ctx do
    alice = join(ctx.uid, "alice")
    _bob = join(ctx.uid, "bob")

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:ok, _} =
                 Mcu.send_message(alice.part, :others, "hand.raised", "secret-body-text")
      end)

    assert log =~ "participant.message"
    assert log =~ "size=16"
    refute log =~ "secret-body-text"
  end
end
