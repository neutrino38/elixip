# Phase 2 tests for UAS INVITE: on_events auto_store + the reply macros
# (reply_invite common to UAC/UAS, redirect_invite / challenge_invite server-side).
#
# Two levels:
#   * unit tests on the backing functions (auto_store, do_reply_invite guard,
#     lasterr mapping) using a stub dialog GenServer;
#   * an end-to-end path over the UDP mockup transport: an INVITE is injected,
#     a minimal UAS scenario replies, and the response code is asserted on the
#     wire (the mockup forwards inbound-INVITE response codes to the test process,
#     exactly like sip_call_test.exs).

# ── Minimal UAS scenarios used by the e2e path ───────────────────────────────
# reply_invite is available through SIP.Scenario (-> CallUAC); redirect_invite /
# challenge_invite require the explicit `use SIP.Session.CallUAS`.

defmodule UASInviteFixture.Answer180 do
  use SIP.Scenario
  uas(:invite)
  config(domain: "example.com")

  state initial_state do
    on_events do
      {:INVITE, _req, _t, _dlg} ->
        reply_invite(180, "Ringing")
        scenario_success("ringing")
    after
      5_000 -> scenario_failure("no INVITE")
    end
  end
end

defmodule UASInviteFixture.Busy do
  use SIP.Scenario
  uas(:invite)
  config(domain: "example.com")

  state initial_state do
    on_events do
      {:INVITE, _req, _t, _dlg} ->
        reply_invite(486, "Busy Here")
        scenario_success("busy")
    after
      5_000 -> scenario_failure("no INVITE")
    end
  end
end

defmodule UASInviteFixture.Redirect do
  use SIP.Scenario
  use SIP.Session.CallUAS
  uas(:invite)
  config(domain: "example.com")

  state initial_state do
    on_events do
      {:INVITE, _req, _t, _dlg} ->
        redirect_invite("<sip:bob@redirect.example.com>", 302, "Moved Temporarily")
        scenario_success("redirected")
    after
      5_000 -> scenario_failure("no INVITE")
    end
  end
end

defmodule UASInviteFixture.Challenge do
  use SIP.Scenario
  use SIP.Session.CallUAS
  uas(:invite)
  config(domain: "example.com")

  state initial_state do
    on_events do
      {:INVITE, _req, _t, _dlg} ->
        challenge_invite("example.com", 401)
        scenario_success("challenged")
    after
      5_000 -> scenario_failure("no INVITE")
    end
  end
end

# Phase 3: connect the (config-driven, mockup) media server, then answer the
# inbound INVITE with a media-negotiated 200 OK + SDP. reply_invite_with_sdp is
# available through SIP.Scenario (-> CallUAC), like reply_invite.
defmodule UASInviteFixture.AnswerSdp do
  use SIP.Scenario
  uas(:invite)
  config(domain: "example.com")

  state initial_state do
    media_connect()

    on_events do
      {:INVITE, _req, _t, _dlg} ->
        reply_invite_with_sdp(200)
        scenario_success("answered with SDP")
    after
      5_000 -> scenario_failure("no INVITE")
    end
  end
end

# ── Call-processing fabricator (stands in for the phase-5 Elixip.ScenarioUAS) ──
# Picks the scenario from the RURI "scenario" param and spawns an instance bound
# to the inbound dialog. Uses run_instance/2 directly (plain spawn, no monitor
# back to the dialog process) — enough for a test.
defmodule TestCallUAS do
  @behaviour SIP.Session.Call
  require Logger

  @scenarios %{
    "answer180" => UASInviteFixture.Answer180,
    "busy" => UASInviteFixture.Busy,
    "redirect" => UASInviteFixture.Redirect,
    "challenge" => UASInviteFixture.Challenge,
    "answersdp" => UASInviteFixture.AnswerSdp
  }

  @impl true
  def on_new_call(dialog_pid, req, transaction_id) do
    true = is_pid(transaction_id)

    case SIP.Uri.get_uri_param(req.ruri, "scenario") do
      {:ok, name} ->
        case Map.fetch(@scenarios, name) do
          {:ok, mod} ->
            pid =
              spawn(fn ->
                SIP.Scenario.Runner.run_instance(mod,
                  dialog_pid: dialog_pid,
                  inbound_request: req
                )
              end)

            {:accept, pid}

          :error ->
            {:reject, 404, "unknown scenario #{name}"}
        end

      _ ->
        {:reject, 404, "no scenario in RURI"}
    end
  end

  @impl true
  def on_call_end(_dialog_pid, _app_pid), do: nil
end

# A GenServer that records the replies it is asked to send, standing in for the
# dialog in the unit tests. Replies :ok, except :ignore for code 487 (to exercise
# the reply_lasterr :ignore -> :ok mapping).
defmodule StubDialog do
  use GenServer
  def start_link(test_pid), do: GenServer.start_link(__MODULE__, test_pid)
  @impl true
  def init(test_pid), do: {:ok, test_pid}

  @impl true
  def handle_call({:replyreq, _req, code, _reason, upd}, _from, test_pid) do
    send(test_pid, {:stub_reply, code, upd})
    {:reply, if(code == 487, do: :ignore, else: :ok), test_pid}
  end

  # In-dialog request send path (SIP.Dialog.new_request/2): record the built
  # request and return a transaction pid, as the real dialog does.
  def handle_call({:newreq, req}, _from, test_pid) do
    send(test_pid, {:stub_newreq, req})
    {:reply, {:ok, self()}, test_pid}
  end
end

# Minimal media server stub whose set_remote_offer always fails, to exercise the
# reply_invite_with_sdp media-error path (-> 500 Media Server Error).
defmodule FailingMedia do
  def create_peer_connection(_server, _sink, _opts), do: {:ok, self()}
  def set_remote_offer(_cnx, _sdp), do: {:error, :media_down}
end

defmodule SIP.Test.UASInvite do
  use ExUnit.Case
  require Logger

  @sdp_body [%{contenttype: "application/sdp", data: "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\n"}]

  # A full, ExSDP-parseable offer for the media negotiation tests.
  @valid_sdp "v=0\r\n" <>
               "o=- 1 1 IN IP4 1.2.3.4\r\n" <>
               "s=-\r\n" <>
               "c=IN IP4 1.2.3.4\r\n" <>
               "t=0 0\r\n" <>
               "m=audio 7344 RTP/AVP 0\r\n"

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    # Config-driven media_connect() in the AnswerSdp fixture resolves to the mockup.
    Application.put_env(:elixip2, :mediaserver, module: :mockup, url: "sip:localhost:8080")
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(TestCallUAS)
    :ok
  end

  # ── Unit tests: auto_store ──────────────────────────────────────────────────

  test "auto_store stashes an inbound INVITE, its transaction pid and the dialog pid" do
    req = %{method: :INVITE, body: @sdp_body}
    dlg = spawn(fn -> :ok end)
    ctx = SIP.Session.CallUAS.auto_store(%SIP.Context{}, {:INVITE, req, self(), dlg})

    assert SIP.Context.appdata_get(ctx, :last_uas_req) == req
    assert SIP.Context.appdata_get(ctx, :last_uas_req_tid) == self()
    # A sub_fsm child is spawned before the dialog exists: the event is its only
    # way to learn the dialog pid the reply macros must target.
    assert ctx.dialogpid == dlg
  end

  test "auto_store stashes an inbound UPDATE" do
    req = %{method: :UPDATE, body: []}
    ctx = SIP.Session.CallUAS.auto_store(%SIP.Context{}, {:UPDATE, req, self(), self()})
    assert SIP.Context.appdata_get(ctx, :last_uas_req) == req
  end

  test "auto_store is a no-op for non-offer events" do
    base = SIP.Context.appdata_set(%SIP.Context{}, :last_uas_req, :sentinel)

    for evt <- [
          {200, %{}, self(), self()},
          {:BYE, %{method: :BYE}, self(), self()},
          {:ACK, %{method: :ACK}, nil, self()},
          {:ms_event, make_ref(), :ice_connected},
          {:scenario_ctl, :shutdown, :x},
          :some_timer
        ] do
      assert SIP.Session.CallUAS.auto_store(base, evt) == base
    end
  end

  # ── Unit tests: reply_invite backing (SDP guard + lasterr mapping) ───────────

  test "do_reply_invite raises for an SDP-bearing code (183/2xx) on an INVITE" do
    ctx = ctx_with(%{method: :INVITE, body: @sdp_body}, nil)

    assert_raise RuntimeError, ~r/requires an SDP body/, fn ->
      SIP.Session.CallUAS.do_reply_invite(ctx, 200, nil, [])
    end

    assert_raise RuntimeError, ~r/requires an SDP body/, fn ->
      SIP.Session.CallUAS.do_reply_invite(ctx, 183, nil, [])
    end
  end

  test "do_reply_invite allows a non-SDP code and records lasterr :ok" do
    {:ok, dlg} = StubDialog.start_link(self())
    ctx = ctx_with(%{method: :INVITE, body: @sdp_body}, dlg)

    ctx = SIP.Session.CallUAS.do_reply_invite(ctx, 180, "Ringing", [])
    assert ctx.lasterr == :ok
    assert_received {:stub_reply, 180, _}
  end

  test "do_reply_invite allows a 2xx to an UPDATE that carried no SDP" do
    {:ok, dlg} = StubDialog.start_link(self())
    ctx = ctx_with(%{method: :UPDATE, body: []}, dlg)

    ctx = SIP.Session.CallUAS.do_reply_invite(ctx, 200, nil, [])
    assert ctx.lasterr == :ok
    assert_received {:stub_reply, 200, _}
  end

  test "do_reply_invite maps :ignore (final response already sent) to lasterr :ok" do
    {:ok, dlg} = StubDialog.start_link(self())
    ctx = ctx_with(%{method: :INVITE, body: @sdp_body}, dlg)

    # StubDialog replies :ignore for code 487.
    ctx = SIP.Session.CallUAS.do_reply_invite(ctx, 487, "Request Terminated", [])
    assert ctx.lasterr == :ok
  end

  test "do_reply_invite raises when no request was stored" do
    ctx = %SIP.Context{dialogpid: self()}

    assert_raise RuntimeError, ~r/no stored INVITE\/UPDATE/, fn ->
      SIP.Session.CallUAS.do_reply_invite(ctx, 486, "Busy", [])
    end
  end

  # ── Unit tests: media negotiation (get_sdp_answer / reply_invite_with_sdp) ───

  test "get_sdp_answer negotiates a local answer through the media server" do
    {:ok, ms} = MediaServer.Mockup.connect("sip:localhost:8080")
    ctx = %SIP.Context{mediaservermodule: MediaServer.Mockup, mediaserverpid: ms}

    {ctx, {:ok, answer}} = SIP.Session.Media.get_sdp_answer(ctx, @valid_sdp)
    assert is_binary(answer) and answer != ""
    # The peer connection is created once and reused (covers re-INVITE).
    cnx = SIP.Context.appdata_get(ctx, :mediapeerconnectionid)
    assert is_pid(cnx)

    {ctx2, {:ok, _}} = SIP.Session.Media.get_sdp_answer(ctx, @valid_sdp)
    assert SIP.Context.appdata_get(ctx2, :mediapeerconnectionid) == cnx
  end

  test "get_sdp_answer raises without a connected media server" do
    assert_raise RuntimeError, ~r/No media server connected/, fn ->
      SIP.Session.Media.get_sdp_answer(%SIP.Context{}, @valid_sdp)
    end
  end

  test "do_reply_invite_with_sdp replies 200 + SDP answer and a local Contact" do
    {:ok, dlg} = StubDialog.start_link(self())
    {:ok, ms} = MediaServer.Mockup.connect("sip:localhost:8080")

    ctx = %SIP.Context{
      dialogpid: dlg,
      username: "bob",
      mediaservermodule: MediaServer.Mockup,
      mediaserverpid: ms,
      appdata: %{last_uas_req: %{method: :INVITE, body: @valid_sdp}}
    }

    ctx = SIP.Session.CallUAS.do_reply_invite_with_sdp(ctx, 200, [])
    assert ctx.lasterr == :ok

    assert_received {:stub_reply, 200, upd}
    assert is_binary(upd[:body]) and upd[:body] != ""
    assert %SIP.Uri{userpart: "bob"} = upd[:contact]
  end

  test "do_reply_invite_with_sdp maps a media failure to 500 Media Server Error" do
    {:ok, dlg} = StubDialog.start_link(self())

    ctx = %SIP.Context{
      dialogpid: dlg,
      mediaservermodule: FailingMedia,
      mediaserverpid: self(),
      appdata: %{last_uas_req: %{method: :INVITE, body: @valid_sdp}}
    }

    ctx = SIP.Session.CallUAS.do_reply_invite_with_sdp(ctx, 200, [])
    assert ctx.lasterr == {:media_error, :media_down}
    assert_received {:stub_reply, 500, _}
  end

  test "do_reply_invite_with_sdp honors on_media_error override" do
    {:ok, dlg} = StubDialog.start_link(self())

    ctx = %SIP.Context{
      dialogpid: dlg,
      mediaservermodule: FailingMedia,
      mediaserverpid: self(),
      appdata: %{last_uas_req: %{method: :INVITE, body: @valid_sdp}}
    }

    _ctx =
      SIP.Session.CallUAS.do_reply_invite_with_sdp(ctx, 200, on_media_error: {503, "Overloaded"})

    assert_received {:stub_reply, 503, _}
  end

  test "do_reply_invite_with_sdp raises for an unsupported code" do
    ctx = %SIP.Context{appdata: %{last_uas_req: %{method: :INVITE, body: @valid_sdp}}}

    assert_raise RuntimeError, ~r/unsupported code/, fn ->
      SIP.Session.CallUAS.do_reply_invite_with_sdp(ctx, 180, [])
    end
  end

  test "do_reply_invite_with_sdp raises when the stored request carries no SDP" do
    ctx = %SIP.Context{
      mediaservermodule: MediaServer.Mockup,
      mediaserverpid: self(),
      appdata: %{last_uas_req: %{method: :INVITE, body: []}}
    }

    assert_raise RuntimeError, ~r/no SDP offer/, fn ->
      SIP.Session.CallUAS.do_reply_invite_with_sdp(ctx, 200, [])
    end
  end

  # ── Unit tests: reply_invite_with_body ───────────────────────────────────────

  test "do_reply_invite_with_body accepts a binary body" do
    {:ok, dlg} = StubDialog.start_link(self())
    ctx = ctx_with(%{method: :INVITE, body: @valid_sdp}, dlg)

    ctx = SIP.Session.CallUAS.do_reply_invite_with_body(ctx, 200, @valid_sdp, [])
    assert ctx.lasterr == :ok
    assert_received {:stub_reply, 200, upd}
    assert upd[:body] == @valid_sdp
    assert %SIP.Uri{} = upd[:contact]
  end

  test "do_reply_invite_with_body accepts a single %{contenttype, data} map" do
    {:ok, dlg} = StubDialog.start_link(self())
    ctx = ctx_with(%{method: :INVITE, body: @valid_sdp}, dlg)
    part = %{contenttype: "application/sdp", data: @valid_sdp}

    SIP.Session.CallUAS.do_reply_invite_with_body(ctx, 200, part, [])
    assert_received {:stub_reply, 200, upd}
    assert upd[:body] == [part]
  end

  test "do_reply_invite_with_body accepts a multipart (list > 1) body" do
    {:ok, dlg} = StubDialog.start_link(self())
    ctx = ctx_with(%{method: :INVITE, body: @valid_sdp}, dlg)

    parts = [
      %{contenttype: "application/sdp", data: @valid_sdp},
      %{contenttype: "text/plain", data: "hi"}
    ]

    ctx = SIP.Session.CallUAS.do_reply_invite_with_body(ctx, 200, parts, [])
    assert ctx.lasterr == :ok
    assert_received {:stub_reply, 200, upd}
    # The list is passed through to the dialog; update_sip_msg turns it into a
    # multipart/mixed body downstream (covered by the sip_parser round-trip test).
    assert upd[:body] == parts
  end

  test "do_reply_invite_with_body rejects an invalid body shape" do
    ctx = ctx_with(%{method: :INVITE, body: @valid_sdp}, self())

    assert_raise RuntimeError, ~r/invalid body/, fn ->
      SIP.Session.CallUAS.do_reply_invite_with_body(ctx, 200, {:bogus, 1}, [])
    end
  end

  # ── Phase 4: CallInDialog — in-dialog senders + reply_request ────────────────

  defp indialog_ctx(dlg) do
    %SIP.Context{dialogpid: dlg, username: "alice", domain: "example.com", ftag: "ftag1"}
  end

  test "do_send_message builds a MESSAGE with a text/plain body by default" do
    {:ok, dlg} = StubDialog.start_link(self())
    ctx = SIP.Session.CallInDialog.do_send_message(indialog_ctx(dlg), "hello", [])

    assert ctx.lasterr == :ok
    assert_received {:stub_newreq, req}
    assert req.method == :MESSAGE
    assert req.body == "hello"
    assert req.contenttype == "text/plain"
    assert req.contentlength == byte_size("hello")
  end

  test "do_send_info defaults to application/dtmf-relay and honors :contenttype" do
    {:ok, dlg} = StubDialog.start_link(self())

    SIP.Session.CallInDialog.do_send_info(indialog_ctx(dlg), "Signal=5", [])
    assert_received {:stub_newreq, %{method: :INFO, contenttype: "application/dtmf-relay"}}

    SIP.Session.CallInDialog.do_send_info(indialog_ctx(dlg), "x", contenttype: "application/xml")
    assert_received {:stub_newreq, %{contenttype: "application/xml"}}
  end

  test "do_send_bye sends a bodyless BYE, and carries a body when given one" do
    {:ok, dlg} = StubDialog.start_link(self())

    SIP.Session.CallInDialog.do_send_bye(indialog_ctx(dlg), nil)
    assert_received {:stub_newreq, %{method: :BYE, contentlength: 0}}

    SIP.Session.CallInDialog.do_send_bye(indialog_ctx(dlg), "reason=stop")
    assert_received {:stub_newreq, %{method: :BYE, body: "reason=stop"}}
  end

  test "do_send_refer sets Refer-To and optional Referred-By" do
    {:ok, dlg} = StubDialog.start_link(self())

    SIP.Session.CallInDialog.do_send_refer(indialog_ctx(dlg), "sip:carol@example.com",
      referred_by: "sip:alice@example.com"
    )

    assert_received {:stub_newreq, req}
    assert req.method == :REFER
    assert req["Refer-To"] == "sip:carol@example.com"
    assert req["Referred-By"] == "sip:alice@example.com"
  end

  test "do_send_update / do_send_reinvite carry an explicit SDP + a local Contact" do
    {:ok, dlg} = StubDialog.start_link(self())

    SIP.Session.CallInDialog.do_send_update(indialog_ctx(dlg), @valid_sdp, [])
    assert_received {:stub_newreq, upd}
    assert upd.method == :UPDATE
    assert upd.body == @valid_sdp
    assert upd.contenttype == "application/sdp"
    assert %SIP.Uri{} = upd.contact

    SIP.Session.CallInDialog.do_send_reinvite(indialog_ctx(dlg), @valid_sdp, [])
    assert_received {:stub_newreq, %{method: :INVITE, body: @valid_sdp}}
  end

  test "do_send_update(:mediaserver) negotiates the offer with the media server" do
    {:ok, dlg} = StubDialog.start_link(self())
    {:ok, ms} = MediaServer.Mockup.connect("sip:localhost:8080")

    ctx = %{indialog_ctx(dlg) | mediaservermodule: MediaServer.Mockup, mediaserverpid: ms}

    SIP.Session.CallInDialog.do_send_update(ctx, :mediaserver, [])
    assert_received {:stub_newreq, req}
    assert req.method == :UPDATE
    assert is_binary(req.body) and req.body != ""
  end

  test "do_send_notify sets the Event header and a body" do
    {:ok, dlg} = StubDialog.start_link(self())

    SIP.Session.CallInDialog.do_send_notify(indialog_ctx(dlg), "refer", "SIP/2.0 200 OK", [])
    assert_received {:stub_newreq, req}
    assert req.method == :NOTIFY
    assert req["Event"] == "refer"
    assert req.body == "SIP/2.0 200 OK"
  end

  test "do_send_options sends an in-dialog OPTIONS" do
    {:ok, dlg} = StubDialog.start_link(self())
    SIP.Session.CallInDialog.do_send_options(indialog_ctx(dlg))
    assert_received {:stub_newreq, %{method: :OPTIONS}}
  end

  test "do_reply_request replies and maps lasterr" do
    {:ok, dlg} = StubDialog.start_link(self())
    ctx = %SIP.Context{dialogpid: dlg}

    ctx = SIP.Session.CallInDialog.do_reply_request(ctx, %{method: :BYE}, 200, "OK", [])
    assert ctx.lasterr == :ok
    assert_received {:stub_reply, 200, []}

    # StubDialog replies :ignore for 487 -> mapped to :ok.
    ctx = SIP.Session.CallInDialog.do_reply_request(ctx, %{method: :INVITE}, 487, nil, [])
    assert ctx.lasterr == :ok
  end

  # ── End-to-end over the UDP mockup ──────────────────────────────────────────

  test "reply_invite(180) reaches the wire" do
    inject_invite("answer180")
    # IST emits the automatic 100 first (phase 1), then the scenario's 180.
    assert_receive 100, 2_000
    assert_receive 180, 2_000
  end

  test "reply_invite(486) reaches the wire" do
    invite = inject_invite("busy")
    assert_receive 486, 2_000
    ack_final(invite)
  end

  test "redirect_invite(302) reaches the wire" do
    invite = inject_invite("redirect")
    assert_receive 302, 2_000
    ack_final(invite)
  end

  test "challenge_invite(401) reaches the wire" do
    invite = inject_invite("challenge")
    assert_receive 401, 2_000
    ack_final(invite)
  end

  test "reply_invite_with_sdp(200) reaches the wire" do
    inject_invite("answersdp")
    # IST emits the automatic 100 first (phase 1), then the media-negotiated 200.
    assert_receive 100, 2_000
    assert_receive 200, 3_000
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp ctx_with(req, dialogpid) do
    %SIP.Context{dialogpid: dialogpid, appdata: %{last_uas_req: req}}
  end

  # Load the canned INVITE, tag its RURI for the mockup transport and with the
  # scenario selector, give it a unique Call-ID and a fresh Via branch, then
  # inject it as an inbound message and route responses back to this process.
  defp inject_invite(scenario) do
    {:ok, msg} = File.read("test/SIP-INVITE-LVP.txt")
    {:ok, parsed} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)

    parsed = Map.put(parsed, :callid, "uasinv-#{System.unique_integer([:positive])}")

    upd_uri =
      parsed.ruri
      |> SIP.Uri.set_uri_param("unittest", "1")
      |> SIP.Uri.set_uri_param("scenario", scenario)

    branch = "z9hG4bK#{System.unique_integer([:positive])}"
    parsed = SIP.Msg.Ops.add_via(parsed, {{2, 2, 2, 2}, 5090, "UDP"}, branch)

    routed = SIP.Transport.Selector.select_transport(upd_uri)
    parsed = SIP.Msg.Ops.update_sip_msg(parsed, {:ruri, routed})

    :ok = GenServer.call(routed.tp_pid, :settestapp)
    send(routed.tp_pid, {:recv, parsed})
    parsed
  end

  # ACK a non-2xx final response on the INVITE's own branch so the IST reaches
  # :terminated instead of lingering and retransmitting (keeps the suite light).
  defp ack_final(invite) do
    ack =
      SIP.Msg.Ops.ack_request(invite, %SIP.Uri{domain: "2.2.2.2", port: 5090})
      |> Map.put(:transid, invite.transid)

    send(invite.ruri.tp_pid, {:recv, ack})
    :ok
  end
end
