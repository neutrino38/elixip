defmodule Kelix.Mod.CaptioningTest do
  @moduledoc """
  `Kelix.Mod.Captioning`: the captioning INFO read, the correction token asked of
  a speech-server (a stub, `Kelix.Test.SpeechServerStub`), the policy around it,
  and the token kept out of every trace.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Kelix.Mod.Captioning
  alias Kelix.Mod.Captioning.Body
  alias Kelix.Test.SpeechServerStub, as: Stub

  @ct "application/captioning+xml"
  @realm "visioassistance.net"

  defp info(xml, callid \\ "call-1") do
    %{
      method: :INFO,
      callid: callid,
      contenttype: @ct,
      body: [%{contenttype: @ct, data: xml}]
    }
  end

  defp request(comp) when is_boolean(comp),
    do: info(~s(<captioning><inbound><stt comp="#{comp}"/></inbound></captioning>))

  defp config(stub, extra \\ %{}) do
    Map.merge(
      %{
        "control_url" => stub.url,
        "public_url" => "wss://speech.example.net:9201",
        "domain" => [
          %{"name" => @realm, "correction" => true, "lang" => "fr"},
          %{"name" => "nolang.example", "correction" => true},
          %{"name" => "basic.example", "correction" => false}
        ]
      },
      extra
    )
  end

  defp start_module(stub, extra \\ %{}) do
    {:ok, cfg} = Captioning.parse_config(config(stub, extra))
    start_supervised!(%{id: Captioning, start: {Captioning, :start_link, [[cfg: cfg]]}})
    :ok
  end

  defp uri_of({200, "OK", body: [%{contenttype: @ct, data: xml}]}) do
    [_, uri] = Regex.run(~r/uri="([^"]+)"/, xml)
    uri
  end

  # ── The body ───────────────────────────────────────────────────────────────

  describe "Body.parse/1" do
    test "reads stt and comp" do
      assert {:ok, %{stt: true, comp: true}} =
               Body.parse(~s(<?xml version="1.0" encoding="UTF-8"?>
                 <captioning><inbound><stt comp="true"/></inbound></captioning>))

      assert {:ok, %{stt: true, comp: true}} =
               Body.parse(~s(<captioning><inbound><stt comp=" TRUE "/></inbound></captioning>))

      assert {:ok, %{stt: true, comp: false}} =
               Body.parse(~s(<captioning><inbound><stt comp="false"/></inbound></captioning>))
    end

    test "an absent comp is false, and so is comp without stt" do
      assert {:ok, %{stt: true, comp: false}} =
               Body.parse("<captioning><inbound><stt/></inbound></captioning>")

      assert {:ok, %{stt: false, comp: false}} = Body.parse("<captioning><inbound/></captioning>")
      assert {:ok, %{stt: false, comp: false}} = Body.parse("<captioning/>")
    end

    test "unknown elements, attributes and a namespace are ignored" do
      xml = ~s(<captioning xmlns="urn:ives:captioning" v="2"><outbound><tts/></outbound>
               <inbound><x/><stt comp="true" speed="fast"/></inbound></captioning>)

      assert {:ok, %{stt: true, comp: true}} = Body.parse(xml)
    end

    test "refuses what is not a captioning document" do
      assert {:error, :doctype_not_allowed} =
               Body.parse(~s(<!DOCTYPE c [<!ENTITY x "y">]><captioning/>))

      assert {:error, {:malformed_xml, _}} = Body.parse("<captioning><inbound><stt comp=")
      assert {:error, {:not_a_captioning_document, "presence"}} = Body.parse("<presence/>")

      assert {:error, {:body_too_large, _}} =
               Body.parse("<captioning>" <> String.duplicate(" ", 5000) <> "</captioning>")

      assert {:error, :no_body} = Body.parse(nil)
    end

    test "renders both answers, the uri escaped" do
      assert Body.render(%{comp: false}) =~ ~s(<stt comp="false"/>)
      refute Body.render(%{comp: false}) =~ "uri="

      xml = Body.render(%{comp: true, uri: "wss://h/streaming/comp/abc?lang=fr&x=1"})
      assert xml =~ ~s(<stt comp="true" uri="wss://h/streaming/comp/abc?lang=fr&amp;x=1"/>)
      assert {:ok, %{stt: true, comp: true}} = Body.parse(xml)
    end
  end

  # ── The configuration ──────────────────────────────────────────────────────

  describe "validate_config/1" do
    setup do: %{stub: %{url: "http://10.0.0.12:9200"}}

    test "accepts a complete block, defaults filled in", %{stub: stub} do
      assert :ok = Captioning.validate_config(config(stub))
      assert {:ok, cfg} = Captioning.parse_config(config(stub))

      assert %{ttl: 60, timeout_ms: 2000, max_per_call: 5, min_interval: 10, retry_after: 30} =
               cfg

      assert %{name: @realm, correction: true, lang: "fr"} = cfg.domains[@realm]
    end

    test "names the key at fault", %{stub: stub} do
      assert {:error, "public_url must be a wss:// URL"} =
               Captioning.validate_config(config(stub, %{"public_url" => "ws://speech:9201"}))

      assert {:error, "control_url is required"} =
               Captioning.validate_config(Map.delete(config(stub), "control_url"))

      assert {:error, "ttl must be between 1 and 3600"} =
               Captioning.validate_config(config(stub, %{"ttl" => 0}))

      assert {:error, "unknown key(s): tll"} =
               Captioning.validate_config(config(stub, %{"tll" => 60}))

      assert {:error, "domain name" <> _} =
               Captioning.validate_config(
                 config(stub, %{"domain" => [%{"name" => "exämple.fr"}]})
               )

      assert {:error, "domain x.fr: lang" <> _} =
               Captioning.validate_config(
                 config(stub, %{"domain" => [%{"name" => "x.fr", "lang" => "French"}]})
               )
    end
  end

  # ── Tokens ─────────────────────────────────────────────────────────────────

  describe "answer/2 with a speech-server" do
    setup do
      stub = Stub.start()
      start_module(stub)
      %{stub: stub}
    end

    test "comp=true: a token, in a wss:// URL with the domain's language" do
      answer = Captioning.answer(request(true), @realm)

      assert_receive {:speech_token_request, sent}
      assert sent == %{"function" => "comp", "ttl" => 60, "account" => @realm}

      uri = uri_of(answer)

      assert uri =~
               ~r"\Awss://speech.example.net:9201/streaming/comp/[A-Za-z0-9_-]{43}\?lang=fr\z"
    end

    test "no lang configured, none in the URL" do
      uri = uri_of(Captioning.answer(request(true), "NoLang.Example"))
      assert uri =~ ~r"/streaming/comp/[A-Za-z0-9_-]+\z"
      assert_receive {:speech_token_request, %{"account" => "nolang.example"}}
    end

    test "comp=false: 200 without uri, and the speech-server is not asked" do
      assert {200, "OK", body: [%{data: xml}]} = Captioning.answer(request(false), @realm)
      assert xml =~ ~s(comp="false")
      refute xml =~ "uri="
      refute_receive {:speech_token_request, _}, 100
    end

    test "a domain without the correction, or not configured, gets 403" do
      assert {403, "Forbidden", []} = Captioning.answer(request(true), "basic.example")
      assert {403, "Forbidden", []} = Captioning.answer(request(true), "unknown.example")
      refute_receive {:speech_token_request, _}, 100

      # ... but comp="false" is the captions alone, which every caller has.
      assert {200, "OK", _} = Captioning.answer(request(false), "basic.example")
    end

    test "a body that is not a captioning document is a 400" do
      assert {400, "Bad Request", []} = Captioning.answer(info("<presence/>"), @realm)
      assert {400, "Bad Request", []} = Captioning.answer(info("not xml"), @realm)
      assert {400, "Bad Request", []} = Captioning.answer(%{method: :INFO, callid: "c"}, @realm)
    end

    test "each refusal of the speech-server is a 503 with Retry-After", %{stub: stub} do
      for {answer, level} <- [
            {{400, %{"error" => "unknown field x"}}, :error},
            {{403, %{"error" => "forbidden"}}, :error},
            {{413, %{"error" => "too large"}}, :error},
            {{500, %{"error" => "internal"}}, :warning},
            {{201, %{"function" => "comp"}}, :warning},
            {{201, %{"token" => "a/b+c", "function" => "comp"}}, :warning},
            {{201, %{"token" => Stub.token(), "function" => "asr"}}, :warning},
            {{:raw, 201, "not json"}, :warning}
          ] do
        Stub.answer(stub, answer)

        log =
          capture_log([level: :warning], fn ->
            assert {503, "Service Unavailable", [{"Retry-After", "30"}]} =
                     answer_as(request(true), @realm, "call-#{inspect(answer)}")
          end)

        assert log =~ "[#{level}]", "#{inspect(answer)} logged as #{log}"
      end
    end

    test "a slow speech-server is a 503 within timeout_ms" do
      stop_supervised!(Captioning)
      stub = Stub.start({:delay, 1_000, :token})
      start_module(stub, %{"timeout_ms" => 200})

      {elapsed, answer} = :timer.tc(fn -> Captioning.answer(request(true), @realm) end)
      assert {503, _, [{"Retry-After", "30"}]} = answer
      assert elapsed < 600_000
    end

    test "a speech-server that is not there is a 503" do
      stop_supervised!(Captioning)
      {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(socket)
      :gen_tcp.close(socket)
      start_module(%{url: "http://127.0.0.1:#{port}"})

      assert {503, _, [{"Retry-After", "30"}]} = Captioning.answer(request(true), @realm)
    end

    test "the token never reaches the log", %{stub: stub} do
      token = Stub.token()
      Stub.answer(stub, {201, %{"token" => token, "function" => "comp"}})

      log =
        capture_log([level: :debug], fn ->
          assert uri_of(Captioning.answer(request(true), @realm)) =~ token
        end)

      assert log =~ "/streaming/comp/" <> binary_part(token, 0, 6) <> "…"
      refute log =~ token
    end
  end

  # Called as answer/2 is, with the Call-ID a test chooses — each case its own call.
  defp answer_as(req, domain, callid), do: Captioning.answer(%{req | callid: callid}, domain)

  describe "renewal bounds" do
    test "max_per_call renewals after the first token, then 503" do
      stub = Stub.start()
      start_module(stub, %{"max_per_call" => 2, "min_interval" => 0, "retry_after" => 45})

      for _ <- 1..3, do: assert({200, "OK", _} = answer_as(request(true), @realm, "c1"))

      assert {503, _, [{"Retry-After", "45"}]} = answer_as(request(true), @realm, "c1")
      assert_received {:speech_token_request, _}
      # Another call is counted apart.
      assert {200, "OK", _} = answer_as(request(true), @realm, "c2")

      # A call released starts over.
      Captioning.release("c1")
      assert {200, "OK", _} = answer_as(request(true), @realm, "c1")
    end

    test "min_interval between two tokens of a call" do
      stub = Stub.start()
      start_module(stub, %{"min_interval" => 10})

      assert {200, "OK", _} = answer_as(request(true), @realm, "c1")
      assert {503, _, [{"Retry-After", "30"}]} = answer_as(request(true), @realm, "c1")
    end
  end

  describe "without the module" do
    test "answer/2 is a 503, and release/1 a no-op" do
      capture_log(fn ->
        assert {503, _, [{"Retry-After", "30"}]} = Captioning.answer(request(true), @realm)
      end)

      assert :ok = Captioning.release("c1")
    end

    test "ModuleRegistry.facade/4 answers the script's default when it is not configured" do
      default = {200, "OK", []}

      assert ^default =
               Kelix.ModuleRegistry.facade(
                 "captioning",
                 :answer,
                 [request(true), @realm],
                 default
               )
    end
  end

  # ── Masking and traces ─────────────────────────────────────────────────────

  test "mask/1 keeps the first six characters of every token" do
    assert Captioning.mask("x wss://h:1/streaming/comp/AbCdEfGhIj-_?lang=fr y") ==
             "x wss://h:1/streaming/comp/AbCdEf…?lang=fr y"

    assert Captioning.mask("nothing here") == "nothing here"
  end

  test "once started, the SIP traces show the 200 OK masked" do
    stub = Stub.start()
    start_module(stub)

    token = Stub.token()
    Stub.answer(stub, {201, %{"token" => token, "function" => "comp"}})
    {200, "OK", body: [part]} = Captioning.answer(request(true), @realm)

    {:ok, raw} =
      File.read(Path.join([__DIR__, "..", "..", "elixip2", "test", "SIP-INVITE-LVP.txt"]))

    {:ok, invite} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    resp = SIP.Msg.Ops.reply_to_request(%{invite | method: :INFO}, 200, "OK", body: [part])
    wire = SIPMsg.serialize(resp)
    assert wire =~ token

    for shown <- [
          SIPMsg.loggable(wire),
          elem(SIPMsg.readable(resp), 0),
          SIPMsg.serialize(SIPMsg.redacted(resp))
        ] do
      assert shown =~ "/streaming/comp/" <> binary_part(token, 0, 6) <> "…"
      refute shown =~ token
    end
  end

  test "kelictl captioning status" do
    stub = Stub.start()
    start_module(stub, %{"max_per_call" => 0, "min_interval" => 0})

    assert {200, _, _} = answer_as(request(true), @realm, "s1")
    assert {503, _, _} = answer_as(request(true), @realm, "s1")
    assert {403, _, _} = answer_as(request(true), "basic.example", "s2")

    assert {:ok, status} = Captioning.handle_control("status", %{})
    assert %{requested: 3, obtained: 1, active_calls: 1, public_url: "wss://" <> _} = status
    assert status.refused == %{"busy" => 1, "forbidden" => 1}
    assert %{last: _, max: _, mean: _} = status.latency_ms
    assert [%{name: "basic.example"}, %{name: "nolang.example"}, %{name: @realm}] = status.domains
  end
end
