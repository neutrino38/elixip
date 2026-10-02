defmodule SIP.Test.DialogInfo do
  # The event-package table lives in :persistent_term and the presence
  # processing module in a node-wide Agent: the notifier tests below share both.
  use ExUnit.Case, async: false

  @moduledoc """
  Dialog-info (RFC 4235) and the `dialog` event package over it: what comes off
  the wire, what goes back on it, what is refused — and the one thing the
  subscription layer does to the document, stamping its `version`.

  The documents in `test/DIALOG-INFO-*.xml` are the RFC's own: the §6 example
  flow (early, confirmed, terminated on one dialog) and the §4.4 full document
  with both parties, a duration, and the elements nobody here models
  (`<replaces>`, `<referred-by>`, `<route-set>`, a target `<param>`).
  """

  alias SIP.DialogInfo.Dialog
  alias SIP.DialogInfo.Doc
  alias SIP.DialogInfo.Party
  alias SIP.DialogInfo.Xml
  alias SIP.Test.Transport.Mockup

  @package SIP.EventPackage.Dialog
  @content_type "application/dialog-info+xml"

  defp sample(name), do: File.read!(Path.join(__DIR__, "DIALOG-INFO-#{name}.xml"))

  # ── Reading ─────────────────────────────────────────────────────────────────

  describe "parse/1" do
    test "reads the §6 initial NOTIFY: one early dialog, version 0, full state" do
      assert {:ok, doc} = Xml.parse(sample("rfc4235-early"))

      assert doc.entity == "sip:alice@example.com"
      assert doc.version == 0
      assert doc.state == :full

      assert [%Dialog{} = dialog] = doc.dialogs
      assert dialog.id == "as7d900as8"
      assert dialog.call_id == "a84b4c76e66710"
      assert dialog.local_tag == "1928301774"
      assert dialog.remote_tag == "456887766"
      assert dialog.direction == :initiator
      assert dialog.state == :early
      assert dialog.event == nil
      assert dialog.code == nil
    end

    test "reads the §6 partial updates: confirmed, then terminated with its event" do
      assert {:ok, confirmed} = Xml.parse(sample("rfc4235-confirmed"))
      assert confirmed.version == 1
      assert confirmed.state == :partial
      assert [%Dialog{state: :confirmed, event: nil}] = confirmed.dialogs

      assert {:ok, terminated} = Xml.parse(sample("rfc4235-terminated"))
      assert terminated.version == 2
      assert [%Dialog{state: :terminated, event: :remote_bye}] = terminated.dialogs
    end

    test "reads both parties, the duration and the code, and skips what it does not model" do
      assert {:ok, doc} = Xml.parse(sample("rfc4235-full"))

      assert doc.version == 7
      assert [%Dialog{} = up, %Dialog{} = down] = doc.dialogs

      assert up.direction == :recipient
      assert up.state == :confirmed
      assert up.duration == 274

      assert up.local == %Party{
               identity: "sip:alice@example.com",
               display: "Alice",
               target: "sip:alice@pc33.example.com"
             }

      # The entity the document escaped, unescaped exactly once.
      assert up.remote == %Party{
               identity: "sip:bob@example.org",
               display: "Bob & Co",
               target: "sip:bobster@phone21.example.org"
             }

      assert down.state == :terminated
      assert down.event == :rejected
      assert down.code == 486
      assert down.local == nil
      assert down.remote == %Party{identity: "sip:dave@example.org"}
    end

    test "reads an empty document as an entity with no dialog" do
      assert {:ok, %Doc{entity: "sip:bob@example.com", dialogs: []}} = Xml.parse(sample("empty"))
    end

    test "tolerates a document with no namespace, and carries an event it does not know" do
      body = """
      <dialog-info version="3" entity="sip:frank@ives.fr">
        <dialog id="x1"><state event="vendor-hangup" code="oops">TERMINATED</state></dialog>
      </dialog-info>
      """

      assert {:ok, doc} = Xml.parse(body)
      assert doc.version == 3
      assert [%Dialog{state: :terminated, event: "vendor-hangup", code: nil}] = doc.dialogs
    end

    test "refuses what is not a dialog-info document, without raising" do
      assert {:error, {:not_a_dialog_info_document, "presence"}} =
               Xml.parse(~s(<presence entity="sip:a@b"/>))

      assert {:error, {:malformed_xml, _}} = Xml.parse("<dialog-info entity=")

      assert {:error, :doctype_not_allowed} =
               Xml.parse(~s(<!DOCTYPE d [<!ENTITY x "y">]><dialog-info entity="sip:a@b"/>))

      big = String.duplicate(" ", 65 * 1024) <> ~s(<dialog-info entity="sip:a@b"/>)
      assert {:error, {:body_too_large, _}} = Xml.parse(big)

      assert {:error, {:not_a_body, nil}} = Xml.parse(nil)
    end
  end

  # ── Writing ─────────────────────────────────────────────────────────────────

  describe "serialize/1" do
    test "round-trips every sample: parse(serialize(doc)) is doc" do
      for name <- ~w(rfc4235-early rfc4235-confirmed rfc4235-terminated rfc4235-full empty) do
        assert {:ok, doc} = Xml.parse(sample(name))
        assert {:ok, body} = Xml.serialize(doc)
        assert {:ok, ^doc} = Xml.parse(body), "#{name} did not survive the round trip"
      end
    end

    test "writes the document a notifier builds, with the version and the parties" do
      doc = %Doc{
        entity: "sip:bob@ives.fr",
        version: 5,
        dialogs: [
          %Dialog{
            id: "d1",
            call_id: "c1",
            local_tag: "lt",
            remote_tag: "rt",
            direction: :recipient,
            state: :terminated,
            event: :local_bye,
            code: 200,
            local: %Party{identity: "sip:bob@ives.fr", display: "Bob <B>"},
            remote: %Party{target: "sip:alice@10.0.0.4"}
          }
        ]
      }

      assert {:ok, body} = Xml.serialize(doc)

      assert body =~ ~s(<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info")
      assert body =~ ~s(version="5" state="full" entity="sip:bob@ives.fr")

      assert body =~
               ~s(<dialog id="d1" call-id="c1" local-tag="lt" remote-tag="rt" direction="recipient">)

      assert body =~ ~s(<state event="local-bye" code="200">terminated</state>)
      assert body =~ ~s(<identity display="Bob &lt;B&gt;">sip:bob@ives.fr</identity>)
      assert body =~ ~s(<target uri="sip:alice@10.0.0.4"/>)
      assert {:ok, ^doc} = Xml.parse(body)
    end

    test "names a dialog after its Call-ID when it has no id of its own" do
      doc = %Doc{entity: "sip:bob@ives.fr", dialogs: [%Dialog{call_id: "c1"}]}
      assert {:ok, body} = Xml.serialize(doc)
      assert body =~ ~s(<dialog id="c1" call-id="c1">)
      assert {:ok, %Doc{dialogs: [%Dialog{id: "c1", state: :trying}]}} = Xml.parse(body)
    end

    test "refuses a document that does not say whose dialogs it lists" do
      assert {:error, :no_entity} = Xml.serialize(%Doc{})
    end
  end

  # ── The package ─────────────────────────────────────────────────────────────

  describe "SIP.EventPackage.Dialog" do
    test "answers the name, the bounds of presence, and one content type" do
      assert @package.name() == "dialog"
      assert @package.default_expires() == SIP.EventPackage.Presence.default_expires()
      assert @package.min_expires() == SIP.EventPackage.Presence.min_expires()
      assert @package.max_expires() == SIP.EventPackage.Presence.max_expires()
      assert @package.content_types() == [@content_type]
    end

    test "parses and serializes through its one content type, matched case-insensitively" do
      doc = %Doc{
        entity: "sip:bob@ives.fr",
        dialogs: [%Dialog{id: "d1", call_id: "c1", state: :early}]
      }

      assert {:ok, body} = @package.serialize("Application/Dialog-Info+XML", doc)
      assert {:ok, ^doc} = @package.parse(@content_type, body)
    end

    test "refuses a content type it cannot produce, and a document it does not model" do
      assert {:error, {:unsupported_content_type, "application/pidf+xml"}} =
               @package.parse("application/pidf+xml", "<x/>")

      assert {:error, {:unsupported_content_type, "text/plain"}} =
               @package.serialize("text/plain", %Doc{entity: "sip:a@b"})

      # A presence document on the dialog package is the mistake a scenario
      # reporting on two packages makes: it is refused here, not read by the
      # watcher as an empty NOTIFY.
      assert {:error, {:not_a_dialog_info_document, %SIP.Presence.Doc{}}} =
               @package.serialize(@content_type, SIP.Presence.Doc.new("sip:a@b"))

      assert {:error, {:not_a_dialog_info_document, "open"}} =
               @package.serialize(@content_type, "open")
    end

    test "registers itself as a provided package at boot, next to presence" do
      SIP.EventPackage.register_builtins()

      assert {:ok, @package} = SIP.EventPackage.lookup("dialog")
      assert {:ok, @package} = SIP.EventPackage.lookup("DIALOG")
      assert %{origin: :builtin} = Map.fetch!(SIP.EventPackage.registered(), "dialog")
      assert {:ok, SIP.EventPackage.Presence} = SIP.EventPackage.lookup("presence")
    end
  end

  # ── The version is the subscription's ───────────────────────────────────────

  defmodule Fixture.Notifier do
    @moduledoc false
    use SIP.Scenario
    uas(:presence)
    config(domain: "unit.test")

    state initial_state do
      goto(authorize)
    end

    # The document is built with a version of its own, 42, on purpose: what
    # reaches the watcher is the subscription's count, whatever the scenario
    # wrote.
    state authorize do
      on_events do
        {:SUBSCRIBE, _req, _t, _d} ->
          case accept_subscription(package: "dialog", expires: 120) do
            {:ok, _sub} ->
              notify(%SIP.DialogInfo.Doc{
                entity: "sip:bob@unit.test",
                version: 42,
                dialogs: [%SIP.DialogInfo.Dialog{call_id: "c1", state: :confirmed}]
              })

              goto(subscribed, "200 + NOTIFY")

            {:error, code} ->
              scenario_failure("SUBSCRIBE refused with #{code}")
          end
      after
        5_000 -> scenario_failure("no SUBSCRIBE received")
      end
    end

    state subscribed do
      on_events do
        {:SUBSCRIBE, _req, _t, _d} ->
          case accept_subscription(package: "dialog", expires: 120) do
            {:ok, _sub} ->
              notify(%SIP.DialogInfo.Doc{entity: "sip:bob@unit.test", version: 42})
              stay("refresh")

            {:error, code} ->
              scenario_failure("refresh refused with #{code}")
          end

        {:subscription_terminated, _ref, reason} ->
          scenario_success("#{reason}")

        {:dialog_terminated, _d, _r} ->
          scenario_success("dialog gone")
      after
        20_000 -> scenario_failure("the subscription never ended")
      end
    end
  end

  defmodule Fixture.WatcherPeer do
    @moduledoc false
    use SIP.Test.Peer

    # Answered 200, or the NICT retransmits the NOTIFY and the test is handed a
    # copy of the first one instead of the second.
    @impl true
    def on_request(%{method: :NOTIFY} = req, state), do: {[reply(req, 200, "OK", [], 10)], state}
    def on_request(req, state), do: default_request(req, state)
  end

  setup_all do
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    SIP.Test.AppEnv.preserve_proxy()
    Application.put_env(:elixip2, :proxyusesrv, false)

    :ok = SIP.EventPackage.register(@package, origin: :builtin)
    on_exit(fn -> SIP.EventPackage.unregister(@package) end)
    :ok
  end

  describe "the notifier" do
    test "stamps two successive NOTIFYs of one subscription with versions 0 and 1" do
      SIP.Test.PresenceUAS.serve(Fixture.Notifier)
      tp = attach("dialog-version")

      req = subscribe("dialog-version")
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = first}}, 2_000
      assert first.contenttype == @content_type

      assert {:ok, %Doc{version: 0, dialogs: [%Dialog{state: :confirmed}]}} =
               @package.parse(@content_type, body_of(first))

      Mockup.inject(tp, refresh(req, 2))
      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = second}}, 2_000
      assert {:ok, %Doc{version: 1, dialogs: []}} = @package.parse(@content_type, body_of(second))
    end
  end

  defp attach(instance) do
    {:ok, uri} = SIP.Uri.parse("sip:bob@unit.test")

    routed =
      SIP.Transport.Selector.select_transport(SIP.Uri.set_uri_param(uri, "unittest", instance))

    :ok = Mockup.attach_probe(routed.tp_pid)
    :ok = Mockup.set_peer(routed.tp_pid, Fixture.WatcherPeer)
    routed.tp_pid
  end

  defp subscribe(instance) do
    branch = SIP.Msg.Ops.generate_branch_value()
    {:ok, ruri} = SIP.Uri.parse("sip:bob@unit.test")

    from =
      SIP.Uri.set_header_param(
        %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "unit.test"},
        "tag",
        SIP.Msg.Ops.generate_from_or_to_tag()
      )

    %{
      "Max-Forwards" => "70",
      method: :SUBSCRIBE,
      ruri: SIP.Uri.set_uri_param(ruri, "unittest", instance),
      from: from,
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
      contact: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "82.184.8.2", port: 53_936},
      event: "dialog",
      accept: @content_type,
      expires: 120,
      callid: SIP.Msg.Ops.generate_from_or_to_tag(),
      cseq: [1, :SUBSCRIBE],
      transid: branch,
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      useragent: "Mockup-watcher",
      contentlength: 0
    }
  end

  defp refresh(req, cseq) do
    branch = SIP.Msg.Ops.generate_branch_value()

    %{
      req
      | cseq: [cseq, :SUBSCRIBE],
        transid: branch,
        via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"]
    }
  end

  defp body_of(msg) do
    case Map.get(msg, :body) do
      body when is_binary(body) -> body
      [%{data: data} | _] -> data
      _ -> nil
    end
  end
end
