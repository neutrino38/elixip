defmodule SIP.Test.PublishLayer do
  @moduledoc """
  The publication layer (RFC 3903) over `SIP.Test.EventPackages.Dummy`, whose
  document is a line of text — no PIDF, no XML parser, no `presence` package.

  Same claim as the subscription suite makes for RFC 6665
  (docs/design/presence-basic-plan.md, P5): the layer reads a PUBLISH, refuses
  what it cannot serve and answers what it can, knowing nothing about the
  document it carries.
  """

  use SIP.Test.PublishSuite, traits: SIP.Test.SubscriptionTraits.Dummy
end

defmodule SIP.Test.PresencePublish do
  @moduledoc """
  The same suite over `SIP.EventPackage.Presence`: `Event: presence`,
  `application/pidf+xml`, and a `%SIP.Presence.Doc{}` where the dummy package
  had a string.
  """

  use SIP.Test.PublishSuite, traits: SIP.Test.SubscriptionTraits.Presence
end

defmodule SIP.Test.PresencePublishDocument do
  @moduledoc """
  What the parameterised suite cannot assert: a document the package **refuses**.

  The dummy package takes any line of text, so only a real one can be handed a
  body that is the right content type and still unreadable — the shape a
  handset sends when its XML is truncated, and the shape an attacker sends on
  purpose (P4 bounds what parsing one costs).
  """

  use ExUnit.Case, async: false

  alias SIP.Test.Transport.Mockup

  @package SIP.EventPackage.Presence
  @content_type "application/pidf+xml"

  defmodule Compositor do
    @moduledoc false
    use SIP.Scenario
    uas(:presence)
    config(domain: "unit.test")

    state initial_state do
      goto(publishing)
    end

    state publishing do
      on_events do
        {:PUBLISH, _req, _t, _d} ->
          case check_publish(package: "presence") do
            {:ok, pub} ->
              case SIP.Test.PublishCollection.publish(pub) do
                {:ok, etag, expires} ->
                  reply_publish(200, etag: etag, expires: expires)
                  scenario_success("published")

                {:ok, :removed} ->
                  reply_publish(200, expires: 0)
                  scenario_success("removed")

                {:error, 412} ->
                  reply_publish(412)
                  scenario_success("stale etag")
              end

            {:error, code} ->
              scenario_success("refused #{code}")
          end
      after
        5_000 -> scenario_failure("no PUBLISH received")
      end
    end
  end

  setup_all do
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    SIP.Test.AppEnv.preserve_proxy()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok = SIP.EventPackage.register(@package, origin: :builtin)
    on_exit(fn -> SIP.EventPackage.unregister(@package) end)
    :ok
  end

  setup do
    :ok = SIP.Test.PublishCollection.start()
    SIP.Test.PresenceUAS.serve(Compositor)
    :ok
  end

  test "a truncated PIDF document is answered 400 and published nowhere" do
    assert response("<?xml version=\"1.0\"?><presence entity=\"sip:bob@unit.test\">", "pidf-cut").response ==
             400

    assert SIP.Test.PublishCollection.all() == []
  end

  test "a document carrying a doctype is answered 400" do
    body = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE presence SYSTEM "pidf.dtd">
    <presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:bob@unit.test">
      <tuple id="t1"><status><basic>open</basic></status></tuple>
    </presence>
    """

    # The entity expansion P4 refuses outright: a PIDF document has no use for a
    # DTD, and every entity attack needs one. Refused here as a body the package
    # cannot read, which is a 400 and not a crash.
    assert response(body, "pidf-doctype").response == 400
    assert SIP.Test.PublishCollection.all() == []
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp response(body, instance) do
    {:ok, uri} = SIP.Uri.parse("sip:bob@unit.test")

    routed =
      SIP.Transport.Selector.select_transport(SIP.Uri.set_uri_param(uri, "unittest", instance))

    :ok = Mockup.attach_probe(routed.tp_pid)

    branch = SIP.Msg.Ops.generate_branch_value()
    callid = SIP.Msg.Ops.generate_from_or_to_tag()

    req = %{
      "Max-Forwards" => "70",
      method: :PUBLISH,
      ruri: SIP.Uri.set_uri_param(uri, "unittest", instance),
      from:
        SIP.Uri.set_header_param(
          %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
          "tag",
          SIP.Msg.Ops.generate_from_or_to_tag()
        ),
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
      event: "presence",
      expires: 3600,
      callid: callid,
      cseq: [1, :PUBLISH],
      transid: branch,
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      useragent: "Mockup-publisher",
      contenttype: @content_type,
      body: body,
      contentlength: byte_size(body)
    }

    Mockup.inject(routed.tp_pid, req)
    await_response(callid)
  end

  defp await_response(callid) do
    receive do
      {:sip_mockup, {:response_sent, code, %{callid: ^callid} = rsp}} when code >= 200 -> rsp
      {:sip_mockup, _other} -> await_response(callid)
    after
      3_000 -> flunk("no final response to the PUBLISH on call #{callid}")
    end
  end
end

defmodule SIP.Test.PublicationPublisher do
  @moduledoc """
  `SIP.Publication.same_publisher?/2` and `connection/1`: the publisher is the
  flow a PUBLISH came in on — the connection over TCP/TLS/WSS, the source
  address over UDP — since the request itself names no device.
  """

  use ExUnit.Case, async: true

  defp pub(flow), do: %SIP.Publication{flow: flow}

  defp connected(pid),
    do: %{received: {:wss, {10, 0, 0, 7}, 40_000}, tp_pid: pid, tp_module: SIP.Transport.WSS}

  defp udp(port),
    do: %{received: {:udp, {10, 0, 0, 7}, port}, tp_pid: self(), tp_module: SIP.Transport.UDP}

  test "over a connection, the connection is the publisher — not the address" do
    other = spawn(fn -> :ok end)
    assert SIP.Publication.same_publisher?(pub(connected(self())), pub(connected(self())))
    refute SIP.Publication.same_publisher?(pub(connected(self())), pub(connected(other)))
  end

  # One UDP transport instance serves every peer: its pid names nobody.
  test "over UDP, the source address and port are" do
    assert SIP.Publication.same_publisher?(pub(udp(5070)), pub(udp(5070)))
    refute SIP.Publication.same_publisher?(pub(udp(5070)), pub(udp(5080)))
  end

  test "an unknown flow is nobody's" do
    refute SIP.Publication.same_publisher?(pub(nil), pub(nil))

    refute SIP.Publication.same_publisher?(
             pub(%{received: nil, tp_pid: nil, tp_module: nil}),
             pub(nil)
           )
  end

  test "only a connection-oriented flow binds a publication" do
    assert SIP.Publication.connection(pub(connected(self()))) == self()
    assert SIP.Publication.connection(pub(udp(5070))) == nil
    assert SIP.Publication.connection(pub(nil)) == nil
  end
end
