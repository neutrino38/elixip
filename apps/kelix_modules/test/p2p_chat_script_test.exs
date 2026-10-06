defmodule Kelix.P2PChatScriptTest do
  @moduledoc """
  The reference chat scripts end to end (chat-basic-plan, C8): Alice's MESSAGEs
  come off a Mockup transport into the kelixip router, which hands them to
  `p2p-chat.exs`; Bob's REGISTERs reach `registrar-chat.exs` the same way. Bob's
  devices are Mockup instances answering each MESSAGE as the test says. The
  Silo runs on the in-memory store its SQL one is tested against.

  Here because this is the one app where the scripts and the modules they call
  (`registrar`, `auth_db`, `presence`, `silo`) are all present.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mod.{Presence, Registrar, Silo}
  alias SIP.Test.Transport.Mockup

  @domain "chat.example"
  @password "secret"
  @chat Path.expand("../../kelixip/scripts/p2p-chat.exs", __DIR__)
  @registrar Path.expand("../../kelixip/scripts/registrar-chat.exs", __DIR__)

  defmodule Device do
    @moduledoc "Bob's device: answers each MESSAGE with `code`, reports it to the test."
    use SIP.Test.Peer

    @impl true
    def on_request(%{method: :MESSAGE} = req, state) do
      send(:p2p_chat_test, {:device_got, state.name, req})
      {[reply(req, Map.get(state, :code, 200), "Answer", [], 0)], state}
    end

    def on_request(req, state), do: default_request(req, state)
  end

  setup do
    Process.register(self(), :p2p_chat_test)

    Kelix.Test.Fixtures.serve_domains("""
    [[domain]]
    name = "#{@domain}"

      [domain.registrar]
      script = "#{@registrar}"

      [[domain.chat]]
      default = true
      script = "#{@chat}"
    """)

    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      # every test writes as an Alice of its own: all Mockup transports share
      # one source address, so two tests with one sender would be one
      # conversation — already authenticated — by the router's rule
      "alice" <> _ = user, @domain ->
        {:ok, SIP.Auth.compute_ha1("MD5", user, @domain, @password)}

      "bob" = user, @domain ->
        {:ok, SIP.Auth.compute_ha1("MD5", user, @domain, @password)}

      _user, _realm ->
        :notfound
    end)

    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)

    start_supervised!(Registrar)
    start_supervised!(Presence)
    start_supervised!({Task.Supervisor, name: Kelix.Mod.Silo.Tasks})
    {:ok, store} = Kelix.Test.SiloMemoryStore.start_link()

    silo = [store: Kelix.Test.SiloMemoryStore, handle: store, page_timeout: 3, retry_ms: 50]
    start_supervised!(%{id: Silo, start: {Silo, :start_link, [silo]}})

    for {name, module} <- [
          registrar: Registrar,
          auth_db: Kelix.Mod.AuthDb,
          presence: Presence,
          silo: Silo
        ],
        do: Kelix.Test.Fixtures.with_module(to_string(name), module)

    %{store: store}
  end

  # ── the parties ──────────────────────────────────────────────────────────────

  # A transport of Alice's or Bob's, as the router sees one: a Mockup instance.
  defp flow(instance) do
    tp = SIP.Transport.Selector.select_transport(mockup_uri("peer", instance)).tp_pid
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp mockup_uri(user, instance) do
    %SIP.Uri{scheme: "sip:", userpart: user, domain: @domain}
    |> SIP.Uri.set_uri_param("unittest", instance)
  end

  # Bob's device: where a page to it goes, and what it answers.
  defp device(name, opts \\ []) do
    contact =
      "<sip:bob@#{name}.chat.example;unittest=bob-#{name}>;+sip.instance=\"<urn:uuid:#{name}>\""

    {:ok, uri} = SIP.Uri.parse(contact)
    tp = SIP.Transport.Selector.select_transport(uri).tp_pid
    :ok = Mockup.set_peer(tp, Device, [name: name] ++ opts)
    uri
  end

  defp request(method, instance, fields) do
    branch = SIP.Msg.Ops.generate_branch_value()

    Map.merge(
      %{
        "Max-Forwards" => "70",
        method: method,
        ruri: SIP.Transport.Selector.select_transport(mockup_uri(nil, instance)),
        transid: branch,
        via: ["SIP/2.0/UDP 10.0.0.1:5060;branch=#{branch}"],
        contentlength: 0
      },
      fields
    )
  end

  defp message(instance, to, body, opts \\ []) do
    ruri =
      %SIP.Uri{scheme: "sip:", userpart: to, domain: @domain}
      |> SIP.Uri.set_uri_param("unittest", instance)
      |> SIP.Transport.Selector.select_transport()

    req =
      request(:MESSAGE, instance, %{
        ruri: ruri,
        from: %SIP.Uri{
          scheme: "sip:",
          userpart: instance,
          domain: @domain,
          hparams: %{"tag" => "a-#{System.unique_integer([:positive])}"}
        },
        to: %SIP.Uri{scheme: "sip:", userpart: to, domain: @domain},
        callid: "chat-#{System.unique_integer([:positive])}",
        cseq: [1, :MESSAGE],
        contenttype: Keyword.get(opts, :type, "text/plain"),
        body: body,
        contentlength: byte_size(body)
      })

    case Keyword.get(opts, :auth) do
      nil -> req
      auth -> Map.put(req, :proxyauthorization, auth)
    end
  end

  defp credentials(challenge, user, method, uri) do
    ha1 = SIP.Auth.compute_ha1("MD5", user, @domain, @password)
    params = %{"nc" => "00000001", "cnonce" => "0a4f113b", "qop" => "auth"}

    %{
      :authproc => "Digest",
      "username" => user,
      "realm" => challenge["realm"],
      "nonce" => challenge["nonce"],
      "uri" => uri,
      "response" =>
        SIP.Auth.compute_auth_response_from_ha1(
          "MD5",
          challenge["nonce"],
          ha1,
          method,
          uri,
          params
        ),
      "algorithm" => "MD5",
      "qop" => "auth",
      "nc" => "00000001",
      "cnonce" => "0a4f113b"
    }
  end

  defp final_response(code_wanted \\ nil) do
    receive do
      {:sip_mockup, {:response_sent, code, rsp}} when code >= 200 ->
        if code_wanted, do: assert(code == code_wanted, "got #{code}, wanted #{code_wanted}")
        rsp

      {:sip_mockup, _other} ->
        final_response(code_wanted)
    after
      5_000 -> flunk("no final response")
    end
  end

  # Alice's first MESSAGE to `to` on `instance`: challenged, then sent again
  # with her credentials. What the node answered the second one.
  defp alice_writes(instance, to, body, opts \\ []) do
    tp = flow(instance)
    Mockup.inject(tp, message(instance, to, body, opts))
    challenge = final_response(407).proxyauthenticate
    auth = credentials(challenge, instance, "MESSAGE", "sip:#{to}@#{@domain}")
    Mockup.inject(tp, message(instance, to, body, Keyword.put(opts, :auth, auth)))
    {tp, final_response()}
  end

  # Bob's device registering through registrar-chat.exs: challenged, then 200.
  defp bob_registers(instance, contact, cseq \\ 1) do
    tp = flow(instance)
    callid = "reg-#{instance}"

    register = fn cseq, auth ->
      fields = %{
        ruri:
          SIP.Transport.Selector.select_transport(
            %SIP.Uri{scheme: "sip:", domain: @domain}
            |> SIP.Uri.set_uri_param("unittest", instance)
          ),
        from: %SIP.Uri{
          scheme: "sip:",
          userpart: "bob",
          domain: @domain,
          hparams: %{"tag" => "b-#{instance}"}
        },
        to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: @domain},
        contact: contact,
        expires: "3600",
        callid: callid,
        cseq: [cseq, :REGISTER]
      }

      req = request(:REGISTER, instance, fields)
      if auth, do: Map.put(req, :authorization, auth), else: req
    end

    Mockup.inject(tp, register.(cseq, nil))
    challenge = final_response(401).wwwauthenticate
    Mockup.inject(tp, register.(cseq + 1, credentials(challenge, "bob", "REGISTER", "sip:#{@domain}")))
    final_response(200)
  end

  # A device of Bob's registered straight into the store, not through a script.
  defp registered(name, opts \\ []) do
    req = %{
      method: :REGISTER,
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: @domain},
      ruri: %SIP.Uri{scheme: "sip:", domain: @domain},
      contact: [device(name, opts)],
      expires: "3600",
      callid: "reg-direct-#{name}"
    }

    assert {:registered, _} = Registrar.save(req, @domain)
  end

  # ── the tests ────────────────────────────────────────────────────────────────

  test "Bob online on two devices: both get it, Alice one 200; the next MESSAGE is not challenged" do
    registered(:phone)
    registered(:desk, code: 480)

    {tp, rsp} = alice_writes("alice-1", "bob", "Rendez-vous jeudi")
    assert rsp.response == 200
    assert_receive {:device_got, :phone, _}, 3_000
    assert_receive {:device_got, :desk, _}, 3_000

    # Same flow, same parties: the conversation, already authenticated.
    Mockup.inject(tp, message("alice-1", "bob", "à 18 h"))
    assert final_response().response == 200
    assert_receive {:device_got, :phone, second}, 3_000
    assert SIP.Msg.Ops.body_string(second) == "à 18 h"
  end

  test "Bob offline: 202 and stored; his REGISTER through registrar-chat.exs brings it, dated", %{
    store: store
  } do
    {_tp, rsp} = alice_writes("alice-2", "bob", "Rendez-vous jeudi")
    assert rsp.response == 202
    assert {:ok, [%{size: 17}]} = Kelix.Test.SiloMemoryStore.list(store, @domain, "bob", now())

    bob_registers("bob-laptop", device(:laptop))
    assert_receive {:device_got, :laptop, delivered}, 5_000
    assert SIP.Msg.Ops.body_string(delivered) == "Rendez-vous jeudi"
    assert SIP.Msg.Ops.address_of_record(delivered, :from) == "alice-2@#{@domain}"
    assert Map.has_key?(delivered, "Date")

    # a refresh of the same device brings nothing again
    bob_registers("bob-laptop", device(:laptop), 3)
    refute_receive {:device_got, :laptop, _}, 500
  end

  test "a refusal is relayed and nothing is stored", %{store: store} do
    registered(:phone, code: 603)

    {_tp, rsp} = alice_writes("alice-3", "bob", "hello")
    assert rsp.response == 603
    assert {:ok, []} = Kelix.Test.SiloMemoryStore.list(store, @domain, "bob", now())
  end

  test "an undelivered typing indicator is 480 and not stored", %{store: store} do
    {_tp, rsp} =
      alice_writes("alice-4", "bob", "<isComposing/>", type: "application/im-iscomposing+xml")

    assert rsp.response == 480
    assert {:ok, []} = Kelix.Test.SiloMemoryStore.list(store, @domain, "bob", now())
  end

  test "a recipient nobody provisioned is 404, after the sender proved who she is", %{
    store: store
  } do
    {_tp, rsp} = alice_writes("alice-5", "mallory", "hello")
    assert rsp.response == 404
    assert {:ok, []} = Kelix.Test.SiloMemoryStore.list(store, @domain, "mallory", now())
  end

  test "the Silo down: 503", %{store: store} do
    Kelix.Test.SiloMemoryStore.set_down(store, true)
    {_tp, rsp} = alice_writes("alice-6", "bob", "hello")
    assert rsp.response == 503
  end

  defp now, do: System.os_time(:second)
end
