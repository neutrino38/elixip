defmodule Kelix.OptionsScriptsTest do
  @moduledoc """
  The reference OPTIONS scripts (`apps/kelixip/scripts/options-keepalive.exs` and
  `options-probe-ua.exs`), served on an OPTIONS dialog (docs/design/options-plan.md).

  Tested here for the reason every reference script is: this is the only app where
  both halves exist — the script, and the `auth_db` / `registrar` modules it calls.
  The subscriber table is injected as a function (`:authdb_ha1_lookup`); the probed
  UA is reached through the in-process UDP mockup, whose peer answers OPTIONS 200.
  """
  use ExUnit.Case, async: false

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  alias Kelix.Mod.Registrar

  @domain "example.com"
  @caller "alice"
  @callee "bob"
  @password "secret"
  @ruri "sip:bob@example.com"

  @ha1 SIP.Auth.compute_ha1("MD5", @caller, @domain, @password)

  # The inbound leg: every reply the script sends is reported to the test.
  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()

    load = fn name ->
      SIP.Scenario.Loader.load_file!(Path.expand("../../kelixip/scripts/#{name}", __DIR__))
    end

    %{keepalive: load.("options-keepalive.exs"), probe: load.("options-probe-ua.exs")}
  end

  setup do
    start_supervised!(Registrar)

    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      @caller, @domain -> {:ok, @ha1}
      _user, _realm -> :notfound
    end)

    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    :ok
  end

  defp contact(host, peer) do
    %SIP.Uri{userpart: @callee, domain: host, port: 5060}
    |> SIP.Uri.set_uri_param("unittest", peer)
  end

  defp register_callee(host, peer) do
    req = %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: contact(host, peer),
      expires: 3600,
      callid: "reg-#{host}-#{peer}"
    }

    {:registered, _granted} = Registrar.save(req, @domain)

    tp = SIP.Transport.Selector.select_transport(contact(host, peer)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp options(user, auth \\ nil, cseq \\ 1) do
    req = %{
      "Max-Forwards" => 70,
      method: :OPTIONS,
      ruri: %SIP.Uri{userpart: user, domain: @domain},
      from: %SIP.Uri{userpart: @caller, domain: @domain, params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: user, domain: @domain},
      callid: "options-script-#{System.unique_integer([:positive])}",
      cseq: [cseq, :OPTIONS],
      contentlength: 0
    }

    if auth, do: Map.put(req, :proxyauthorization, auth), else: req
  end

  defp credentials(challenge) do
    nc = "00000001"
    cnonce = "0a4f113b"

    response =
      SIP.Auth.compute_auth_response_from_ha1(
        "MD5",
        challenge["nonce"],
        @ha1,
        "OPTIONS",
        @ruri,
        %{"nc" => nc, "cnonce" => cnonce, "qop" => "auth"}
      )

    %{
      "username" => @caller,
      "realm" => challenge["realm"],
      "nonce" => challenge["nonce"],
      "uri" => @ruri,
      "response" => response,
      "algorithm" => "MD5",
      "qop" => "auth",
      "nc" => nc,
      "cnonce" => cnonce
    }
  end

  defp spawn_instance(module, req) do
    {:ok, dialog} = MockDialog.start_link(self())

    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(module,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain]
      )

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    send(pid, {:OPTIONS, req, self(), dialog})
    {pid, dialog}
  end

  # Challenged, then re-submitted on the same dialog with credentials.
  defp authenticate!(pid, dialog, req) do
    assert_receive {:replied, 407, _reason, fields, _req}, 5_000
    challenge = Keyword.fetch!(fields, :proxyauthenticate)

    authenticated =
      %{options(@callee, credentials(challenge), 2) | callid: req.callid}

    send(pid, {:OPTIONS, authenticated, self(), dialog})
  end

  describe "options-keepalive.exs" do
    test "answers 200 with the core's Allow, then ends", %{keepalive: module} do
      {pid, _dialog} = spawn_instance(module, options(nil))
      ref = Process.monitor(pid)

      assert_receive {:replied, 200, "OK", fields, _req}, 5_000
      assert {"Allow", Kelix.Options.allow()} in fields

      # One ping, one instance: its max_calls slot is freed at once.
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2_000
    end
  end

  describe "options-probe-ua.exs" do
    test "an OPTIONS with no credentials is challenged 407, and nothing is relayed",
         %{probe: module} do
      _tp = register_callee("10.0.0.31", "opt_probe1")
      spawn_instance(module, options(@callee))

      assert_receive {:replied, 407, _reason, fields, _req}, 5_000
      challenge = Keyword.fetch!(fields, :proxyauthenticate)
      assert challenge["realm"] == @domain

      refute_receive {:sip_mockup, {:request_sent, :OPTIONS, _}}, 500
    end

    test "an authenticated probe of an unregistered UA is answered 480", %{probe: module} do
      req = options(@callee)
      {pid, dialog} = spawn_instance(module, req)
      authenticate!(pid, dialog, req)

      assert_receive {:replied, 480, _reason, _fields, _req}, 5_000
      refute_receive {:sip_mockup, {:request_sent, :OPTIONS, _}}, 200
    end

    test "an authenticated probe reaches the registered UA, and its answer comes back",
         %{probe: module} do
      _tp = register_callee("10.0.0.32", "opt_probe2")
      req = options(@callee)
      {pid, dialog} = spawn_instance(module, req)
      authenticate!(pid, dialog, req)

      assert_receive {:sip_mockup, {:request_sent, :OPTIONS, fwd}}, 5_000
      assert fwd.ruri.userpart == @callee
      assert fwd.ruri.domain == "10.0.0.32"
      # The sender's credentials are ours to check, never the UA's to see.
      refute Map.has_key?(fwd, :proxyauthorization)

      # The peer answers the OPTIONS 200 on its own; the answer crosses back.
      assert_receive {:replied, 200, _reason, _fields, %{method: :OPTIONS}}, 5_000
    end
  end

  # The whole chain, from the datagram to the script and back: Kelix.Options routes
  # the ping to the keepalive rule, the dialog layer opens an OPTIONS dialog, the
  # Router spawns the script through the pool, and its answer goes out.
  describe "on the wire" do
    setup do
      {:ok, _} = SIP.Session.ConfigRegistry.start()
      prev = SIP.Session.ConfigRegistry.get_options_processing_module()
      :ok = SIP.Session.ConfigRegistry.set_options_processing_module(Kelix.Options)

      dir = Path.join(System.tmp_dir!(), "options-wire-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      script = Path.expand("../../kelixip/scripts/options-keepalive.exs", __DIR__)
      path = Path.join(dir, "domains.toml")
      empty = Path.join(dir, "empty.toml")

      File.write!(path, """
      [[domain]]
      name = "wire.example"

      [[domain.options]]
      keepalive = true
      script    = "#{script}"
      """)

      File.write!(empty, "")
      :ok = Kelix.Domains.reload(path)

      on_exit(fn ->
        Kelix.Domains.reload(empty)
        File.rm_rf(dir)
        SIP.Session.ConfigRegistry.set_options_processing_module(prev)
      end)

      :ok
    end

    test "a ping on sip:domain is answered by options-keepalive.exs" do
      ruri =
        %SIP.Uri{scheme: "sip:", domain: "wire.example", port: 5060}
        |> SIP.Uri.set_uri_param("unittest", "options_wire")
        |> SIP.Transport.Selector.select_transport()

      :ok = Mockup.attach_probe(ruri.tp_pid)
      _snapshot = Kelix.InstancePool.subscribe_monitor(self())
      aor = %SIP.Uri{scheme: "sip:", userpart: "lb", domain: "wire.example"}
      cid = "opt-wire-#{System.unique_integer([:positive])}"

      Mockup.inject(ruri.tp_pid, %{
        "Max-Forwards" => "70",
        method: :OPTIONS,
        ruri: ruri,
        from: SIP.Uri.set_uri_param(aor, "tag", "lb-tag"),
        to: %SIP.Uri{scheme: "sip:", domain: "wire.example"},
        callid: cid,
        cseq: [1, :OPTIONS],
        contentlength: 0,
        via: ["SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK#{System.unique_integer([:positive])}"],
        transid: "z9hG4bK#{System.unique_integer([:positive])}"
      })

      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = resp}}, 5_000
      assert Map.get(resp, "Allow") == Kelix.Options.allow()

      # It was the script, not the core: an instance of it ran on this domain.
      assert_receive {:kelix_monitor, {:upsert, %{domain: "wire.example", function: :options}}},
                     2_000
    end
  end
end
