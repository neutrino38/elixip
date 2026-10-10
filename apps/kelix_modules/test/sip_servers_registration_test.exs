defmodule Kelix.Mod.SipServersRegistrationTest do
  @moduledoc """
  A trunk's registration and the answer to its challenges (lot L4 of
  `docs/design/sip-server-specs.md`).

  The registrar is a `Manual` mockup peer: the test sees each REGISTER go out, then
  says how the registrar answers it. Its challenges are for realm `elioz.net`,
  SHA-256.
  """
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  import SIP.Test.Wait

  alias Kelix.Mod.SipServers
  alias Kelix.Mod.SipServers.{Credentials, Server}
  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @domain "example.com"

  # Every server of this suite lives at a 10.0.2.x address of its own.
  defmodule FakeDns do
    def resolve(server) do
      targets =
        for uri <- [server.primary_uri, server.backup_uri], uri != nil, into: %{} do
          {:ok, parsed} = SIP.Uri.parse(uri)
          n = :erlang.phash2(parsed.domain, 250) + 1
          {uri, [{"UDP", {10, 0, 2, n}, 5060}]}
        end

      {:ok, targets, 300}
    end
  end

  setup_all do
    toml = Path.join(System.tmp_dir!(), "sip_servers_registration_domains.toml")
    File.write!(toml, ~s([[domain]]\nname = "example.com"\n))
    :ok = Kelix.Domains.reload(toml)
    Application.put_env(:kelix_modules, :sip_servers_resolver, FakeDns)

    on_exit(fn ->
      Application.delete_env(:kelix_modules, :sip_servers_resolver)
      empty = Path.join(System.tmp_dir!(), "sip_servers_registration_empty.toml")
      File.write!(empty, "")
      _ = Kelix.Domains.reload(empty)
      File.rm(toml)
    end)

    :ok
  end

  setup do
    start_supervised!(SipServers.child_spec(:sip_servers, %{}))
    :ok
  end

  defp uri(name), do: "sip:0123456789@#{name}.example.net;unittest=#{name}"

  defp registrar!(name) do
    tp = SIP.Transport.Selector.select_transport(uri(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual, [])
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp trunk(slug, extra) do
    args =
      Map.merge(
        %{
          "domain" => @domain,
          "slug" => slug,
          "type" => "sip-trunk",
          "primary_uri" => uri(slug),
          "send_keepalive" => "false",
          "auth_username" => "0123456789",
          "auth_realm" => "elioz.net",
          "auth_password" => "secret"
        },
        extra
      )

    {:ok, _} = SipServers.handle_control("server.create", args)
    :ok
  end

  defp registration(slug) do
    {:ok, shown} =
      SipServers.handle_control("server.show", %{"domain" => @domain, "slug" => slug})

    shown.registration
  end

  # The probe hands over the request as it went out: From, To and Contact are the
  # header values as written.
  defp parsed(%SIP.Uri{} = uri), do: uri
  defp parsed([value | _]), do: parsed(value)

  defp parsed(value) when is_binary(value) do
    {:ok, uri} = SIP.Uri.parse(value)
    uri
  end

  defp expires(req), do: SIP.Uri.get_header_param(parsed(req.contact), "expires")

  defp next_register! do
    assert_receive {:sip_mockup, {:request_sent, :REGISTER, req}}, 3_000
    req
  end

  test "a challenged REGISTER is answered, then the trunk is registered" do
    tp = registrar!("reg1")
    :ok = trunk("reg1", %{})

    first = next_register!()
    assert first.ruri.userpart == nil
    assert first.ruri.domain == "reg1.example.net"
    assert parsed(first.from).userpart == "0123456789"
    assert parsed(first.to).userpart == "0123456789"
    assert expires(first) == {:ok, "600"}
    assert registration("reg1").state == "registering"

    :ok = Manual.simulate(tp, 401, 0)
    second = next_register!()
    auth = second.authorization
    assert auth["username"] == "0123456789"
    assert auth["realm"] == "elioz.net"
    assert auth["algorithm"] == "SHA-256"
    assert second.callid == first.callid
    assert hd(second.cseq) == hd(first.cseq) + 1

    :ok = Manual.simulate(tp, 200, 0)
    until!(fn -> registration("reg1") == %{state: "registered", error: nil} end)
  end

  test "deleting a registered trunk un-registers it" do
    tp = registrar!("reg2")
    :ok = trunk("reg2", %{})
    _ = next_register!()
    :ok = Manual.simulate(tp, 200, 0)
    until!(fn -> registration("reg2").state == "registered" end)

    {:ok, _} =
      SipServers.handle_control("server.delete", %{"domain" => @domain, "slug" => "reg2"})

    bye = next_register!()
    assert expires(bye) == {:ok, "0"}
  end

  test "register = false: no REGISTER, but its calls still answer challenges" do
    _tp = registrar!("reg5")
    :ok = trunk("reg5", %{"register" => "false"})

    refute_receive {:sip_mockup, {:request_sent, :REGISTER, _}}, 300
    assert registration("reg5") == nil

    {_req, %SIP.B2bua.Peer{credentials: link}} =
      SipServers.forward(@domain, %{method: :INVITE, ruri: %SIP.Uri{userpart: "3000"}}, "reg5")

    assert is_pid(link)
  end

  test "turning register off un-registers a registered trunk" do
    tp = registrar!("reg6")
    :ok = trunk("reg6", %{})
    _ = next_register!()
    :ok = Manual.simulate(tp, 200, 0)
    until!(fn -> registration("reg6").state == "registered" end)

    {:ok, _} =
      SipServers.handle_control("server.update", %{
        "domain" => @domain,
        "slug" => "reg6",
        "register" => "false"
      })

    assert expires(next_register!()) == {:ok, "0"}
    refute_receive {:sip_mockup, {:request_sent, :REGISTER, _}}, 300
    assert registration("reg6") == nil
  end

  test "credentials refused twice: failed, and said" do
    tp = registrar!("reg3")
    :ok = trunk("reg3", %{})
    _ = next_register!()

    capture_log(fn ->
      :ok = Manual.simulate(tp, 401, 0)
      _ = next_register!()
      :ok = Manual.simulate(tp, 401, 0)
      until!(fn -> registration("reg3").state == "failed" end)
    end)

    assert registration("reg3").error =~ "credentials refused"
  end

  test "a challenge for another realm is refused, naming both realms" do
    tp = registrar!("reg4")
    :ok = trunk("reg4", %{"auth_realm" => "operator.net"})
    _ = next_register!()

    log =
      capture_log(fn ->
        :ok = Manual.simulate(tp, 401, 0)
        until!(fn -> registration("reg4").state == "failed" end)
      end)

    assert log =~ "elioz.net"
    assert log =~ "operator.net"
    refute_receive {:sip_mockup, {:request_sent, :REGISTER, _}}, 300
  end

  describe "Credentials.authorize/4" do
    defp server(password \\ "secret") do
      {:ok, s} =
        Server.build(%{
          "domain" => @domain,
          "slug" => "t",
          "type" => "sip-trunk",
          "primary_uri" => "sip:0123456789@sbc.operator.net",
          "auth_username" => "0123456789",
          "auth_realm" => "operator.net",
          "auth_password" => password
        })

      s
    end

    defp challenge(extra),
      do: Map.merge(%{"realm" => "operator.net", "nonce" => "abc"}, extra)

    test "the response is the digest of the password, MD5 by default" do
      {:ok, params} =
        Credentials.authorize(server(), challenge(%{}), :INVITE, "sip:3000@sbc.operator.net")

      ha1 = :crypto.hash(:md5, "0123456789:operator.net:secret") |> Base.encode16(case: :lower)
      ha2 = :crypto.hash(:md5, "INVITE:sip:3000@sbc.operator.net") |> Base.encode16(case: :lower)
      expected = :crypto.hash(:md5, "#{ha1}:abc:#{ha2}") |> Base.encode16(case: :lower)

      assert params["response"] == expected
      refute Map.has_key?(params, "qop")
    end

    test "qop=auth when offered, with the opaque echoed" do
      {:ok, params} =
        Credentials.authorize(
          server(),
          challenge(%{"qop" => "auth,auth-int", "opaque" => "o1", "algorithm" => "SHA-256"}),
          :REGISTER,
          "sip:sbc.operator.net"
        )

      assert params["qop"] == "auth"
      assert params["nc"] == "00000001"
      assert params["opaque"] == "o1"
      assert params["algorithm"] == "SHA-256"
    end

    test "what it cannot answer" do
      assert {:error, {:realm_mismatch, "operator.net", "x.net"}} =
               Credentials.authorize(
                 server(),
                 %{"realm" => "x.net", "nonce" => "n"},
                 :INVITE,
                 "u"
               )

      assert {:error, {:unsupported_algorithm, "SHA-512-256"}} =
               Credentials.authorize(
                 server(),
                 challenge(%{"algorithm" => "SHA-512-256"}),
                 :INVITE,
                 "u"
               )
    end
  end
end
