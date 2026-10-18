defmodule SIP.Test.TLSOutboundVerify do
  @moduledoc """
  Step 7 of `docs/design/multi-interface.md`: the outbound TLS/WSS leg checks the
  certificate it is offered.

  Not `async`: the two keys under test are node-wide application env.
  """
  use ExUnit.Case, async: false

  alias SIP.Transport.ImplHelpers

  @certs Path.expand("../certs", __DIR__)

  setup do
    previous = [
      verify: Application.fetch_env(:elixip2, :tls_verify),
      ca: Application.fetch_env(:elixip2, :tls_cacertfile)
    ]

    on_exit(fn ->
      restore(:tls_verify, previous[:verify])
      restore(:tls_cacertfile, previous[:ca])
    end)

    :ok
  end

  defp restore(key, {:ok, value}), do: Application.put_env(:elixip2, key, value)
  defp restore(key, :error), do: Application.delete_env(:elixip2, key)

  describe "what the leg asks :ssl for" do
    test "no check unless asked for: verifying a peer is an interconnect decision" do
      Application.delete_env(:elixip2, :tls_verify)

      opts = ImplHelpers.peer_verification_options(%{destdomain: "proxy.example.com"})

      assert opts == [verify: false]
    end

    test "turned on, the name matched is the DOMAIN the URI named" do
      Application.put_env(:elixip2, :tls_verify, true)

      opts = ImplHelpers.peer_verification_options(%{destdomain: "proxy.example.com"})

      assert opts[:verify] == true
      # RFC 5922 §7.2: the identity in the certificate is the SIP domain, never the
      # address DNS resolved it to.
      assert opts[:server_name] == "proxy.example.com"
    end

    test "a leg aimed at a bare address states no name" do
      Application.put_env(:elixip2, :tls_verify, true)

      opts = ImplHelpers.peer_verification_options(%{destdomain: nil})

      assert opts[:verify] == true
      refute Keyword.has_key?(opts, :server_name)
    end

    test "a configured authority is the only one trusted" do
      Application.put_env(:elixip2, :tls_verify, true)
      Application.put_env(:elixip2, :tls_cacertfile, "/etc/pki/proxy-ca.pem")

      opts = ImplHelpers.peer_verification_options(%{destdomain: "proxy.example.com"})

      assert opts[:authorities] == [path: "/etc/pki/proxy-ca.pem"]
    end
  end

  describe "against a real TLS server" do
    # The repository's own certificate: self-signed, and carrying neither a CN nor
    # a subjectAltName. Nothing can verify it, which is exactly what makes it the
    # right peer for these two tests.
    defp tls_server() do
      {:ok, listener} =
        :ssl.listen(0, [
          :binary,
          {:active, false},
          {:reuseaddr, true},
          {:ip, {127, 0, 0, 1}},
          {:certfile, Path.join(@certs, "certificate.pem")},
          {:keyfile, Path.join(@certs, "private_key.pem")},
          {:versions, [:"tlsv1.2"]}
        ])

      {:ok, {_ip, port}} = :ssl.sockname(listener)

      # The acceptor has to OUTLIVE the handshake. A task that returns as soon as
      # it has shaken hands owns the socket, so its exit closes the connection —
      # and the client then fails with "closed" whatever the certificate said,
      # which is a passing test for the wrong reason.
      spawn(fn ->
        with {:ok, t} <- :ssl.transport_accept(listener, 3_000),
             do: :ssl.handshake(t, 3_000)

        Process.sleep(5_000)
      end)

      on_exit(fn -> :ssl.close(listener) end)
      port
    end

    test "an unverifiable certificate is refused, and it is the certificate" do
      Application.put_env(:elixip2, :tls_verify, true)
      Application.delete_env(:elixip2, :tls_cacertfile)
      port = tls_server()

      assert {:error, :cnxerror} =
               GenServer.start(SIP.Transport.TLS, {{127, 0, 0, 1}, port, "unit.test"})

      # Named, so the test cannot pass on a closed socket or a refused port: the
      # handshake got far enough for us to reject what was presented.
      assert {:error, {:tls_alert, {alert, _}}} =
               Socket.SSL.connect({127, 0, 0, 1}, tls_server(),
                 verify: true,
                 versions: [:"tlsv1.2"],
                 timeout: 3_000
               )

      assert alert in [:bad_certificate, :unknown_ca, :handshake_failure]
    end

    test "and accepted by default, where nothing asked for the check" do
      Application.delete_env(:elixip2, :tls_verify)
      port = tls_server()

      assert {:ok, pid} =
               GenServer.start(SIP.Transport.TLS, {{127, 0, 0, 1}, port, "unit.test"})

      on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    end
  end

  describe "the client certificate, against a server that demands one" do
    setup do
      previous = [
        cert: Application.fetch_env(:elixip2, :tls_certfile),
        key: Application.fetch_env(:elixip2, :tls_keyfile)
      ]

      Application.delete_env(:elixip2, :tls_verify)

      on_exit(fn ->
        restore(:tls_certfile, previous[:cert])
        restore(:tls_keyfile, previous[:key])
      end)

      :ok
    end

    # Mutual TLS as Teams Direct Routing does it: no certificate, no connection.
    # The acceptor reports its own handshake, since a client that offers nothing
    # may still believe it connected. It accepts any certificate presented: the
    # repository's own cannot be verified, and the question here is whether one
    # is presented at all.
    defp mtls_server() do
      {:ok, listener} =
        :ssl.listen(0, [
          :binary,
          {:active, false},
          {:reuseaddr, true},
          {:ip, {127, 0, 0, 1}},
          {:certfile, Path.join(@certs, "certificate.pem")},
          {:keyfile, Path.join(@certs, "private_key.pem")},
          {:cacertfile, Path.join(@certs, "certificate.pem")},
          {:verify, :verify_peer},
          {:verify_fun, {fn _cert, _event, state -> {:valid, state} end, nil}},
          {:fail_if_no_peer_cert, true},
          {:versions, [:"tlsv1.2"]}
        ])

      {:ok, {_ip, port}} = :ssl.sockname(listener)
      test = self()

      spawn(fn ->
        with {:ok, t} <- :ssl.transport_accept(listener, 3_000) do
          send(test, {:server_handshake, :ssl.handshake(t, 3_000)})
        end

        Process.sleep(5_000)
      end)

      on_exit(fn -> :ssl.close(listener) end)
      port
    end

    test "configured, it is presented" do
      Application.put_env(:elixip2, :tls_certfile, Path.join(@certs, "certificate.pem"))
      Application.put_env(:elixip2, :tls_keyfile, Path.join(@certs, "private_key.pem"))
      port = mtls_server()

      _ = GenServer.start(SIP.Transport.TLS, {{127, 0, 0, 1}, port, "unit.test"})

      assert_receive {:server_handshake, {:ok, _socket}}, 5_000
    end

    test "absent, the server refuses the connection" do
      Application.delete_env(:elixip2, :tls_certfile)
      Application.delete_env(:elixip2, :tls_keyfile)
      port = mtls_server()

      _ = GenServer.start(SIP.Transport.TLS, {{127, 0, 0, 1}, port, "unit.test"})

      assert_receive {:server_handshake, {:error, {:tls_alert, {:handshake_failure, why}}}},
                     5_000

      assert to_string(why) =~ "no_client_certificate_provided"
    end
  end
end
