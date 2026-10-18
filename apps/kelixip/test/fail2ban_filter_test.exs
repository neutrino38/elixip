defmodule Kelix.Fail2banFilterTest do
  # The shipped filters against the lines the reporter writes. The emitted line
  # and the regex that reads it live in two files, and drift between them is
  # silent: the jail stops banning and nobody notices. This is the test the
  # discussion asked for (integration-fail2ban.md §8).
  #
  # `<HOST>` is fail2ban's own placeholder; it is stood in for here by an IPv4 or
  # IPv6 literal pattern. This is NOT a proof that fail2ban matches the lines —
  # that is `fail2ban-regex` on a host that has it (fail2ban-plan.md phase 7).
  use ExUnit.Case, async: true

  alias Elixip.Security.Incident

  @filter_dir Path.expand("../../../packaging/fail2ban/filter.d", __DIR__)
  @host "(?<host>(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9a-fA-F:]+))"

  defp failregexes(jail) do
    content = File.read!(Path.join(@filter_dir, "#{jail}.conf"))

    [_, block] = Regex.run(~r/^failregex\s*=\s*(.*?)^\S/ms, content <> "\n[end]")

    block
    |> String.split("\n", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(fn re -> Regex.compile!(String.replace(re, "<HOST>", @host)) end)
  end

  defp host(jail, line) do
    jail
    |> failregexes()
    |> Enum.find_value(fn re -> Regex.named_captures(re, line) end)
    |> case do
      %{"host" => host} -> host
      nil -> nil
    end
  end

  # The line as the reporter writes it to the file, and as the journal shows it.
  defp file_line(incident), do: "2026-10-07T12:34:56Z kelixip: " <> to_string(incident)
  defp journal_line(incident), do: "[warning] kelixip: " <> to_string(incident)

  @auth %Incident{
    type: :auth_failure,
    src: {192, 0, 2, 5},
    port: 5060,
    proto: "UDP",
    method: :REGISTER,
    realm: "example.com",
    user: "alice",
    reason: :bad_password
  }

  test "every filter file parses to at least one failregex" do
    for jail <- ~w(kelixip-auth kelixip-scan kelixip-api kelixip-packet) do
      assert [_ | _] = failregexes(jail), "#{jail} has no failregex"
    end
  end

  test "kelixip-auth: a wrong password, from the file and from the journal" do
    assert host("kelixip-auth", file_line(@auth)) == "192.0.2.5"
    assert host("kelixip-auth", journal_line(@auth)) == "192.0.2.5"
  end

  test "kelixip-auth: an IPv6 source" do
    line = file_line(%Incident{@auth | src: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}})
    assert host("kelixip-auth", line) == "2001:db8::1"
  end

  test "kelixip-auth: the real source when the username carries a forged one" do
    forged = %Incident{
      @auth
      | user: ~s(x" src=203.0.113.9 port=1 proto=UDP method=REGISTER reason=bad_password)
    }

    assert host("kelixip-auth", file_line(forged)) == "192.0.2.5"
  end

  test "kelixip-auth: a credential with no username (bad_realm never counts here anyway)" do
    assert host("kelixip-auth", file_line(%Incident{@auth | user: nil})) == "192.0.2.5"
  end

  test "kelixip-auth matches neither a scanner's line nor a stray REGISTER log line" do
    assert host("kelixip-auth", file_line(%Incident{@auth | reason: :unknown_user})) == nil
    assert host("kelixip-auth", file_line(%Incident{@auth | reason: :bad_realm})) == nil
    assert host("kelixip-auth", "[debug] UDP: Message received from 192.0.2.5:5060 <----") == nil
    assert host("kelixip-auth", "REGISTER sip:example.com SIP/2.0") == nil
  end

  test "kelixip-scan: unknown user, foreign realm, unknown domain, no domain" do
    assert host("kelixip-scan", file_line(%Incident{@auth | reason: :unknown_user})) ==
             "192.0.2.5"

    assert host("kelixip-scan", file_line(%Incident{@auth | reason: :bad_realm, user: nil})) ==
             "192.0.2.5"

    domain = %Incident{
      type: :invalid_domain,
      src: {203, 0, 113, 7},
      port: 5060,
      proto: "TCP",
      method: :INVITE,
      reason: :unknown_domain
    }

    assert host("kelixip-scan", file_line(domain)) == "203.0.113.7"

    assert host("kelixip-scan", journal_line(%Incident{domain | reason: :no_domain})) ==
             "203.0.113.7"
  end

  test "kelixip-scan does not count a wrong password" do
    assert host("kelixip-scan", file_line(@auth)) == nil
  end

  test "kelixip-api: the three credential failures, never a path" do
    api = %Incident{
      type: :api_auth,
      src: {198, 51, 100, 2},
      port: 51000,
      proto: "HTTP",
      method: "GET"
    }

    for reason <- [:missing_token, :invalid_token, :no_client_cert] do
      line = file_line(%Incident{api | reason: reason})
      refute line =~ "/"
      assert host("kelixip-api", line) == "198.51.100.2", line
    end

    assert host("kelixip-api", file_line(@auth)) == nil
  end

  test "kelixip-packet: every invalid-packet and transport-error reason" do
    packet = %Incident{type: :invalid_packet, src: {192, 0, 2, 9}, port: 40000, proto: "UDP"}

    for reason <- [:unparsable, :too_large, :bad_frame, :garbage] do
      assert host("kelixip-packet", file_line(%Incident{packet | reason: reason})) == "192.0.2.9"
    end

    tls = %Incident{type: :transport_error, src: {192, 0, 2, 9}, port: 40001, proto: "TLS"}

    for reason <- [:tls_handshake, :ws_upgrade] do
      assert host("kelixip-packet", journal_line(%Incident{tls | reason: reason})) == "192.0.2.9"
    end

    assert host("kelixip-packet", file_line(@auth)) == nil
  end

  test "a line with no source matches no filter" do
    for jail <- ~w(kelixip-auth kelixip-scan kelixip-api kelixip-packet) do
      assert host(jail, file_line(%Incident{@auth | src: nil, reason: :bad_password})) == nil
    end
  end
end
