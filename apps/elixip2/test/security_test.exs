defmodule Elixip.SecurityTest do
  # The incident line is evidence: its shape is what the shipped fail2ban filters
  # read, so the rendering is pinned here field by field.
  use ExUnit.Case, async: false

  alias Elixip.Security
  alias Elixip.Security.Incident

  @full %Incident{
    type: :auth_failure,
    src: {192, 0, 2, 5},
    port: 5060,
    proto: "UDP",
    method: :REGISTER,
    realm: "example.com",
    user: "alice",
    reason: :bad_password
  }

  test "the fields come out in a fixed order, type first and src second" do
    assert to_string(@full) ==
             "auth-failure src=192.0.2.5 port=5060 proto=UDP method=REGISTER " <>
               "realm=example.com user=\"alice\" reason=bad_password"
  end

  test "a nil field is omitted rather than written with a made-up value" do
    line =
      to_string(%Incident{
        type: :invalid_packet,
        src: {10, 0, 0, 1},
        port: 40000,
        proto: "TCP",
        reason: :garbage
      })

    assert line == "invalid-packet src=10.0.0.1 port=40000 proto=TCP reason=garbage"
    refute line =~ "realm="
    refute line =~ "user="
    refute line =~ "method="
  end

  test "an HTTP verb is a method too" do
    line =
      to_string(%Incident{
        type: :api_auth,
        src: {127, 0, 0, 1},
        port: 51000,
        proto: "HTTP",
        method: "GET",
        reason: :invalid_token
      })

    assert line == "api-auth src=127.0.0.1 port=51000 proto=HTTP method=GET reason=invalid_token"
  end

  test "an IPv6 source renders unbracketed" do
    line = to_string(%Incident{@full | src: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}})
    assert line =~ " src=2001:db8::1 port=5060 "
  end

  test "user is quoted, and a quote, a backslash, CR and LF inside it are escaped" do
    line = to_string(%Incident{@full | user: "a\"b\\c\rd\ne"})
    assert line =~ ~s( user="a\\"b\\\\c\\x0Dd\\x0Ae" reason=bad_password)
    refute line =~ "\n"
    refute line =~ "\r"
  end

  test "a forged src= inside the username stays inside the quotes" do
    line = to_string(%Incident{@full | user: "x\" src=203.0.113.9 reason=bad_password \"y"})

    # The address a filter anchored on the type reads is the real one.
    assert [_, "192.0.2.5"] = Regex.run(~r/^auth-failure src=(\S+) port=/, line)
    assert line =~ ~s(user="x\\" src=203.0.113.9 reason=bad_password \\"y")
  end

  test "report/1 with no sink configured returns :ok" do
    prev = Application.get_env(:elixip2, :security_sink)
    Application.delete_env(:elixip2, :security_sink)
    on_exit(fn -> if prev, do: Application.put_env(:elixip2, :security_sink, prev) end)

    assert Security.report(@full) == :ok
  end

  defmodule Sink do
    def take(incident), do: send(:elixip_security_test, {:sunk, incident})
  end

  test "report/1 hands the struct to the configured {module, fun}" do
    prev = Application.get_env(:elixip2, :security_sink)
    Process.register(self(), :elixip_security_test)
    Application.put_env(:elixip2, :security_sink, {Sink, :take})

    on_exit(fn ->
      if prev,
        do: Application.put_env(:elixip2, :security_sink, prev),
        else: Application.delete_env(:elixip2, :security_sink)
    end)

    assert Security.report(@full) == :ok
    assert_received {:sunk, @full}
  end

  test "the type names of the line map back to the struct's atoms" do
    assert Incident.type_names() ==
             ~w(auth-failure invalid-domain invalid-packet transport-error api-auth)

    assert Incident.type_from_name("invalid-packet") == :invalid_packet
    assert Incident.type_from_name("bogus") == nil
  end
end
