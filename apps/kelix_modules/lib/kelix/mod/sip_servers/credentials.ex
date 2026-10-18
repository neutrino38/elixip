defmodule Kelix.Mod.SipServers.Credentials do
  @moduledoc """
  The answer to a trunk's digest challenge, from the HA1 stored for it (design
  `docs/design/sip-server-specs.md`, "HA1").

  The password is not kept, so only the HA1 of the realm entered with it can
  answer: a challenge for another realm, or for an algorithm with no HA1, is
  refused with its reason rather than answered wrong. `qop=auth` is used when the
  challenge offers it (RFC 7616 §3.4), `auth-int` never.
  """

  alias Kelix.Mod.SipServers.Server

  @doc """
  `{:ok, params}` — the `Authorization` / `Proxy-Authorization` parameters for
  `method` on `digest_uri` — or `{:error, reason}`.
  """
  @spec authorize(Server.t(), map(), atom() | String.t(), String.t()) ::
          {:ok, map()} | {:error, term}
  def authorize(%Server{} = server, challenge, method, digest_uri) when is_map(challenge) do
    realm = challenge["realm"]
    algorithm = SIP.Auth.canonical_algorithm(challenge["algorithm"] || "MD5")

    cond do
      server.auth_ha1 == [] ->
        {:error, :no_credentials}

      realm != server.auth_realm ->
        {:error, {:realm_mismatch, server.auth_realm, realm}}

      is_nil(algorithm) ->
        {:error, {:unsupported_algorithm, challenge["algorithm"]}}

      true ->
        case Enum.find(server.auth_ha1, &(&1.algorithm == algorithm)) do
          nil -> {:error, {:unsupported_algorithm, challenge["algorithm"]}}
          %{hex: ha1} -> {:ok, params(server, challenge, algorithm, ha1, method, digest_uri)}
        end
    end
  end

  defp params(server, challenge, algorithm, ha1, method, digest_uri) do
    nonce = challenge["nonce"]
    method = to_string(method)

    base = %{
      "username" => server.auth_username,
      "realm" => challenge["realm"],
      "nonce" => nonce,
      "uri" => digest_uri,
      :authproc => "Digest"
    }

    base =
      base
      |> put_present("algorithm", challenge["algorithm"])
      |> put_present("opaque", challenge["opaque"])

    if offers_auth?(challenge["qop"]) do
      qop = %{"nc" => "00000001", "cnonce" => cnonce(), "qop" => "auth"}

      response =
        SIP.Auth.compute_auth_response_from_ha1(algorithm, nonce, ha1, method, digest_uri, qop)

      base |> Map.merge(qop) |> Map.put("response", response)
    else
      Map.put(
        base,
        "response",
        SIP.Auth.compute_auth_response_from_ha1(algorithm, nonce, ha1, method, digest_uri)
      )
    end
  end

  # The challenge advertises a list (`qop="auth,auth-int"`).
  defp offers_auth?(qop) when is_binary(qop) do
    qop |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.member?("auth")
  end

  defp offers_auth?(_), do: false

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  defp cnonce(), do: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
end
