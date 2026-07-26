defmodule SIP.Auth do
	@moduledoc "Utility to handle SIP authentication procedures"

  defp algo2atom(algorithm) do
    case algorithm do
      "MD5" -> :md5
      "SHA1" -> :sha1
      "SHA256" -> :sha256
      _ -> raise "Unsupported hash algorithm #{algorithm}"
    end
  end

  def compute_ha1(algorithm, username, realm, passwd) do
    algoid = if is_binary(algorithm), do: algo2atom(algorithm), else: algorithm
    :crypto.hash(algoid, "#{username}:#{realm}:#{passwd}") |> Base.encode16(case: :lower)
  end

  @spec compute_auth_response_from_pwd(String.t(), String.t(), String.t(), String.t(), String.t(), atom(), String.t() | SIP.Uristruct) :: String.t()
  def compute_auth_response_from_pwd(algorithm, username, nonce, realm, passwd, method, uri) do
    algoid = algo2atom(algorithm)
    ha1 = compute_ha1(algoid, username, realm, passwd)
    compute_auth_response_from_ha1(algoid, nonce, ha1, method, uri )
  end

  def compute_auth_response_from_ha1(algorithm, nonce, ha1, method, uri) do
    algoid = if is_binary(algorithm), do: algo2atom(algorithm), else: algorithm
    uri = to_string(uri)
    ha2 = :crypto.hash(algoid, "#{method}:#{uri}") |> Base.encode16(case: :lower)
    :crypto.hash(algoid, "#{ha1}:#{nonce}:#{ha2}") |> Base.encode16(case: :lower)
  end

  @doc """
  RFC 2617 `qop=auth` digest response:
  `H(HA1:nonce:nc:cnonce:qop:HA2)` — additive to the RFC 2069 form above
  (kept for the no-qop fallback). `qop` is a map with `"nc"`, `"cnonce"` and
  (optionally) `"qop"` (defaults to `"auth"`).
  """
  def compute_auth_response_from_ha1(algorithm, nonce, ha1, method, uri, %{} = qop) do
    algoid = if is_binary(algorithm), do: algo2atom(algorithm), else: algorithm
    uri = to_string(uri)
    ha2 = :crypto.hash(algoid, "#{method}:#{uri}") |> Base.encode16(case: :lower)
    nc = Map.fetch!(qop, "nc")
    cnonce = Map.fetch!(qop, "cnonce")
    qopv = Map.get(qop, "qop", "auth")

    :crypto.hash(algoid, "#{ha1}:#{nonce}:#{nc}:#{cnonce}:#{qopv}:#{ha2}")
    |> Base.encode16(case: :lower)
  end

  @doc """
  Expected digest response for a client's Authorization params, from a stored
  HA1. Uses the `qop=auth` form when the client sent `qop`+`nc`+`cnonce`, else
  the RFC 2069 form (very old clients). `params` is the string-keyed auth map
  (`"nonce"`, `"uri"`, and for qop `"qop"`/`"nc"`/`"cnonce"`); `method` is the
  request method.
  """
  def expected_response_from_ha1(algorithm, ha1, method, params) when is_map(params) do
    nonce = params["nonce"]
    uri = params["uri"]

    case params["qop"] do
      q when is_binary(q) and q != "" ->
        compute_auth_response_from_ha1(algorithm, nonce, ha1, method, uri, %{
          "nc" => params["nc"],
          "cnonce" => params["cnonce"],
          "qop" => q
        })

      _ ->
        compute_auth_response_from_ha1(algorithm, nonce, ha1, method, uri)
    end
  end

  @spec build_auth_response( String.t(), String.t(), String.t(), String.t(), String.t(), atom(), atom(), String.t() | SIP.Uristruct) :: map()
  @doc "Build challenge on nonce and realm"
  def build_auth_response( algorithm, username, nonce, realm, passwd_or_hash, pwdformat, method, uri) do
    response = case pwdformat do
      :plain -> compute_auth_response_from_pwd(algorithm, username, nonce, realm, passwd_or_hash, method, uri)
      :ha1 -> compute_auth_response_from_ha1(algorithm,  nonce, passwd_or_hash, Atom.to_string(method), uri)
      _ -> raise "Unsupported password format #{pwdformat}"
    end

    %{ "username" => username, "realm" => realm, "nonce" => nonce,"algorithm" => algorithm,
       "response" => response, :authproc => "Digest", "uri" => uri }
  end

  @nonce_size 16  # 16 bytes = 128 bits

  @doc "Generate a nonce for Digest auth procedure"
  def generate_nonce do
    now = DateTime.utc_now(:second)
    generate_nonce(now)
  end

  def generate_nonce(date) do
    :crypto.hash(:sha256, "ElixSIP-#{date.day}:#{date.hour}:#{date.minute}")
      |> binary_part(0, @nonce_size)
      |> Base.encode16(case: :lower)
  end
end
