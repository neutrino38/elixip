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
