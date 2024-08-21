defmodule SIP.Auth do
	@moduledoc "Utility to handle SIP authentication procedures"

  @spec compute_auth_response_from_pwd(String.t(), String.t(), String.t(), String.t(), String.t(), atom(), String.t() | SIP.Uristruct) :: String.t()
  def compute_auth_response_from_pwd(algorithm, username, nonce, realm, passwd, method, uri) do
    uri = to_string(uri)
    algoid = case algorithm do
      "MD5" -> :md5
      "SHA1" -> :sha1
      "SHA256" -> :sha256
      _ -> raise "Unsupported hash algorithm #{algorithm}"
    end
    ha1 = :crypto.hash(algoid, "#{username}:#{realm}:#{passwd}") |> Base.encode16(case: :lower)
    ha2 = :crypto.hash(algoid, "#{method}:#{uri}") |> Base.encode16(case: :lower)
    :crypto.hash(algoid, "#{ha1}:#{nonce}:#{ha2}") |> Base.encode16(case: :lower)
  end

  def compute_auth_response_from_ha1(algorithm, nonce, ha1, method, uri) do
    algoid = case algorithm do
      "MD5" -> :md5
      "SHA1" -> :sha1
      "SHA256" -> :sha256
      _ -> raise "Unsupported hash algorithm #{algorithm}"
    end
    ha2 = :crypto.hash(algoid, "#{method}:#{uri}") |> Base.encode16(case: :lower)
    :crypto.hash(algoid, "#{ha1}:#{nonce}:#{ha2}") |> Base.encode16(case: :lower)
  end

  @doc "Build challenge on nonce and realm"
  def build_auth_response( algorithm, username, nonce, realm, passwd_or_hash, pwdformat, method, uri) do
    response = case pwdformat do
      :plain -> compute_auth_response_from_pwd(algorithm, username, nonce, realm, passwd_or_hash, Atom.to_string(method), uri)
      :ha1 -> compute_auth_response_from_ha1(algorithm,  nonce, passwd_or_hash, Atom.to_string(method), uri)
      _ -> raise "Unsupported password format #{pwdformat}"
    end

    %{ "username" => username, "realm" => realm, "nonce" => nonce,"algorithm" => algorithm,
       "response" => response }
  end

  @nonce_size 16  # 16 bytes = 128 bits

  @doc "Generate a nonce for Digest auth procedure"
  def generate_nonce do
    :crypto.strong_rand_bytes(@nonce_size) |> Base.encode64()
  end
end
