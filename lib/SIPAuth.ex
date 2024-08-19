defmodule SIP.Auth do
	@moduledoc "Utility to handle SIP authentication procedures"

  defp compute_auth_response_from_pwd(algorithm, username, nonce, realm, passwd, method, uri) do
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

  defp compute_auth_response_from_ha1(algorithm, nonce, ha1, method, uri) do
    algoid = case algorithm do
      "MD5" -> :md5
      "SHA1" -> :sha1
      "SHA256" -> :sha256
      _ -> raise "Unsupported hash algorithm #{algorithm}"
    end
    ha2 = :crypto.hash(algoid, "#{method}:#{uri}") |> Base.encode16(case: :lower)
    :crypto.hash(algoid, "#{ha1}:#{nonce}:#{ha2}") |> Base.encode16(case: :lower)
  end

  @doc "Build authentication parameters based on nonce and realm"
  def build_auth_response( algorithm, username, nonce, realm, passwd_or_hash, pwdformat, method, uri) do
    response = case pwdformat do
      :plain -> compute_auth_response_from_pwd(algorithm, username, nonce, realm, passwd_or_hash, Atom.to_string(method), uri)
      :ha1 -> compute_auth_response_from_ha1(algorithm,  nonce, passwd_or_hash, Atom.to_string(method), uri)
      _ -> raise "Unsupported password format #{pwdformat}"
    end

    %{ "username" => username, "realm" => realm, "nonce" => nonce,"algorithm" => algorithm,
       "response" => response }
  end
end
