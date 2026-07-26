defmodule Kelix.Nonce do
  @moduledoc """
  Stateless, unforgeable digest nonce (design §7.1, §11.1) — replaces the old
  stateful per-dialog nonce and the secret-less `SIP.Auth.generate_nonce`.

      nonce = base64url( ts ‖ rand ‖ HMAC-SHA256(server_secret, ts ‖ rand ‖ realm) )

  Validation recomputes the HMAC (no storage) and checks freshness
  `now − ts ≤ max_age`. Beyond that it is `:stale` (the challenge is re-issued
  with `stale=true` and the client replays transparently). `realm` is bound into
  the HMAC, so a nonce minted for one domain is useless on another.

  The server secret comes from `Kelix.Secret`; both functions accept a `:secret`
  (and `:now`) override for testing. base64url avoids `+`/`/` (spec §11.1).
  """

  @rand_bytes 8
  @ts_bytes 8
  @mac_bytes 32
  @default_max_age 60

  @type verdict :: :ok | :stale | :invalid

  @doc "Mint a fresh nonce for `realm`."
  @spec generate(String.t(), keyword) :: String.t()
  def generate(realm, opts \\ []) when is_binary(realm) do
    secret = secret(opts)
    ts = Keyword.get(opts, :now, now())
    rand = :crypto.strong_rand_bytes(@rand_bytes)
    ts_bin = <<ts::unsigned-big-integer-size(64)>>
    mac = mac(secret, ts_bin, rand, realm)
    Base.url_encode64(ts_bin <> rand <> mac, padding: false)
  end

  @doc """
  Validate `nonce` against `realm`: `:ok` (fresh & authentic), `:stale`
  (authentic but older than `max_age` — re-challenge with `stale=true`), or
  `:invalid` (forged / wrong realm / malformed).
  """
  @spec validate(String.t(), String.t(), keyword) :: verdict
  def validate(nonce, realm, opts \\ []) when is_binary(nonce) and is_binary(realm) do
    secret = secret(opts)
    max_age = Keyword.get(opts, :max_age, @default_max_age)
    now = Keyword.get(opts, :now, now())

    with {:ok, ts_bin, rand, mac} <- decode(nonce),
         true <- constant_time_equal?(mac, mac(secret, ts_bin, rand, realm)) do
      <<ts::unsigned-big-integer-size(64)>> = ts_bin
      if now - ts <= max_age, do: :ok, else: :stale
    else
      _ -> :invalid
    end
  end

  @doc "Extract the timestamp (unix seconds) from a nonce, without validating it."
  @spec timestamp(String.t()) :: {:ok, integer} | :error
  def timestamp(nonce) do
    case decode(nonce) do
      {:ok, <<ts::unsigned-big-integer-size(64)>>, _rand, _mac} -> {:ok, ts}
      _ -> :error
    end
  end

  # ── internals ────────────────────────────────────────────────────────────────

  defp decode(nonce) do
    case Base.url_decode64(nonce, padding: false) do
      {:ok, <<ts_bin::binary-size(@ts_bytes), rand::binary-size(@rand_bytes), mac::binary-size(@mac_bytes)>>} ->
        {:ok, ts_bin, rand, mac}

      _ ->
        :error
    end
  end

  defp mac(secret, ts_bin, rand, realm),
    do: :crypto.mac(:hmac, :sha256, secret, ts_bin <> rand <> realm)

  defp secret(opts), do: Keyword.get(opts, :secret) || Kelix.Secret.get()

  defp now(), do: System.os_time(:second)

  # constant-time comparison (avoid timing oracles on the MAC)
  defp constant_time_equal?(a, b) when byte_size(a) == byte_size(b),
    do: :crypto.hash_equals(a, b)

  defp constant_time_equal?(_, _), do: false
end
