defmodule Kelix.Auth do
  @moduledoc """
  Builds a digest **challenge** using the stateless `SIP.Auth.Nonce` (design §7).

  The registrar script sends the returned map as an explicit `WWW-Authenticate`
  header (`SIP.Dialog.reply(dialog_pid, req, 401, reason, wwwauthenticate: params)`)
  — the framework then serializes it verbatim, without generating or storing a
  stateful nonce (see the `is_binary(realm)` guard in `SIP.DialogImpl`).

  MD5 (not SHA-256 — broadest client support), `qop="auth"`, and `stale=true`
  on re-challenge of an expired/replayed nonce so the client replays transparently.
  """

  @doc """
  WWW-Authenticate params for `realm`. `opts`: `:stale` (bool, default false),
  and `:secret`/`:now` forwarded to `SIP.Auth.Nonce.generate` (tests).
  """
  @spec challenge_www_authenticate(String.t(), keyword) :: map
  def challenge_www_authenticate(realm, opts \\ []) when is_binary(realm) do
    nonce = SIP.Auth.Nonce.generate(realm, Keyword.take(opts, [:secret, :now]))

    params = %{
      "realm" => realm,
      "nonce" => nonce,
      "algorithm" => "MD5",
      "qop" => "auth",
      :authproc => "Digest"
    }

    if Keyword.get(opts, :stale, false), do: Map.put(params, "stale", "true"), else: params
  end
end
