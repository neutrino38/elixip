defmodule Kelix.Auth do
  @moduledoc """
  Builds a digest **challenge** using the stateless `SIP.Auth.Nonce` (design §7).

  A script sends the returned map as an explicit challenge header — the registrar
  as `WWW-Authenticate` (`SIP.Dialog.reply(dialog_pid, req, 401, reason,
  wwwauthenticate: params)`), a call script as `Proxy-Authenticate` through
  `b2bua_challenge/3` — and the framework serializes it verbatim, without
  generating or storing a stateful nonce (see the `is_binary(realm)` guard in
  `SIP.DialogImpl`).

  `qop="auth"`, and `stale=true` on re-challenge of an expired/replayed nonce so
  the client replays transparently.

  The algorithm defaults to MD5 (broadest client support) but must match what the
  authentication backend can verify — the stored secret was salted with one hash
  and one only. The caller passes it (`Kelix.Mod.AuthDb.challenge_algorithm/0`),
  so the challenge never advertises something the base cannot check.
  """

  @doc """
  Digest challenge params for `realm` — header-agnostic, because the params are.

  A 401 carries them in `WWW-Authenticate` (a UAS answering for itself, RFC 3261
  §22.2), a 407 in `Proxy-Authenticate` (§22.3 — what a UA expects of the server
  routing its calls). Which one goes out is the scenario's decision, not this
  function's: `SIP.Session.Registrar.challenge_registration/3` for a REGISTER,
  `b2bua_challenge/3` for a call.

  `opts`: `:stale` (bool, default false), `:algorithm` (default `"MD5"`), and
  `:secret`/`:now` forwarded to `SIP.Auth.Nonce.generate` (tests).
  """
  @spec challenge_params(String.t(), keyword) :: map
  def challenge_params(realm, opts \\ []) when is_binary(realm) do
    nonce = SIP.Auth.Nonce.generate(realm, Keyword.take(opts, [:secret, :now]))

    params = %{
      "realm" => realm,
      "nonce" => nonce,
      "algorithm" => Keyword.get(opts, :algorithm, "MD5"),
      "qop" => "auth",
      :authproc => "Digest"
    }

    if Keyword.get(opts, :stale, false), do: Map.put(params, "stale", "true"), else: params
  end
end
