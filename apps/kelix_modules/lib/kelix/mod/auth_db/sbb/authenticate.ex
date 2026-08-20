defmodule Kelix.Mod.AuthDb.SBB.Authenticate do
  @moduledoc """
  The FSM behind `Kelix.Mod.AuthDb.SBB.authenticate/1`: the challenge cycle every
  script gating a request on a digest was writing out, once.

  What it replaces is two states — `authenticate_caller` and `wait_credentials` —
  whose useful half was comments about SIP rules that had nothing to do with the
  call flow they sat in: 407 rather than 401, `stale`, "answer and keep waiting",
  and the 32 s a challenge is worth waiting for. They were already copied
  verbatim into a second script.

  ## What it does

  Asks `Kelix.Mod.AuthDb.authenticate/3` for a verdict on the request the host is
  serving, and composes the SIP each verdict means:

    * `{:ok, identity}` — records the identity (`assert_identity/1`, so the leg
      the host places next carries a `P-Asserted-Identity`) and returns;
    * `{:requireauth, stale}` — challenges and waits for the request to come back
      with credentials, on the same dialog: same Call-ID, a new CSeq, no To tag.
      Its ACK never reaches us — the server transaction absorbs the ACK of a
      non-2xx (RFC 3261 §17.2.1);
    * `{:reject, code, reason}` — answers and **keeps waiting**. One request's
      verdict is not the end of the conversation: a client that fixes its
      credentials must be able to say so, and ending the instance would leave the
      dialog matching the next INVITE of that Call-ID and casting it to a dead
      process — the caller would then get no answer at all until the dialog
      expires. After `max_attempts` of those it gives up and says so.

  ## What it takes

  Through `args`, all optional:

    * `:realm` — the realm to require, defaulting to `sip_ctx.domain`;
    * `:code` — 407 (default) or 401;
    * `:max_attempts` — rejected attempts to answer before giving up, 3 by
      default, `:infinity` for the behaviour the scripts had before this block.

  ## What bounds it

  `@sbb_timeout 32_000` — the `after` clause the two states carried, which was
  never a property of a call flow but of how long a challenge is worth waiting
  for. A UA replays a challenge within a second; what does not is a scanner or a
  phone with a wrong password, and neither deserves a slot.
  """

  use SIP.SBB
  # `challenge_invite/2` lives in the UAS mixin, which `use SIP.Scenario` does
  # not pull in — unlike `reply_invite`, which comes from CallUAC and is
  # everywhere. A block that answers an inbound INVITE is a UAS and says so.
  use SIP.Session.CallUAS

  require Logger

  @sbb_namespace :auth

  @sbb_returns [
    authenticated:
      "the digest checked out and the identity check had its say — %{user, realm}. " <>
        "The identity is recorded in the context, so the leg placed next asserts it",
    cancelled: "the caller gave up on the challenge with a CANCEL — %{}",
    caller_gone: "the dialog ended while we waited for credentials — %{reason}",
    refused:
      "too many rejected attempts; the block gave up on this sender — " <>
        "%{code, reason, attempts}. The last attempt has been answered"
  ]

  @sbb_timeout 32_000

  @default_max_attempts 3
  @default_code 407

  # Decide on the request the host is serving. No on_events: it verdicts and moves.
  #
  # The request needs no carrying around — `on_events` stored it and
  # `last_uas_req()` reads it back, which matters doubly here: the request
  # authenticated is the *last* one received, i.e. the one carrying the
  # credentials, never the challenged one.
  state initial_state do
    req = last_uas_req()
    realm = sbb_data_get(:realm) || ctx_get(:domain)

    case Kelix.Mod.AuthDb.authenticate(req, realm) do
      # The digest proved `identity.user`, and the identity check has already had
      # its say about the From asserting someone else (auth_db `identity_check`).
      {:ok, identity} ->
        SIP.Scenario.Monitor.note_account(identity.user)
        assert_identity(identity)
        sbb_return({:auth, :authenticated, %{user: identity.user, realm: realm}})

      # `stale` tells the client its nonce merely aged, so it replays without
      # asking its user for a password again. The algorithm is the backend's:
      # the stored secret only verifies under the hash it was made with.
      {:requireauth, stale} ->
        params =
          Kelix.Auth.challenge_params(realm,
            stale: stale,
            algorithm: Kelix.Mod.AuthDb.challenge_algorithm()
          )

        challenge_invite(params, sbb_data_get(:code) || @default_code)
        goto(wait_credentials, if(stale, do: "challenge (stale)", else: "challenge"))

      {:reject, code, reason} ->
        reply_invite(code, reason)
        attempts = (sbb_data_get(:attempts) || 0) + 1
        sbb_data_set(:attempts, attempts)

        if give_up?(attempts, sbb_data_get(:max_attempts)) do
          sbb_return({:auth, :refused, %{code: code, reason: reason, attempts: attempts}})
        else
          goto(wait_credentials, "#{code} #{reason}")
        end
    end
  end

  state wait_credentials do
    on_events do
      # The challenged request comes back with credentials. 100 Trying first:
      # the caller's UAC has restarted timer A on a fresh transaction.
      {:INVITE, _req, _trans, _dlg} ->
        reply_invite(100, "Trying")
        goto(initial_state, "credentials re-submitted")

      # A caller that cancels the challenged attempt: nothing was forwarded, so
      # there is nothing to cancel but ourselves.
      {:CANCEL, _req, _trans, _dlg} ->
        sbb_return({:auth, :cancelled, %{}})

      {:dialog_terminated, _dlg, reason} ->
        sbb_return({:auth, :caller_gone, %{reason: reason}})
    end
  end

  # `:infinity` is the behaviour the reference scripts had before this block:
  # answer every rejected attempt and let the block's own deadline end it.
  defp give_up?(_attempts, :infinity), do: false
  defp give_up?(attempts, nil), do: attempts >= @default_max_attempts
  defp give_up?(attempts, max) when is_integer(max), do: attempts >= max
end
