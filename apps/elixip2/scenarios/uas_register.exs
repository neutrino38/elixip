# Reference UAS (server-side) REGISTER scenario. Run it as a registrar with:
#     elixipp --listen udp:5060 scenarios/uas_register.exs
#
# elixipp loads this file, sees it is a `:uas_register` scenario (set by the
# `uas :register` annotation), starts the configured listeners and registers
# Elixip.RegistrarUAS as the processing module. One instance of this scenario is
# spawned per inbound REGISTER dialog and receives
# `{:REGISTER, req, transaction_id, dialog_pid}` in its mailbox.
#
# Replying to a REGISTER (challenge / accept / reject) is the *application's*
# responsibility, so the helpers live here in the scenario, not in the framework.
# They are plain functions: a scenario module cannot call a macro it defines
# itself, and inside a `state` body `sip_ctx` is just the function parameter, so
# no macro / `var!` plumbing is needed.
defmodule UAS.RegisterExample do
  use SIP.Scenario
  import SIP.Session.Registrar, only: [challenge_registration: 3, accept_registration: 3, reject_registration: 4, set_contacts_expires: 2]

  # Marks the scenario type as :uas_register so elixipp runs it in server mode.
  uas(:register)

  @domain "example.com"
  # Granted registration lifetime (seconds), echoed back in the 200 OK Contact.
  @granted_expires 300

  # No outbound account here: a server scenario is seeded from the inbound
  # request, not from a local identity. `domain` is used as the digest realm.
  #
  # `password` is the shared secret used to verify the digest. It is left unset
  # here on purpose — credential management is not this test scenario's job. When
  # absent, any well-formed Authorization is accepted; set it from the config
  # block (`config domain: …, password: "secret"`) or at runtime via the
  # registrar's `:scenario_overrides` (e.g. an external JSON config) to enforce a
  # real digest check. It is read back from the context appdata at runtime.
  config(domain: @domain)

  # The {:REGISTER, …} message is already queued in our mailbox by the dialog
  # layer; jump straight to the waiting state.
  state initial_state do
    goto(next)
  end

  # ---------------------------------------------------------------------------
  # First REGISTER: challenge if unauthenticated; once an Authorization is
  # present, verify the nonce (must be one we issued for this dialog), the realm
  # and the digest against the configured password before accepting.
  state wait_register do
    on_events do
      {:REGISTER, req, _trans_pid, dialog_pid} ->
        case check_registration_auth(req, dialog_pid, password: appdata_get(:password)) do
          # A nonce that merely aged out is re-challenged, not refused: the client
          # replays with the fresh one (RFC 3261 §22.2 stale).
          why when why in [:no_auth_header, :stale_nonce] ->
            challenge_registration(req, dialog_pid, realm: @domain)
            goto(loop, "401 Unauthorized (#{why})")

          :ok ->
            accept_registration(req, dialog_pid, expires: @granted_expires)
            goto(registered, "200 OK")

          other ->
            reject_registration(req, dialog_pid, 403, "Forbidden")
            scenario_failure("auth rejected: #{inspect(other)}")
        end

      {:scenario_ctl, :shutdown, _reason } -> scenario_aborted("Registrar stopped gracefully")
    after
      32_000 ->
        scenario_failure("no REGISTER received")
    end
  end

  # ---------------------------------------------------------------------------
  # Registered. Handle:
  #   * REGISTER refreshes → re-authenticate then 200 OK (stay registered);
  #   * un-REGISTER (a REGISTER with Expires/Contact expires 0) → 200 OK then end;
  #   * dialog termination → end.
  # OPTIONS keepalives are answered by the dialog layer itself (200 OK) and never
  # reach the scenario, so there is nothing to handle here for them.
  state registered do
    on_events do
      {:REGISTER, req, _trans_pid, dialog_pid} ->
        case check_registration_auth(req, dialog_pid, password: appdata_get(:password)) do
          why when why in [:no_auth_header, :stale_nonce] ->
            challenge_registration(req, dialog_pid, realm: @domain)
            goto(loop, "401 (re-auth: #{why})")

          :ok ->
            if unregister?(req) do
              accept_unregister(req, dialog_pid)
              scenario_success("un-REGISTER")
            else
              accept_registration(req, dialog_pid, expires: @granted_expires)
              goto(loop, "REGISTER refreshed")
            end

          other ->
            reject_registration(req, dialog_pid, 403, "Forbidden")
            goto(loop, "refresh auth rejected: #{inspect(other)}")
        end

      {:scenario_ctl, :shutdown, _reason} ->
        scenario_aborted("Registrar stopped gracefully")

      # Interrupted because client socket has been interrupted
      {:dialog_terminated, _dialog_pid, reason}
        when reason in [ :tcp_closed, :tls_closed, :wss_closed ]->
          scenario_aborted("Client socket closed")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("registration ended")
    after
      600_000 ->
        scenario_success("registration idle timeout")
    end
  end

  # Cooperative shutdown — required by kelixip's load-time contract (§5.3), which
  # forbids elixip's abrupt default. A registrar has no BYE to send nor media to
  # release, so aborting cleanly is enough. The per-state {:scenario_ctl,…} clauses
  # above drain the common in-wait cases; this explicit block is what proves the
  # script is shutdown-aware and is the fallback for any other state.
  on_shutdown do
    scenario_aborted("Registrar stopped gracefully")
  end

  # ── REGISTER reply helpers (application side) ──────────────────────────────
  # Thin wrappers over the framework's dialog/transaction machinery.

  # An un-REGISTER is a REGISTER requesting expiration 0 (Expires header or the
  # Contact "expires" parameter).
  defp unregister?(req), do: requested_expires(req) == 0

  defp requested_expires(req) do
    case Map.get(req, :expires) do
      e when is_integer(e) ->
        e

      _ ->
        case List.wrap(Map.get(req, :contact)) do
          [%SIP.Uri{} = contact | _] ->
            case SIP.Uri.get_uri_param(contact, "expires") do
              {:ok, v} -> String.to_integer(v)
              _ -> nil
            end

          _ ->
            nil
        end
    end
  end

  # Confirm an un-REGISTER with a 200 OK echoing the Contact at expires 0. We do
  # not run check_register/1 here: it rejects expirations below the 60 s minimum,
  # which would (wrongly) refuse a de-registration.
  defp accept_unregister(req, dialog_pid) do
    contact = set_contacts_expires(Map.get(req, :contact), 0)
    SIP.Dialog.reply(dialog_pid, req, 200, "OK", contact: contact)
  end

  # Verify the inbound REGISTER credentials. Returns :no_auth_header or
  # :stale_nonce (caller must challenge), :ok, or a refusal atom. With no
  # configured password any well-formed Authorization is accepted; pass
  # opts[:password] for a real digest check via SIP.Msg.Ops.check_authrequest/3.
  defp check_registration_auth(req, _dialog_pid, opts) do
    # Get auth header
    auth =
      cond do
        Map.has_key?(req, :authorization) -> Map.get(req, :authorization)
        Map.has_key?(req, :proxyauthorization) -> Map.get(req, :proxyauthorization)
        true -> nil
      end

    cond do
      is_nil(auth) ->
        :no_auth_header

      is_nil(Keyword.get(opts, :password)) ->
        :ok

      auth["realm"] != @domain ->
        :invalid_domain

      true ->
        # Digest auth params are string-keyed maps (only :authproc is an atom), so
        # read them with the string keys — auth.nonce / auth.domain would raise.
        # The nonce carries its own proof (HMAC over ts+rand+realm), so there is
        # nothing to look up: validate it, and re-challenge when it merely aged
        # out. `check_authrequest/3` then verifies the digest itself; its own
        # nonce-equality check is left off (nil) — it is this validation's job.
        case SIP.Auth.Nonce.validate(auth["nonce"], @domain) do
          :ok -> SIP.Msg.Ops.check_authrequest(req, Keyword.get(opts, :password), nil)
          :stale -> :stale_nonce
          :invalid -> :invalid_nonce
        end
    end
  end

end
