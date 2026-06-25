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
          :no_auth_header ->
            challenge_registration(req, dialog_pid)
            goto(loop, "401 Unauthorized")

          :ok ->
            accept_registration(req, dialog_pid, expires: @granted_expires)
            goto(registered, "200 OK")

          other ->
            reject_registration(req, dialog_pid, 403, "Forbidden")
            scenario_failure("auth rejected: #{inspect(other)}")
        end

      {:scenario_ctl, :shutdown, _reason } -> scenario_success("Registrar stopped gracefully")
    after
      32_000 ->
        scenario_failure("no REGISTER received")
    end
  end

  # ---------------------------------------------------------------------------
  # Registered. Handle:
  #   * OPTIONS keepalives → 200 OK (stay registered);
  #   * REGISTER refreshes → re-authenticate then 200 OK (stay registered);
  #   * un-REGISTER (a REGISTER with Expires/Contact expires 0) → 200 OK then end;
  #   * dialog termination → end.
  state registered do
    on_events do
      {:OPTIONS, req, _trans_pid, dialog_pid} ->
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        goto(loop, "OPTIONS keepalive")

      {:REGISTER, req, _trans_pid, dialog_pid} ->
        case check_registration_auth(req, dialog_pid, password: appdata_get(:password)) do
          :no_auth_header ->
            challenge_registration(req, dialog_pid)
            goto(loop, "401 (re-auth)")

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
        scenario_success("Registrar stopped gracefully")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("registration ended")
    after
      600_000 ->
        scenario_success("registration idle timeout")
    end
  end

  # ── REGISTER reply helpers (application side) ──────────────────────────────
  # Thin wrappers over the framework's dialog/transaction machinery.

  # Challenge with a 401 carrying a freshly generated WWW-Authenticate digest
  # header. For a 401, SIP.Dialog.reply/5 interprets the 5th argument as the
  # realm and the dialog layer generates + stores the nonce.
  defp challenge_registration(req, dialog_pid, opts \\ []) do
    realm = Keyword.get(opts, :realm, @domain)
    reason = Keyword.get(opts, :reason, "Unauthorized")
    SIP.Dialog.reply(dialog_pid, req, 401, reason, realm)
  end

  # Accept with a 200 OK echoing the Contact binding(s) with the granted
  # expiration. Contact/Expires values are bounded by check_register/1 (min 60,
  # max 3600, max 5 contacts); a violation becomes the matching reject response.
  defp accept_registration(req, dialog_pid, opts) do
    expires = Keyword.get(opts, :expires, @granted_expires)

    try do
      _checked = SIP.Session.Registrar.check_register(req)

      contact =
        case Keyword.get(opts, :contact) do
          nil -> set_contacts_expires(Map.get(req, :contact), expires)
          c -> c
        end

      SIP.Dialog.reply(dialog_pid, req, 200, "OK", contact: contact)
    catch
      {:reject, code, reason} ->
        SIP.Dialog.reply(dialog_pid, req, code, reason, [])
    end
  end

  defp reject_registration(req, dialog_pid, code, reason) do
    SIP.Dialog.reply(dialog_pid, req, code, reason, [])
  end

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

  # Verify the inbound REGISTER credentials. Returns :no_auth_header (caller must
  # challenge), :ok, or a refusal atom. With no configured password any
  # well-formed Authorization is accepted; pass opts[:password] for a real digest
  # check via SIP.Msg.Ops.check_authrequest/3.
  defp check_registration_auth(req, dialog_pid, opts) do
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

      # Digest auth params are string-keyed maps (only :authproc is an atom), so
      # read them with the string keys — auth.nonce / auth.domain would raise.
      SIP.Dialog.check_nonce(dialog_pid, auth["nonce"]) == false ->
        :invalid_nonce

      auth["realm"] != @domain ->
        :invalid_domain

      true ->
        SIP.Msg.Ops.check_authrequest(
          req,
          Keyword.get(opts, :password),
          auth["nonce"]
        )
    end
  end

  defp set_contacts_expires(nil, _expires), do: nil

  defp set_contacts_expires(contacts, expires) when is_list(contacts),
    do: Enum.map(contacts, &set_contacts_expires(&1, expires))

  defp set_contacts_expires(%SIP.Uri{} = contact, expires),
    do: SIP.Uri.set_uri_param(contact, "expires", to_string(expires))
end
