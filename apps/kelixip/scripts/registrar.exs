# Reference kelixip registrar script (design §6, §12.4). One instance is spawned
# per inbound REGISTER dialog by Kelix.Router → Kelix.InstancePool. The served
# domain is injected into the context by the router (config override `domain:`).
#
# Separation of concerns (§11.1): the MODULES decide, the SCRIPT composes the SIP
# response. Kelix.Mod.AuthDb.do_registration_auth/2 returns the auth verdict;
# Kelix.Mod.Registrar.save/4 stores the binding and returns the granted contacts.
# This script maps those onto SIP.Session.reply/6 (the instrumented reply):
#
#   {:requireauth, stale} -> 401 with a stateless-nonce challenge (Kelix.Auth)
#   :ok                   -> save, then 200 OK echoing the granted contacts
#   {:reject, code, msg}  -> code msg
defmodule Kelix.Registrar do
  use SIP.Scenario
  require Logger
  import SIP.Session, only: [reply: 5, reply: 6]

  uas(:register)

  # The {:REGISTER, …} is already queued by the dialog layer; wait for it.
  state initial_state do
    goto(wait_register)
  end

  state wait_register do
    on_events do
      {:REGISTER, req, _trans_pid, dialog_pid} ->
        goto(loop, process_register(req, dialog_pid, sip_ctx.domain))

      {:dialog_terminated, _dialog_pid, reason}
      when reason in [:tcp_closed, :tls_closed, :wss_closed] ->
        scenario_aborted("client socket closed")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("registration ended")
    after
      600_000 ->
        scenario_success("registration idle timeout")
    end
  end

  # Cooperative shutdown (§5.3): a registrar has no BYE/media to release.
  on_shutdown do
    scenario_aborted("Registrar stopped gracefully")
  end

  # ── application logic ───────────────────────────────────────────────────────
  # modules decide, this composes the SIP reply. Returns a short description.
  #
  # The rescue is the load-bearing part: a module that is not installed
  # (UndefinedFunctionError) or that faults mid-verdict would otherwise kill this
  # instance, and the client would get NO response at all — worse than any error
  # code, since it retransmits into the void. Answer 500 and let it fail loudly.
  defp process_register(req, dialog_pid, domain) do
    do_process_register(req, dialog_pid, domain)
  rescue
    e ->
      Logger.error(
        module: __MODULE__,
        message: "registrar script failed: #{Exception.message(e)}"
      )

      reply(dialog_pid, req, 500, "Server Internal Error", [], "script_failed")
      "500 Server Internal Error"
  end

  defp do_process_register(req, dialog_pid, domain) do
    case Kelix.Mod.AuthDb.do_registration_auth(req, domain) do
      {:requireauth, stale} ->
        # The algorithm comes from the backend: advertising MD5 while the base
        # stores SHA-256 HA1s would challenge forever.
        params =
          Kelix.Auth.challenge_www_authenticate(domain,
            stale: stale,
            algorithm: Kelix.Mod.AuthDb.challenge_algorithm()
          )

        reply(
          dialog_pid,
          req,
          401,
          "Unauthorized",
          [wwwauthenticate: params],
          if(stale, do: "401 stale", else: "401 challenge")
        )

        if stale, do: "401 stale", else: "401 Unauthorized"

      :ok ->
        accept_or_reject(req, dialog_pid, domain)

      {:reject, code, reason} ->
        reply(dialog_pid, req, code, reason, [])
        "#{code} #{reason}"
    end
  end

  defp accept_or_reject(req, dialog_pid, domain) do
    case Kelix.Mod.Registrar.save(req, domain, dialog_pid) do
      # RFC 3261 §10.3 step 8: enumerate ALL current bindings, each with its own
      # remaining lifetime — `granted.contacts` already is that list (empty after
      # an un-REGISTER, in which case the 200 carries no Contact at all).
      {:ok, granted} ->
        reply(
          dialog_pid,
          req,
          200,
          "OK",
          [contact: empty_to_nil(granted.contacts), expires: granted.expires],
          "accept_registration"
        )

        # Name the identity this instance serves, so `kelictl monitor` says WHO is
        # registering and not just that something is.
        SIP.Scenario.Monitor.note_account(granted.aor)
        "200 OK"

      # RFC 3261 §10.3 step 7: a 423 MUST carry Min-Expires, otherwise the client
      # has no way to know what to ask for and simply fails.
      {:error, {423, reason}} ->
        min = Kelix.Mod.Registrar.min_expires(domain)

        reply(dialog_pid, req, 423, reason, [{"Min-Expires", to_string(min)}], "423 too brief")

        "423 #{reason} (min #{min})"

      # The store is down or wedged — `Kelix.Module.safe_call/3` degrades to this
      # instead of blocking us (§8.2). 503, not 500: nothing is broken, the service
      # is momentarily unavailable and the client should retry.
      {:error, reason} when reason in [:down, :timeout] ->
        Logger.error(module: __MODULE__, message: "registrar store #{reason}")
        reply(dialog_pid, req, 503, "Service Unavailable", [], "503 store down")
        "503 Service Unavailable"

      {:error, {code, reason}} ->
        reply(dialog_pid, req, code, reason, [])
        "#{code} #{reason}"
    end
  end

  # No binding left ⇒ no Contact header at all, rather than an empty one.
  defp empty_to_nil([]), do: nil
  defp empty_to_nil(contacts), do: contacts
end
