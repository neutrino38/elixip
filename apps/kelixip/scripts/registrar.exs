# Reference kelixip registrar script (design §6, §12.4). One instance is spawned
# per inbound REGISTER dialog by Kelix.Router → Kelix.InstancePool. The served
# domain is injected into the context by the router (config override `domain:`).
#
# Separation of concerns (§11.1): the module DECIDES, the script COMPOSES the SIP
# response. Here Kelix.Mod.Registrar.save/4 stores the binding and returns the
# granted contacts/expires; this script echoes them in a 200 OK (or relays the
# error code). Digest auth is delegated to the auth_db module (roadmap) — this
# MVP accepts any REGISTER for the served domain.
defmodule Kelix.Registrar do
  use SIP.Scenario
  import SIP.Session.Registrar, only: [set_contacts_expires: 2]

  uas(:register)

  # The {:REGISTER, …} is already queued by the dialog layer; wait for it.
  state initial_state do
    goto(wait_register)
  end

  state wait_register do
    on_events do
      {:REGISTER, req, _trans_pid, dialog_pid} ->
        handle_register(req, dialog_pid, sip_ctx.domain)
        goto(loop, "REGISTER handled")

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
  # save/4 (the usrloc module) decides; this composes the SIP reply.
  defp handle_register(req, dialog_pid, domain) do
    case Kelix.Mod.Registrar.save(req, domain, dialog_pid) do
      {:ok, granted} ->
        contact = set_contacts_expires(Map.get(req, :contact), granted.expires)
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", contact: contact)

      {:error, {code, reason}} ->
        SIP.Dialog.reply(dialog_pid, req, code, reason, [])
    end
  end
end
