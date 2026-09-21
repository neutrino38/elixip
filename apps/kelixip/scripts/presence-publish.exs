# Reference kelixip presence script, PUBLISH half — the event state compositor of
# RFC 3903. One instance is spawned per inbound PUBLISH by Kelix.Router →
# Kelix.InstancePool, and it serves that one request and ends: a PUBLISH is one
# transaction, and the entity-tag lifecycle is the collection's state, not this
# instance's (DESIGN-PRESENCE.md, plan decision 5).
#
# The reading is NOT here. The router has already answered 489 for any package
# this domain does not serve, and `check_publish/1` answers 400, 415 and 423
# itself, handing back a presentity row already read. What is left is the one
# answer only the holder of the entity-tags can give — the 412 — and the SIP each
# outcome means.
defmodule Kelix.PresencePublish do
  use SIP.Scenario
  require Logger

  uas(:presence)

  config(uses_modules: [:presence, :auth_db])

  state initial_state do
    goto(wait_publish)
  end

  state wait_publish do
    on_events do
      {:PUBLISH, _req, _trans_pid, _dialog_pid} ->
        goto(authorize, "PUBLISH received")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_aborted("publisher vanished before the PUBLISH")
    after
      32_000 ->
        scenario_failure("no PUBLISH received")
    end
  end

  # Whose state is this? The only check this reference makes is that the
  # presentity exists in the subscriber base: publishing state for a user nobody
  # provisioned is 404, and it is how a typo stops here instead of becoming a
  # resource watchers can subscribe to.
  state authorize do
    req = last_uas_req()

    if Kelix.Mod.AuthDb.subscriber?(SIP.Msg.Ops.target_aor(req), sip_ctx.domain) do
      goto(publish, "presentity exists")
    else
      reply_publish(404, "Not Found")
      scenario_success("404 no such presentity")
    end
  end

  state publish do
    case check_publish(package: ctx_get(:event_package)) do
      {:ok, pub} ->
        case Kelix.Mod.Presence.publish(sip_ctx, pub) do
          # RFC 3903 §6 makes SIP-ETag and Expires mandatory on the 2xx. A
          # removal carries neither — `reply_publish/2` writes no tag with
          # `expires: 0`, since there is no state left to name.
          {:ok, etag, expires} ->
            reply_publish(200, etag: etag, expires: expires)
            scenario_success("published (#{expires}s)")

          # A tag we do not hold: expired under the publisher's feet, or issued
          # by a node that has since restarted. The publisher must start over
          # with an initial PUBLISH, which is exactly what the 412 tells it.
          {:error, 412} ->
            reply_publish(412, "Conditional Request Failed")
            scenario_success("412 unknown entity-tag")

          # The store is down or wedged — Kelix.Module.safe_call/3 degrades to
          # this instead of blocking us (§8.2). 503, not 500: nothing is broken,
          # and the publisher should retry.
          {:error, reason} when reason in [:down, :timeout] ->
            Logger.error(module: __MODULE__, message: "presence store #{reason}")
            reply_publish(503, "Service Unavailable")
            scenario_failure("presence store #{reason}")
        end

      # 400 / 415 / 423 have already gone out. (The 489 never reaches here — the
      # router raised it before this instance existed.)
      {:error, code} ->
        scenario_success("PUBLISH refused with #{code}")
    end
  end

  # Cooperative shutdown (§5.3): a publisher instance holds nothing to release.
  on_shutdown do
    scenario_aborted("Compositor stopped gracefully")
  end
end
