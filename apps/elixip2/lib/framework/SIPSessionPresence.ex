# Presence session layer: the behaviour the dialog layer calls when a SUBSCRIBE
# or a PUBLISH creates a dialog.
# Part of the SIP.Session namespace; see SIPSession.ex for the common core.

defmodule SIP.Session.Presence do
  @moduledoc """
  What a presence server implements, so the dialog layer knows where to send an
  inbound SUBSCRIBE, PUBLISH, MESSAGE or INFO.

  The exact counterpart of `SIP.Session.Registrar`, and deliberately shaped like
  it: the callback receives the **dialog pid**, the parsed request and the pid of
  the **server transaction** that created the dialog, and answers
  `{:accept, app_pid}` — the dialog then forwards
  `{:SUBSCRIBE, req, transaction_id, dialog_id}` to that process — or
  `{:reject, code, reason}`.

  The transaction pid is the third argument for the reason it is one on
  `on_new_registration/3`: the application has to be able to reply on the right
  transaction, and a factory that spawns one instance per inbound dialog has no
  other way to know which. The arity-2 shape this module carried before P3 had no
  implementation and no caller.

  Registering an implementation is `SIP.Session.ConfigRegistry.set_presence_processing_module/1`.
  With none, an inbound SUBSCRIBE or PUBLISH is answered **500** — the answer
  `internal_dispatch/4` gives for every empty slot — rather than the 501 the
  catch-all used to give for a method the stack simply did not route.
  """

  @doc """
  An out-of-dialog SUBSCRIBE created `dialog_id`. Answer with the process that
  will serve this subscription.

  The **protocol** refusals — 489 on a package the node does not know, 406 on an
  unusable `Accept`, 423 on a lifetime below the package's minimum — are NOT this
  callback's: `SIP.Session.Notifier.accept_subscription/1` raises them from
  inside the instance, and a kelixip Router raises the 489 before any script runs
  at all. What belongs here is admission: quota, served domains, whether this
  node serves presence for that resource.
  """
  @callback on_new_subscribe(dialog_id :: pid, sub_req :: map, transaction_id :: pid) ::
              {:accept, pid} | {:reject, integer, binary}

  @doc "An out-of-dialog PUBLISH created `dialog_id`. Same contract."
  @callback on_new_publish(dialog_id :: pid, pub_req :: map, transaction_id :: pid) ::
              {:accept, pid} | {:reject, integer, binary}

  @doc "A page-mode MESSAGE (RFC 3428). Its dispatch is chat's — see DESIGN-CHAT.md."
  @callback on_message(dialog_id :: pid, msg_req :: map, transaction_id :: pid) ::
              {:accept, pid} | {:reject, integer, binary}

  @doc "An out-of-dialog INFO. Same contract."
  @callback on_info(dialog_id :: pid, msg_req :: map, transaction_id :: pid) ::
              {:accept, pid} | {:reject, integer, binary}

  @doc """
  The subscription bound to `app_pid` has ended — its lifetime lapsed, or the
  dialog carrying it is gone.

  The application has already been handed its one
  `{:subscription_terminated, ref, reason}`; this is the *factory's* copy, so it
  can free the slot the instance was holding.
  """
  @callback on_subscription_expired(dialog_id :: pid, app_pid :: pid) :: any()

  @optional_callbacks on_message: 3, on_info: 3, on_subscription_expired: 2
end
