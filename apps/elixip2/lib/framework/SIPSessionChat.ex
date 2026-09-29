# Chat session layer: the behaviour the dialog layer calls when an out-of-dialog
# MESSAGE creates a dialog.
# Part of the SIP.Session namespace; see SIPSession.ex for the common core.

defmodule SIP.Session.Chat do
  @moduledoc """
  What a page-mode messaging server implements (RFC 3428), so the dialog layer
  knows where to send an inbound out-of-dialog MESSAGE.

  Shaped like `SIP.Session.Presence` and `SIP.Session.Registrar`: the callback
  receives the **dialog pid**, the parsed request and the pid of the **server
  transaction** that created the dialog, and answers `{:accept, app_pid}` — the
  dialog then forwards `{:MESSAGE, req, transaction_id, dialog_id}` to that
  process — or `{:reject, code, reason}`.

  A slot of its own rather than a callback of the presence host: chat is a
  function of its own (docs/design/DESIGN-CHAT.md, *chat is a function of its
  own*), an elixipp scenario answering MESSAGE must not have to pose as a presence
  server, and a MESSAGE must not land in a subscription script when routing goes
  wrong.

  Registering an implementation is
  `SIP.Session.ConfigRegistry.set_chat_processing_module/1`. With none, an inbound
  MESSAGE is answered **500**, the answer `internal_dispatch/4` gives for every
  empty slot.

  A MESSAGE sent **inside** an established dialog does not come here: it reaches
  that dialog, and the application already serving it.
  """

  @doc """
  An out-of-dialog MESSAGE created `dialog_id`. Answer with the process that will
  serve it.

  What belongs here is admission — quota, served domains, whether this node serves
  chat for that recipient. What to answer the sender (200, 202, 480…) is the
  serving process's decision, once it has tried.
  """
  @callback on_message(dialog_id :: pid, msg_req :: map, transaction_id :: pid) ::
              {:accept, pid} | {:reject, integer, binary}
end
