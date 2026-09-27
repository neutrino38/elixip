# The dialog-info document, as RFC 4235 models it and as a module or a scenario
# builds it. The wire format is SIPDialogInfoXml.ex; this file is the model both
# directions agree on.

defmodule SIP.DialogInfo.Party do
  @moduledoc """
  One end of a dialog — `<local>` or `<remote>` (RFC 4235 §4.1.6, §4.1.7).

  `identity` is the AOR the party is known by, `display` its display name, and
  `target` the URI the other party sends its in-dialog requests to: the Contact.
  Every field is optional, and a party with nothing to say is simply absent
  from the dialog.
  """

  @type t :: %__MODULE__{
          identity: binary() | nil,
          display: binary() | nil,
          target: binary() | nil
        }

  defstruct identity: nil, display: nil, target: nil
end

defmodule SIP.DialogInfo.Dialog do
  @moduledoc """
  One `<dialog>` of a dialog-info document (RFC 4235 §4.1.2 to §4.1.7).

  `id` names the dialog **within the document**, and a watcher matches it from
  one NOTIFY to the next; `call_id`, `local_tag` and `remote_tag` name the SIP
  dialog itself. `direction` is read from the entity's point of view:
  `:initiator` when the entity sent the INVITE, `:recipient` when it received
  it.

  `state` is one of RFC 4235 §3.7.1's five, and `event` and `code` say why a
  `:terminated` dialog ended — `event` is an atom for the values §4.1.4 names
  (`:cancelled`, `:rejected`, `:replaced`, `:local_bye`, `:remote_bye`,
  `:error`, `:timeout`) and the raw string for anything else. A document comes
  off the network, so nothing here calls `String.to_atom/1`.

  `duration` is the time in seconds since the dialog was confirmed, when the
  notifier states it.
  """

  alias SIP.DialogInfo.Party

  @type state :: :trying | :proceeding | :early | :confirmed | :terminated
  @type event ::
          :cancelled
          | :rejected
          | :replaced
          | :local_bye
          | :remote_bye
          | :error
          | :timeout
          | binary()
          | nil

  @type t :: %__MODULE__{
          id: binary() | nil,
          call_id: binary() | nil,
          local_tag: binary() | nil,
          remote_tag: binary() | nil,
          direction: :initiator | :recipient | nil,
          state: state() | binary(),
          event: event(),
          code: 100..699 | nil,
          duration: non_neg_integer() | nil,
          local: Party.t() | nil,
          remote: Party.t() | nil
        }

  defstruct id: nil,
            call_id: nil,
            local_tag: nil,
            remote_tag: nil,
            direction: nil,
            state: :trying,
            event: nil,
            code: nil,
            duration: nil,
            local: nil,
            remote: nil
end

defmodule SIP.DialogInfo.Doc do
  @moduledoc """
  A dialog-info document (RFC 4235 §4.1.1): whose dialogs it lists (`entity`)
  and the dialogs themselves.

  `version` is the **subscription's**, not the document's: a notifier stamps
  it before the NOTIFY goes out (`SIP.Session.Notifier`), so whoever builds the
  document leaves it at 0. `state` says whether the document is the whole
  state or only what changed; this node emits `:full` only.

  An entity with no call is an **empty** document, not an absent one: a watcher
  of an idle phone is told "no dialog", which is what its BLF key displays.

      iex> %SIP.DialogInfo.Doc{entity: "sip:bob@ives.fr"}
      %SIP.DialogInfo.Doc{entity: "sip:bob@ives.fr", version: 0, state: :full, dialogs: []}
  """

  alias SIP.DialogInfo.Dialog

  @type t :: %__MODULE__{
          entity: binary() | nil,
          version: non_neg_integer(),
          state: :full | :partial,
          dialogs: [Dialog.t()]
        }

  defstruct entity: nil,
            version: 0,
            state: :full,
            dialogs: []

  @doc """
  One line saying what the document states, for a log: the dialogs and the
  state of each, in document order.

      iex> SIP.DialogInfo.Doc.summary(%SIP.DialogInfo.Doc{entity: "sip:bob@ives.fr"})
      "no dialog"
  """
  @spec summary(t()) :: binary()
  def summary(%__MODULE__{dialogs: []}), do: "no dialog"

  def summary(%__MODULE__{dialogs: dialogs}) do
    count = if length(dialogs) == 1, do: "1 dialog", else: "#{length(dialogs)} dialogs"
    count <> ": " <> Enum.map_join(dialogs, ", ", &to_string(&1.state))
  end
end
