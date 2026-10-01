defmodule Kelix.Domain do
  @moduledoc """
  One served SIP domain and the functions enabled on it
  (design `docs/design/DESIGN-KELIXIP.md`).

  A function block present = enabled. `registrar` carries the function script +
  tuning; `dial_plan` is the ordered `calls` rule list (empty if `calls` is not
  enabled). Field order in `domains.toml` is significant for the dial-plan
  (first-match-wins).

  `presence` is a **list**, one `%Kelix.PresenceBlock{}` per event package the
  domain serves (empty if presence is not enabled). One block per package because
  the package is what a watcher asks for, and what the domain answers **489** on
  when it serves another (DESIGN-PRESENCE.md, *the Router reads `Event`*); the
  list is also what `Allow-Events` is composed from.

  `chat` is the ordered `[[domain.chat]]` rule list — the dial plan's shape, a
  pattern on the R-URI user part and a catch-all last — routing an out-of-dialog
  MESSAGE to its script (DESIGN-CHAT.md, *chat is a function of its own*). Empty
  if chat is not enabled.
  """

  @type fn_config :: %{optional(atom) => term}

  @type t :: %__MODULE__{
          name: String.t(),
          aliases: [String.t()],
          max_calls: pos_integer | nil,
          registrar: fn_config | nil,
          presence: [Kelix.PresenceBlock.t()],
          dial_plan: [Kelix.DialRule.t()],
          chat: [Kelix.DialRule.t()]
        }

  defstruct name: nil,
            aliases: [],
            max_calls: nil,
            registrar: nil,
            presence: [],
            dial_plan: [],
            chat: []
end

defmodule Kelix.PresenceBlock do
  @moduledoc """
  One `[[domain.presence]]` block: an event package, and the script serving each
  of the two methods that carry it.

  `subscribe` is required — a package nothing can be subscribed to is a package
  the domain does not serve. `publish` is optional: the `dialog` package (RFC
  4235) is published by nothing, and a domain serving it answers **405** to a
  PUBLISH rather than naming a script that would have to refuse it.

  `lists` names the Request-URI user parts that are resource lists (RFC 4662) on
  this domain, and `list_subscribe` the script serving a SUBSCRIBE to one of them.
  A list is not a presentity: its subscription is challenged, answered and
  notified differently, so it gets a script of its own while the domain's own
  users keep `subscribe`. Both are set or neither (`lists` is then `[]`). A
  PUBLISH is never routed to a list.
  """

  @type t :: %__MODULE__{
          event_package: String.t(),
          subscribe: String.t(),
          publish: String.t() | nil,
          lists: [String.t()],
          list_subscribe: String.t() | nil
        }

  defstruct event_package: nil, subscribe: nil, publish: nil, lists: [], list_subscribe: nil

  @doc """
  The script serving `method` addressed to the Request-URI user part `user` on this
  block, or nil when it serves none.

  The user part is compared exactly: it is case-sensitive (RFC 3261 §19.1.4).
  """
  @spec script_for(t, atom, String.t() | nil) :: String.t() | nil
  def script_for(%__MODULE__{lists: lists, list_subscribe: ls, subscribe: s}, :SUBSCRIBE, user),
    do: if(user in lists, do: ls, else: s)

  def script_for(%__MODULE__{publish: p}, :PUBLISH, _user), do: p
end

defmodule Kelix.DialRule do
  @moduledoc """
  One `[[domain.call]]` dial-plan rule (design §3.3), or one `[[domain.chat]]`
  rule — the same list. Either a compiled Asterisk `pattern` (matching the R-URI
  user-part) or the `default = true` catch-all.

  A chat rule also carries `idle_timeout`, the seconds of silence that end one of
  its conversations (chat-basic-plan, C3b); `nil` on a call rule.
  """

  @type t :: %__MODULE__{
          matcher: (String.t() -> boolean) | nil,
          raw: String.t() | nil,
          script: String.t(),
          default?: boolean,
          idle_timeout: pos_integer | nil
        }

  defstruct matcher: nil,
            raw: nil,
            script: nil,
            default?: false,
            idle_timeout: nil

  @doc "Does this rule match `user_part`? The catch-all matches anything."
  @spec matches?(t, String.t()) :: boolean
  def matches?(%__MODULE__{default?: true}, _user_part), do: true
  def matches?(%__MODULE__{matcher: m}, user_part) when is_function(m, 1), do: m.(user_part)
end
