defmodule Kelix.Domain do
  @moduledoc """
  One served SIP domain and the functions enabled on it
  (design `docs/design/kelixip_basic_design.md` §3.2).

  A function block present = enabled. `registrar` / `presence` carry the function
  script + tuning; `dial_plan` is the ordered `calls` rule list (empty if `calls`
  is not enabled). Field order in `domains.toml` is significant for the dial-plan
  (first-match-wins).
  """

  @type fn_config :: %{optional(atom) => term}

  @type t :: %__MODULE__{
          name: String.t(),
          aliases: [String.t()],
          max_calls: pos_integer | nil,
          registrar: fn_config | nil,
          presence: fn_config | nil,
          dial_plan: [Kelix.DialRule.t()]
        }

  defstruct name: nil,
            aliases: [],
            max_calls: nil,
            registrar: nil,
            presence: nil,
            dial_plan: []
end

defmodule Kelix.DialRule do
  @moduledoc """
  One `[[domain.call]]` dial-plan rule (design §3.3). Either a compiled Asterisk
  `pattern` (matching the R-URI user-part) or the `default = true` catch-all.
  """

  @type t :: %__MODULE__{
          matcher: (String.t() -> boolean) | nil,
          raw: String.t() | nil,
          script: String.t(),
          default?: boolean
        }

  defstruct matcher: nil, raw: nil, script: nil, default?: false

  @doc "Does this rule match `user_part`? The catch-all matches anything."
  @spec matches?(t, String.t()) :: boolean
  def matches?(%__MODULE__{default?: true}, _user_part), do: true
  def matches?(%__MODULE__{matcher: m}, user_part) when is_function(m, 1), do: m.(user_part)
end
