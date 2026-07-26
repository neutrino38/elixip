defmodule Kelix.DialPlan do
  @moduledoc """
  Asterisk-style extension pattern compiler for the `calls` dial-plan
  (design `docs/kelixip_basic_design.md` §3.3).

  A pattern is compiled **once** (at config load) into a matcher closure that
  tests a Request-URI user-part. First-match-wins is applied by the caller over
  the ordered rule list; the catch-all (`default = true`) is a rule property, not
  a pattern, and is handled by the caller.

  Symbols:

  | `X` | a digit `[0-9]`                                   |
  | `Z` | a digit `[1-9]`                                   |
  | `N` | a digit `[2-9]`                                   |
  | `[…]` | one char in the set/range, e.g. `[13-6]`        |
  | `.` | one or more of any character                     |
  | `!` | zero or more of any character                    |
  | other | matches literally                              |

  A pattern must match the **whole** user-part.

  Implementation: a hand-written tokenizer + a backtracking matcher (design
  option (b)) — no regex, so `[…]` ranges and the `.`/`!` wildcards have exact,
  unit-testable semantics with no escaping footguns.
  """

  @type matcher :: (String.t() -> boolean)

  # A token is one of:
  #   {:lit, codepoint}        literal char
  #   {:range, lo, hi}         one char in [lo..hi]  (also X/Z/N)
  #   {:set, [members]}        one char in a [...] set; member = {:char,c}|{:range,lo,hi}
  #   :plus                    one or more of any char  (`.`)
  #   :star                    zero or more of any char (`!`)

  @doc """
  Compile a pattern into a matcher closure.

  Returns `{:ok, fun}` where `fun.(user_part)` is a boolean, or `{:error, reason}`
  for a malformed pattern (e.g. an unterminated `[` set).
  """
  @spec compile(String.t()) :: {:ok, matcher} | {:error, term}
  def compile(pattern) when is_binary(pattern) do
    case tokenize(String.to_charlist(pattern), []) do
      {:ok, tokens} -> {:ok, fn input -> do_match(tokens, String.to_charlist(input)) end}
      {:error, _} = err -> err
    end
  end

  @doc "Convenience: compile `pattern` and test it against `input` in one shot."
  @spec matches?(String.t(), String.t()) :: boolean
  def matches?(pattern, input) do
    case compile(pattern) do
      {:ok, m} -> m.(input)
      {:error, _} -> false
    end
  end

  # ── tokenizer ──────────────────────────────────────────────────────────────

  defp tokenize([], acc), do: {:ok, Enum.reverse(acc)}
  defp tokenize([?X | rest], acc), do: tokenize(rest, [{:range, ?0, ?9} | acc])
  defp tokenize([?Z | rest], acc), do: tokenize(rest, [{:range, ?1, ?9} | acc])
  defp tokenize([?N | rest], acc), do: tokenize(rest, [{:range, ?2, ?9} | acc])
  defp tokenize([?. | rest], acc), do: tokenize(rest, [:plus | acc])
  defp tokenize([?! | rest], acc), do: tokenize(rest, [:star | acc])
  defp tokenize([?] | _rest], _acc), do: {:error, :unexpected_closing_bracket}

  defp tokenize([?[ | rest], acc) do
    case parse_set(rest, []) do
      {:ok, [], _rest2} -> {:error, :empty_set}
      {:ok, members, rest2} -> tokenize(rest2, [{:set, members} | acc])
      {:error, _} = err -> err
    end
  end

  defp tokenize([c | rest], acc), do: tokenize(rest, [{:lit, c} | acc])

  # parse the body of a [...] set until the closing ]
  defp parse_set([], _acc), do: {:error, :unterminated_set}
  defp parse_set([?] | rest], acc), do: {:ok, Enum.reverse(acc), rest}

  defp parse_set([a, ?-, b | rest], acc) when b != ?] and a <= b,
    do: parse_set(rest, [{:range, a, b} | acc])

  defp parse_set([c | rest], acc), do: parse_set(rest, [{:char, c} | acc])

  # ── matcher (whole-string, backtracking for . and !) ────────────────────────

  defp do_match([], []), do: true
  defp do_match([], [_ | _]), do: false

  # `.` — one or more of any char
  defp do_match([:plus | _rest], []), do: false

  defp do_match([:plus | rest], [_ | tail]),
    do: do_match(rest, tail) or do_match([:plus | rest], tail)

  # `!` — zero or more of any char
  defp do_match([:star | rest], input) do
    do_match(rest, input) or
      case input do
        [] -> false
        [_ | tail] -> do_match([:star | rest], tail)
      end
  end

  # a concrete token needs at least one input char
  defp do_match([_tok | _rest], []), do: false

  defp do_match([tok | rest], [c | tail]) do
    if tok_matches?(tok, c), do: do_match(rest, tail), else: false
  end

  defp tok_matches?({:lit, c}, c), do: true
  defp tok_matches?({:lit, _}, _), do: false
  defp tok_matches?({:range, lo, hi}, c), do: c >= lo and c <= hi
  defp tok_matches?({:set, members}, c), do: Enum.any?(members, &set_member?(&1, c))

  defp set_member?({:char, x}, c), do: x == c
  defp set_member?({:range, lo, hi}, c), do: c >= lo and c <= hi
end
