defmodule Kelix.Domains.Edit do
  @moduledoc """
  The commands that edit one domain (`docs/design/dynamic-domains-plan.md`, §4),
  as pure transformations of its `[[domain]]` table (`change/2`) — string keys, the file's own
  shape. `Kelix.Control` reads the table, applies one command here, and hands the
  result to `Kelix.Domains.put_domain/2`, which validates it as the file is
  validated at boot.

  A rule is addressed by its 1-based number in its list, in the order the router
  tries it. The `options` list numbers its rules without the keepalive entry, which
  is not a rule. Arguments arrive as the frontals give them: strings from kelictl,
  JSON values from REST; integers are read from either, and `none` (or `nil`)
  removes an optional key.

  `change/2` answers `{:ok, table}`, `{:error, :not_found}` for an alias, block, package or
  rule number the domain does not have, `{:error, :exists}` for one it already has,
  or `{:error, {:invalid, message}}`.
  """

  @type list_name :: :call | :chat | :options | {:subscribe, String.t()}
  @type command ::
          {:set, map}
          | {:alias_add, String.t()}
          | {:alias_remove, String.t()}
          | {:registrar_set, map}
          | :registrar_remove
          | {:presence_add, String.t(), map}
          | {:presence_set, String.t(), map}
          | {:presence_remove, String.t()}
          | {:rule_add, list_name, String.t(), map}
          | {:rule_update, list_name, term, map}
          | {:rule_move, list_name, term, term}
          | {:rule_remove, list_name, term}
          | {:keepalive_set, String.t()}
          | :keepalive_remove

  @doc "A new domain's table: `name`, plus `aliases` and `max_calls` when given."
  @spec new(String.t(), map) :: {:ok, map} | {:error, term}
  def new(name, attrs) do
    with :ok <- only(attrs, ~w(aliases max_calls)),
         {:ok, table} <- set_keys(%{"name" => name}, attrs, max_calls: :int) do
      case Map.get(attrs, "aliases") do
        nil -> {:ok, table}
        aliases -> {:ok, Map.put(table, "aliases", host_list(aliases))}
      end
    end
  end

  @doc "Apply one command to a domain's table."
  @spec change(map, command) :: {:ok, map} | {:error, term}
  def change(table, {:set, attrs}) do
    with :ok <- only(attrs, ~w(max_calls)), do: set_keys(table, attrs, max_calls: :int)
  end

  def change(table, {:alias_add, host}) do
    aliases = Map.get(table, "aliases", [])

    if Enum.any?(aliases, &same?(&1, host)),
      do: {:error, :exists},
      else: {:ok, Map.put(table, "aliases", aliases ++ [host])}
  end

  def change(table, {:alias_remove, host}) do
    aliases = Map.get(table, "aliases", [])

    case Enum.reject(aliases, &same?(&1, host)) do
      ^aliases -> {:error, :not_found}
      [] -> {:ok, Map.delete(table, "aliases")}
      kept -> {:ok, Map.put(table, "aliases", kept)}
    end
  end

  def change(table, {:registrar_set, attrs}) do
    keys = [script: :string, default_expires: :int, min_expires: :int, keepalive_period: :int]

    with :ok <- only(attrs, Enum.map(keys, &to_string(elem(&1, 0)))),
         {:ok, block} <- set_keys(Map.get(table, "registrar", %{}), attrs, keys) do
      {:ok, Map.put(table, "registrar", block)}
    end
  end

  def change(table, :registrar_remove) do
    if Map.has_key?(table, "registrar"),
      do: {:ok, Map.delete(table, "registrar")},
      else: {:error, :not_found}
  end

  def change(table, {:presence_add, package, attrs}) do
    blocks = Map.get(table, "presence", [])

    with :ok <- only(attrs, ~w(subscribe publish)),
         nil <- find_package(blocks, package) && {:error, :exists},
         {:ok, block} <-
           set_keys(%{"event-package" => package}, attrs, subscribe: :string, publish: :string) do
      {:ok, Map.put(table, "presence", blocks ++ [block])}
    end
  end

  def change(table, {:presence_set, package, attrs}) do
    with :ok <- only(attrs, ~w(subscribe publish)) do
      update_package(table, package, fn block ->
        set_keys(block, attrs, subscribe: :string, publish: :string)
      end)
    end
  end

  def change(table, {:presence_remove, package}) do
    blocks = Map.get(table, "presence", [])

    case Enum.reject(blocks, &same?(&1["event-package"], package)) do
      ^blocks -> {:error, :not_found}
      [] -> {:ok, Map.delete(table, "presence")}
      kept -> {:ok, Map.put(table, "presence", kept)}
    end
  end

  def change(table, {:rule_add, list, rule, attrs}) do
    with :ok <- only(attrs, ["script", "at" | extra_keys(list)]),
         {:ok, entry} <- rule_entry(%{}, rule),
         {:ok, entry} <- set_keys(entry, Map.delete(attrs, "at"), rule_keys(list)) do
      edit_rules(table, list, fn rules ->
        with {:ok, at} <- position(Map.get(attrs, "at"), rules) do
          {:ok, List.insert_at(rules, at - 1, entry)}
        end
      end)
    end
  end

  def change(table, {:rule_update, list, n, attrs}) do
    with :ok <- only(attrs, ["pattern", "script" | extra_keys(list)]) do
      edit_rules(table, list, fn rules ->
        with {:ok, i} <- number(n, rules),
             entry = Enum.at(rules, i),
             {:ok, entry} <- maybe_pattern(entry, Map.get(attrs, "pattern")),
             {:ok, entry} <- set_keys(entry, Map.delete(attrs, "pattern"), rule_keys(list)) do
          {:ok, List.replace_at(rules, i, entry)}
        end
      end)
    end
  end

  def change(table, {:rule_move, list, n, to}) do
    edit_rules(table, list, fn rules ->
      with {:ok, i} <- number(n, rules),
           {:ok, j} <- target(to, rules) do
        {entry, rest} = List.pop_at(rules, i)
        {:ok, List.insert_at(rest, j, entry)}
      end
    end)
  end

  def change(table, {:rule_remove, list, n}) do
    edit_rules(table, list, fn rules ->
      with {:ok, i} <- number(n, rules), do: {:ok, List.delete_at(rules, i)}
    end)
  end

  def change(table, {:keepalive_set, script}) do
    {_old, rules} = split_keepalive(Map.get(table, "options", []))
    {:ok, Map.put(table, "options", [%{"keepalive" => true, "script" => script} | rules])}
  end

  def change(table, :keepalive_remove) do
    case split_keepalive(Map.get(table, "options", [])) do
      {nil, _rules} -> {:error, :not_found}
      {_keepalive, []} -> {:ok, Map.delete(table, "options")}
      {_keepalive, rules} -> {:ok, Map.put(table, "options", rules)}
    end
  end

  # ── ordered rule lists ───────────────────────────────────────────────────────

  @doc "The rules of one list of a domain's table, in the order they are numbered."
  @spec rules(map, list_name) :: [map]
  def rules(table, list) when list in [:call, :chat], do: Map.get(table, Atom.to_string(list), [])

  def rules(table, :options) do
    {_keepalive, rules} = split_keepalive(Map.get(table, "options", []))
    rules
  end

  # The one-script shorthand `subscribe = "x.exs"` is a single catch-all rule.
  def rules(table, {:subscribe, package}) do
    blocks = Map.get(table, "presence", [])

    case find_package(blocks, package) do
      nil -> []
      i -> subscribe_rules(Enum.at(blocks, i))
    end
  end

  defp subscribe_rules(block) do
    case Map.get(block, "subscribe") do
      script when is_binary(script) -> [%{"default" => true, "script" => script}]
      rules when is_list(rules) -> rules
      nil -> []
    end
  end

  # `fun` sees the list's rules, numbered from 1, and answers the new list.
  defp edit_rules(table, list, fun) when list in [:call, :chat] do
    with {:ok, rules} <- fun.(rules(table, list)),
         do: {:ok, put_list(table, Atom.to_string(list), rules)}
  end

  defp edit_rules(table, :options, fun) do
    {keepalive, rules} = split_keepalive(Map.get(table, "options", []))

    with {:ok, rules} <- fun.(rules) do
      {:ok, put_list(table, "options", List.wrap(keepalive) ++ rules)}
    end
  end

  # The first rule command on a package written with the shorthand writes it out as
  # the list it stands for.
  defp edit_rules(table, {:subscribe, package}, fun) do
    update_package(table, package, fn block ->
      with {:ok, rules} <- fun.(subscribe_rules(block)),
           do: {:ok, Map.put(block, "subscribe", rules)}
    end)
  end

  defp put_list(table, key, []), do: Map.delete(table, key)
  defp put_list(table, key, rules), do: Map.put(table, key, rules)

  defp split_keepalive(options) do
    case Enum.split_with(options, &Map.has_key?(&1, "keepalive")) do
      {[keepalive | _], rules} -> {keepalive, rules}
      {[], rules} -> {nil, rules}
    end
  end

  # Without `at`, a new rule goes just before the catch-all, which must stay last.
  defp position(nil, rules) do
    case Enum.find_index(rules, &(&1["default"] == true)) do
      nil -> {:ok, length(rules) + 1}
      i -> {:ok, i + 1}
    end
  end

  defp position(at, rules) do
    case int(at) do
      {:ok, n} when n >= 1 and n <= length(rules) + 1 ->
        {:ok, n}

      _ ->
        {:error, {:invalid, "`at` must be a rule number from 1 to #{length(rules) + 1}"}}
    end
  end

  defp number(n, rules) do
    case int(n) do
      {:ok, i} when i >= 1 and i <= length(rules) -> {:ok, i - 1}
      {:ok, _out_of_range} -> {:error, :not_found}
      _ -> {:error, {:invalid, "a rule is addressed by its number, got #{inspect(n)}"}}
    end
  end

  defp target(to, rules) do
    case int(to) do
      {:ok, j} when j >= 1 and j <= length(rules) ->
        {:ok, j - 1}

      _ ->
        {:error, {:invalid, "`to` must be a rule number from 1 to #{length(rules)}"}}
    end
  end

  defp rule_entry(entry, "default"),
    do: {:ok, entry |> Map.delete("pattern") |> Map.put("default", true)}

  defp rule_entry(entry, pattern) when is_binary(pattern) and pattern != "",
    do: {:ok, entry |> Map.delete("default") |> Map.put("pattern", pattern)}

  defp rule_entry(_entry, _),
    do: {:error, {:invalid, "a rule needs a pattern, or `default` for the catch-all"}}

  defp maybe_pattern(entry, nil), do: {:ok, entry}
  defp maybe_pattern(entry, pattern), do: rule_entry(entry, pattern)

  defp extra_keys(:chat), do: ["idle_timeout"]
  defp extra_keys(_list), do: []

  defp rule_keys(:chat), do: [script: :string, idle_timeout: :int]
  defp rule_keys(_list), do: [script: :string]

  # ── presence blocks ──────────────────────────────────────────────────────────

  defp find_package(blocks, package),
    do: Enum.find_index(blocks, &same?(&1["event-package"], package))

  defp update_package(table, package, fun) do
    blocks = Map.get(table, "presence", [])

    case find_package(blocks, package) do
      nil ->
        {:error, :not_found}

      i ->
        with {:ok, block} <- fun.(Enum.at(blocks, i)),
             do: {:ok, Map.put(table, "presence", List.replace_at(blocks, i, block))}
    end
  end

  # ── arguments ────────────────────────────────────────────────────────────────

  defp only(attrs, allowed) do
    case Map.keys(attrs) -- allowed do
      [] -> :ok
      extra -> {:error, {:invalid, "unknown argument(s): #{Enum.join(Enum.sort(extra), ", ")}"}}
    end
  end

  # Sets the given keys, typed; `none` or nil removes one.
  defp set_keys(map, attrs, types) do
    Enum.reduce_while(types, {:ok, map}, fn {key, type}, {:ok, acc} ->
      name = Atom.to_string(key)

      case Map.fetch(attrs, name) do
        :error ->
          {:cont, {:ok, acc}}

        {:ok, v} when v in [nil, "none"] ->
          {:cont, {:ok, Map.delete(acc, name)}}

        {:ok, v} ->
          case typed(v, type) do
            {:ok, value} -> {:cont, {:ok, Map.put(acc, name, value)}}
            :error -> {:halt, {:error, {:invalid, "`#{name}` must be #{describe(type)}"}}}
          end
      end
    end)
  end

  defp typed(v, :string) when is_binary(v) and v != "", do: {:ok, v}

  defp typed(v, :int) do
    case int(v) do
      {:ok, n} when n > 0 -> {:ok, n}
      _ -> :error
    end
  end

  defp typed(_v, _type), do: :error

  defp describe(:string), do: "a non-empty string"
  defp describe(:int), do: "a positive integer"

  defp int(n) when is_integer(n), do: {:ok, n}

  defp int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} -> {:ok, n}
      _ -> :error
    end
  end

  defp int(_), do: :error

  defp host_list(hosts) when is_list(hosts), do: hosts
  defp host_list(hosts) when is_binary(hosts), do: String.split(hosts, ",", trim: true)

  defp same?(a, b) when is_binary(a) and is_binary(b),
    do: String.downcase(a) == String.downcase(b)

  defp same?(_a, _b), do: false
end
