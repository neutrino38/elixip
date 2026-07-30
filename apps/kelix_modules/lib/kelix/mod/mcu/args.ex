defmodule Kelix.Mod.Mcu.Args do
  @moduledoc """
  Normalisation of a control command's arguments, whichever frontal they came from
  (design `docs/design/mcu_module.md` §8.3.6).

  REST hands `handle_control/2` a decoded JSON object (merged with the path and
  query params by FW-4); `kelictl` hands it `%{"args" => ["domain=example.com", …]}`
  because the CLI does not read the command registry (FW-3 would fix that). Until
  it does, the *module* normalises both shapes — here, once, rather than in every
  command clause.

  A CLI value is typed by its syntax: `true`/`false` → boolean, digits → integer,
  a leading `{`/`[` → JSON. That is what makes
  `layout='{"comp":1,"size":6}'` work on the command line with no quoting rules of
  its own.

  Every getter returns `{:ok, value}` / `{:error, message}` and never raises: an
  operator typo must become a `400`, not a module crash.
  """

  @type t :: %{optional(String.t()) => term}

  @doc """
  Flatten the two arg shapes into one string-keyed map.

  The `k=v` tokens win over an identically-named JSON key: a CLI invocation carries
  nothing else, so there is nothing to lose, and it keeps the merge total.
  """
  @spec normalize(map) :: t
  def normalize(args) when is_map(args) do
    {tokens, rest} = Map.pop(args, "args")
    Map.merge(rest, parse_tokens(tokens))
  end

  def normalize(_args), do: %{}

  defp parse_tokens(tokens) when is_list(tokens) do
    for token <- tokens, is_binary(token), into: %{} do
      case String.split(token, "=", parts: 2) do
        [key, value] -> {key, typed(value)}
        # a bare token is a flag: `force` means force=true
        [key] -> {key, true}
      end
    end
  end

  defp parse_tokens(_tokens), do: %{}

  defp typed("true"), do: true
  defp typed("false"), do: false

  defp typed(value) do
    cond do
      String.starts_with?(value, "{") or String.starts_with?(value, "[") -> json(value)
      match?({_, ""}, Integer.parse(value)) -> value |> Integer.parse() |> elem(0)
      true -> value
    end
  end

  defp json(value) do
    case Jason.decode(value) do
      {:ok, decoded} -> decoded
      # keep the raw string: the getter that needs a map will say so with a clear
      # error, which beats a cryptic JSON complaint about an unrelated argument
      {:error, _} -> value
    end
  end

  @doc """
  Refuse an argument the command does not know (design §8.3.3: an unknown field is
  a `400`, not a silent no-op — an operator who mistypes `max_participant` must
  learn it now and not from a conference that never fills up).
  """
  @spec reject_unknown(t, [String.t()]) :: :ok | {:error, String.t()}
  def reject_unknown(args, allowed) do
    case Map.keys(args) -- allowed do
      [] -> :ok
      extra -> {:error, "unknown argument(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  @doc "Refuse a server-owned field a client tried to send (§8.3.3 `PUT` semantics)."
  @spec reject_readonly(t, [String.t()]) :: :ok | {:error, String.t()}
  def reject_readonly(args, readonly) do
    case Enum.filter(readonly, &Map.has_key?(args, &1)) do
      [] -> :ok
      extra -> {:error, "read-only field(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  @doc "A required string argument."
  @spec required_string(t, String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def required_string(args, key) do
    case Map.get(args, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      nil -> {:error, "#{key} is required"}
      other -> {:error, "#{key} must be a string, got #{inspect(other)}"}
    end
  end

  @doc "An optional string argument (integers are accepted and stringified — a DID typed as a number)."
  @spec string(t, String.t(), String.t() | nil) :: {:ok, String.t() | nil} | {:error, String.t()}
  def string(args, key, default \\ nil) do
    case Map.get(args, key) do
      nil -> {:ok, default}
      v when is_binary(v) -> {:ok, v}
      v when is_integer(v) -> {:ok, Integer.to_string(v)}
      other -> {:error, "#{key} must be a string, got #{inspect(other)}"}
    end
  end

  @doc "An optional integer argument, optionally restricted to `allowed`."
  @spec int(t, String.t(), term, [integer] | nil) :: {:ok, term} | {:error, String.t()}
  def int(args, key, default, allowed \\ nil) do
    case Map.get(args, key) do
      nil ->
        {:ok, default}

      v when is_integer(v) ->
        cond do
          is_nil(allowed) and v >= 0 -> {:ok, v}
          is_nil(allowed) -> {:error, "#{key} must be a non-negative integer"}
          v in allowed -> {:ok, v}
          true -> {:error, "#{key} must be one of #{inspect(allowed)}"}
        end

      other ->
        {:error, "#{key} must be an integer, got #{inspect(other)}"}
    end
  end

  @doc "An optional boolean argument."
  @spec bool(t, String.t(), boolean) :: {:ok, boolean} | {:error, String.t()}
  def bool(args, key, default) do
    case Map.get(args, key) do
      nil -> {:ok, default}
      v when is_boolean(v) -> {:ok, v}
      other -> {:error, "#{key} must be a boolean, got #{inspect(other)}"}
    end
  end

  @doc "An optional list-of-strings argument (upcased — codec names are case-insensitive)."
  @spec codec_list(t, String.t(), [String.t()]) :: {:ok, [String.t()]} | {:error, String.t()}
  def codec_list(args, key, default) do
    case Map.get(args, key) do
      nil ->
        {:ok, default}

      list when is_list(list) ->
        if Enum.all?(list, &is_binary/1),
          do: {:ok, Enum.map(list, &String.upcase/1)},
          else: {:error, "#{key} must be a list of codec names"}

      other ->
        {:error, "#{key} must be a list of codec names, got #{inspect(other)}"}
    end
  end

  @doc """
  An optional sub-map argument (`video`, `layout`), merged over `default` and
  restricted to `allowed` keys — so `video='{"fps":25}'` changes the frame rate and
  keeps the rest of the profile.
  """
  @spec sub_map(t, String.t(), map, [atom]) :: {:ok, map} | {:error, String.t()}
  def sub_map(args, key, default, allowed) do
    case Map.get(args, key) do
      nil ->
        {:ok, default}

      map when is_map(map) ->
        allowed_names = Enum.map(allowed, &Atom.to_string/1)

        case Map.keys(map) -- allowed_names do
          [] -> merge_sub_map(map, default, key)
          extra -> {:error, "#{key}: unknown field(s): #{Enum.join(Enum.sort(extra), ", ")}"}
        end

      other ->
        {:error, "#{key} must be a table, got #{inspect(other)}"}
    end
  end

  defp merge_sub_map(map, default, key) do
    Enum.reduce_while(map, {:ok, default}, fn {name, value}, {:ok, acc} ->
      atom = String.to_existing_atom(name)

      case value do
        v when is_integer(v) and v >= 0 ->
          {:cont, {:ok, Map.put(acc, atom, v)}}

        v when is_boolean(v) ->
          {:cont, {:ok, Map.put(acc, atom, v)}}

        other ->
          {:halt,
           {:error, "#{key}.#{name} must be an integer or a boolean, got #{inspect(other)}"}}
      end
    end)
  end
end
