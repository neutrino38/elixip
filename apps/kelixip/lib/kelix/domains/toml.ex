defmodule Kelix.Domains.Toml do
  @moduledoc """
  Encodes the decoded `domains.toml` map back to TOML text: what a write through
  the frontals puts on disk (`docs/design/dynamic-domains-plan.md`, decision 1).

  It covers the types of the `domains.toml` schema only — strings, integers,
  booleans, arrays of those, tables and arrays of tables, nested ones included.
  Anything else is refused, never approximated.

  `encode/1` reads its own text back with the decoder, and refuses a text that
  does not give back the map it was given.
  """

  @header """
  # domains.toml — the served domains and their dial-plan.
  #
  # Written by kelixip. A domain created, edited or deleted through kelictl, the
  # REST API or kelescope rewrites this file, and comments do not survive that.
  # A hand edit is applied with `kelictl domain reload-all`; until then, the node
  # refuses to write over it. A commented example of every block is in
  # /usr/share/doc/kelixip/domains.toml.example.
  """

  # Keys the schema knows come in this order, whatever the order of the map;
  # any other key follows, alphabetically.
  @key_order ~w(name aliases max_calls event-package keepalive pattern default script
                subscribe publish idle_timeout registrar presence call chat options)

  @spec encode(map) :: {:ok, String.t()} | {:error, String.t()}
  def encode(map) when is_map(map) do
    with {:ok, body} <- table([], map, :root) do
      text = IO.iodata_to_binary([@header, body])

      case Toml.decode(text) do
        {:ok, ^map} -> {:ok, text}
        {:ok, _other} -> {:error, "the encoded TOML does not read back as the same data"}
        {:error, reason} -> {:error, "the encoded TOML does not parse: #{inspect(reason)}"}
      end
    end
  end

  # An array element has its `[[path]]` line written by the caller. A table needs
  # its own `[path]` line only when it holds plain keys or nothing at all: one
  # holding only sub-tables is created by their headers.
  defp table(path, map, kind) do
    with {:ok, {scalars, nested}} <- split(path, map),
         {:ok, lines} <- map_ok(scalars, &scalar_line(path, &1)),
         {:ok, subs} <- map_ok(nested, &nested(path, &1)) do
      head =
        if kind == :table and (scalars != [] or map == %{}),
          do: ["\n", indent(path), "[", dotted(path), "]\n"],
          else: []

      {:ok, [head, lines, subs]}
    end
  end

  defp scalar_line(path, {k, v}) do
    with {:ok, key} <- key(path, k),
         {:ok, val} <- value(path ++ [k], v) do
      {:ok, [indent(path), key, " = ", val, "\n"]}
    end
  end

  defp nested(path, {k, map}) when is_map(map), do: table(path ++ [k], map, :table)

  defp nested(path, {k, list}) do
    sub = path ++ [k]

    map_ok(list, fn map ->
      with {:ok, body} <- table(sub, map, :element) do
        {:ok, ["\n", indent(sub), "[[", dotted(sub), "]]\n", body]}
      end
    end)
  end

  # TOML wants every plain key of a table before its first sub-table header; the
  # tables and arrays of tables that follow can come in any order.
  defp split(path, map) do
    Enum.reduce_while(map, {:ok, {[], []}}, fn {k, v} = kv, {:ok, {s, n}} ->
      cond do
        not is_binary(k) ->
          {:halt, {:error, "#{where(path)}: key #{inspect(k)} is not a string"}}

        is_map(v) or (is_list(v) and v != [] and Enum.all?(v, &is_map/1)) ->
          {:cont, {:ok, {s, [kv | n]}}}

        is_list(v) and Enum.any?(v, &is_map/1) ->
          {:halt, {:error, "#{where(path ++ [k])}: mixes tables and values"}}

        true ->
          {:cont, {:ok, {[kv | s], n}}}
      end
    end)
    |> case do
      {:ok, {s, n}} -> {:ok, {sort(s), sort(n)}}
      err -> err
    end
  end

  defp sort(pairs) do
    Enum.sort_by(pairs, fn {k, _} ->
      {Enum.find_index(@key_order, &(&1 == k)) || length(@key_order), k}
    end)
  end

  defp value(_path, v) when is_boolean(v), do: {:ok, to_string(v)}
  defp value(_path, v) when is_integer(v), do: {:ok, Integer.to_string(v)}
  defp value(path, v) when is_binary(v), do: string(path, v)

  defp value(path, list) when is_list(list) do
    with {:ok, items} <- map_ok(list, &value(path, &1)) do
      {:ok, ["[", Enum.intersperse(items, ", "), "]"]}
    end
  end

  defp value(path, v), do: {:error, "#{where(path)}: cannot be written as TOML: #{inspect(v)}"}

  defp key(path, k) do
    if Regex.match?(~r/^[A-Za-z0-9_-]+$/, k), do: {:ok, k}, else: string(path ++ [k], k)
  end

  defp string(path, s) do
    if String.valid?(s),
      do: {:ok, ["\"", escape(s), "\""]},
      else: {:error, "#{where(path)}: not valid UTF-8"}
  end

  defp escape(s) do
    for <<c::utf8 <- s>>, into: "" do
      case c do
        ?" ->
          "\\\""

        ?\\ ->
          "\\\\"

        ?\n ->
          "\\n"

        ?\t ->
          "\\t"

        ?\r ->
          "\\r"

        ?\b ->
          "\\b"

        ?\f ->
          "\\f"

        c when c < 0x20 or c == 0x7F ->
          "\\u" <> String.pad_leading(Integer.to_string(c, 16), 4, "0")

        c ->
          <<c::utf8>>
      end
    end
  end

  defp dotted(path), do: Enum.map_join(path, ".", &IO.iodata_to_binary(elem(key([], &1), 1)))

  defp indent([]), do: ""
  defp indent(path), do: String.duplicate("  ", length(path) - 1)

  defp where([]), do: "the top level"
  defp where(path), do: Enum.join(path, ".")

  defp map_ok(list, fun) do
    Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
      case fun.(item) do
        {:ok, out} -> {:cont, {:ok, [out | acc]}}
        {:error, _} = err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      err -> err
    end
  end
end
