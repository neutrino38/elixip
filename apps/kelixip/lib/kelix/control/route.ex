defmodule Kelix.Control.Route do
  @moduledoc """
  Pure routing algebra for the module-contributed control commands (design
  `docs/design/mcu_module.md` §8.3.4, FW-4).

  A command declares `rest: {method | [method], path_template}` where the template
  is relative to `/modules/<name>` and may contain `:param` segments. This module
  is everything the REST frontal needs to turn that declaration into a route:

    * `segments/1` — compile a template into matchable segments;
    * `match/2` — match compiled segments against a request path, yielding the
      path parameters;
    * `specificity/1` — the sort key that resolves **most-literal-first**
      (`/conferences` before `/conferences/:uid`);
    * `check_conflicts/1` — refuse an ambiguous pair **at registration time**
      rather than resolving it arbitrarily per request;
    * `render/2` — fill a `Location:` template from a result map.

  Two templates are *ambiguous* when no request could tell them apart: same length
  and, at every position, either two params or the same literal. A param facing a
  literal is **not** ambiguous — `specificity/1` orders the literal first, which is
  a deterministic (and conventional) answer.
  """

  @type segment :: {:lit, String.t()} | {:param, String.t()}
  @type command :: Kelix.Module.control_command()

  @methods [:get, :post, :put, :patch, :delete]

  @doc "The HTTP methods a command answers (a bare atom or a list; `[:post]` by default)."
  @spec methods(command) :: [atom]
  def methods(%{rest: {method, _path}}) when is_atom(method), do: [method]

  def methods(%{rest: {methods, _path}}) when is_list(methods),
    do: Enum.filter(methods, &(&1 in @methods))

  def methods(_command), do: [:post]

  @doc """
  The path template of a command, relative to `/modules/<name>`.

  A command that declares none falls back to `/<name>`, i.e. exactly the flat
  single-segment route the frontal offered before FW-4 (§8.3.5).
  """
  @spec template(command) :: String.t()
  def template(%{rest: {_methods, path}}) when is_binary(path), do: path
  def template(%{name: name}), do: "/" <> name

  @doc """
  Compile a path template into segments.

      iex> Kelix.Control.Route.segments("/conferences/:uid/participants")
      [{:lit, "conferences"}, {:param, "uid"}, {:lit, "participants"}]
  """
  @spec segments(String.t()) :: [segment]
  def segments(path) when is_binary(path) do
    path
    |> String.split("/", trim: true)
    |> Enum.map(fn
      ":" <> name -> {:param, name}
      literal -> {:lit, literal}
    end)
  end

  @doc """
  Match compiled `segments` against a request path (a list of segments).

  Returns `{:ok, params}` with the captured `:param` values as a string-keyed map,
  or `:error`.
  """
  @spec match([segment], [String.t()]) :: {:ok, %{optional(String.t()) => String.t()}} | :error
  def match(segments, path) when is_list(segments) and is_list(path) do
    if length(segments) == length(path) do
      Enum.zip(segments, path)
      |> Enum.reduce_while({:ok, %{}}, fn
        {{:lit, lit}, lit}, acc -> {:cont, acc}
        {{:lit, _}, _}, _acc -> {:halt, :error}
        {{:param, name}, value}, {:ok, params} -> {:cont, {:ok, Map.put(params, name, value)}}
      end)
    else
      :error
    end
  end

  @doc """
  Sort key ordering matched templates **most-literal-first**: a literal segment
  sorts before a param at the same position, so `/conferences/list` wins over
  `/conferences/:uid` for the path `conferences/list`.
  """
  @spec specificity([segment]) :: [0 | 1]
  def specificity(segments) do
    Enum.map(segments, fn
      {:lit, _} -> 0
      {:param, _} -> 1
    end)
  end

  @doc """
  Refuse a command set that carries an ambiguous pair (same method, templates no
  request can tell apart). Returns `:ok` or `{:error, {:ambiguous_templates, a, b}}`
  naming the two offending command ids.
  """
  @spec check_conflicts([command]) ::
          :ok | {:error, {:ambiguous_templates, String.t(), String.t()}}
  def check_conflicts(commands) when is_list(commands) do
    compiled = Enum.map(commands, &{&1, segments(template(&1)), methods(&1)})

    conflict =
      for {a, segs_a, meth_a} <- compiled,
          {b, segs_b, meth_b} <- compiled,
          a.name < b.name,
          # only a shared method makes two matching templates undecidable
          Enum.any?(meth_a, &(&1 in meth_b)),
          ambiguous?(segs_a, segs_b),
          do: {a.name, b.name}

    case conflict do
      [{a, b} | _] -> {:error, {:ambiguous_templates, a, b}}
      [] -> :ok
    end
  end

  @doc "Whether two compiled templates could both match the same request path."
  @spec ambiguous?([segment], [segment]) :: boolean
  def ambiguous?(a, b) when length(a) == length(b) do
    Enum.zip(a, b)
    |> Enum.all?(fn
      {{:param, _}, {:param, _}} -> true
      {{:lit, x}, {:lit, x}} -> true
      _ -> false
    end)
  end

  def ambiguous?(_a, _b), do: false

  @doc """
  The status a command declares for `reason`, else the default mapping.

  This is the **one** reading of a command's `errors:` map: the REST frontal turns
  it into the HTTP status, `kelictl` into an exit code (FW-5), and neither invents
  its own table — a module that declares `no_did_available: 409` is a `409` and a
  non-zero-in-its-own-right exit code, from a single declaration.

  The default mapping covers what a module returns without declaring it:

    * `:not_found` / `:unknown` / `:unknown_module` → `404`, nothing to act on;
    * `:down` / `:timeout` → `503`: these are `Kelix.Module.safe_call/3` saying the
      service is absent or wedged, which is the server's problem and not the
      caller's — the retry semantics of a `400` would be exactly wrong;
    * anything else → `400`, i.e. "the request was not usable".

  A `reason` that is a tuple is keyed on its first element (`{:bad_offer, detail}`
  matches a declared `bad_offer:`), so a module can carry a detail without losing
  its declaration.
  """
  @spec error_status(command | map, term) :: 100..599
  def error_status(command, reason) when is_map(command) do
    case Map.get(Map.get(command, :errors, %{}), reason_key(reason)) do
      status when is_integer(status) -> status
      nil -> default_error_status(reason)
    end
  end

  defp reason_key(reason) when is_atom(reason), do: reason

  defp reason_key(reason) when is_tuple(reason) and tuple_size(reason) > 0 do
    case elem(reason, 0) do
      atom when is_atom(atom) -> atom
      _ -> nil
    end
  end

  defp reason_key(_reason), do: nil

  defp default_error_status(reason) when reason in [:not_found, :unknown, :unknown_module],
    do: 404

  defp default_error_status(reason) when reason in [:down, :timeout], do: 503
  defp default_error_status(_reason), do: 400

  @doc """
  Render a `location:` template from a result map, e.g. `"/conferences/:uid"` with
  `%{uid: "c-1"}` → `{:ok, "/conferences/c-1"}`. `:error` when the result does not
  carry every param the template names (the frontal then omits the header rather
  than emitting a `Location` pointing nowhere).
  """
  @spec render(String.t(), map) :: {:ok, String.t()} | :error
  def render(template, result) when is_binary(template) and is_map(result) do
    template
    |> segments()
    |> Enum.reduce_while({:ok, []}, fn
      {:lit, lit}, {:ok, acc} ->
        {:cont, {:ok, [lit | acc]}}

      {:param, name}, {:ok, acc} ->
        case fetch_param(result, name) do
          {:ok, value} -> {:cont, {:ok, [to_string(value) | acc]}}
          :error -> {:halt, :error}
        end
    end)
    |> case do
      {:ok, parts} -> {:ok, "/" <> Enum.join(Enum.reverse(parts), "/")}
      :error -> :error
    end
  end

  def render(_template, _result), do: :error

  # a result map may be atom- or string-keyed (whatever handle_control/2 returned)
  defp fetch_param(result, name) do
    case Map.fetch(result, name) do
      {:ok, value} -> {:ok, value}
      :error -> atom_fetch(result, name)
    end
  end

  defp atom_fetch(result, name) do
    Map.fetch(result, String.to_existing_atom(name))
  rescue
    ArgumentError -> :error
  end
end
