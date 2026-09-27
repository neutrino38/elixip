# The resource list a watcher carries in its SUBSCRIBE (RFC 5367 over RFC 4826):
# `application/resource-lists+xml`, read into the URIs it names.

defmodule SIP.Presence.ResourceLists do
  @moduledoc """
  `application/resource-lists+xml`, in the one direction this node needs it.

  RFC 4826 defines the document as what an XCAP server stores; RFC 5367 has a
  watcher put one **in its SUBSCRIBE** instead, under
  `Content-Disposition: recipient-list`, which is how a Linphone client opens its
  buddy list with a single subscription. So this reads, and does not write: the
  list is the watcher's, never ours.

  ## What it answers

  The `uri` of every `<entry>`, in document order, deduplicated, whatever nesting
  of `<list>` elements they sit under — a real client sends one flat `<list>`, and
  the schema allows lists inside lists.

  `<entry-ref>` and `<external>` are **skipped**: both name a document to go and
  fetch over XCAP, which this node does not do. Skipping them is not the same as
  refusing the list — a watcher mixing an `<entry>` with an `<external>` gets the
  buddies we can serve rather than an empty answer.

  The safety rules are `SIP.Presence.Pidf`'s, for the same reason — the body is
  untrusted network input: a size bound, a doctype refused outright, and
  `:erlsom`, which resolves no external entity.
  """

  require Logger

  @max_body_size 64 * 1024
  @ns "urn:ietf:params:xml:ns:resource-lists"

  @doc """
  Read a resource-lists body into the list of URIs it names.

  Answers `{:ok, uris}` — possibly `[]`, which is a list naming nobody and not an
  error — or `{:error, reason}` for a body that is too large, carries a doctype,
  is not well-formed, or whose root is not `<resource-lists>`.

      iex> SIP.Presence.ResourceLists.parse(~s(<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="sip:bob@example.com"/></list></resource-lists>))
      {:ok, ["sip:bob@example.com"]}
  """
  @spec parse(binary()) :: {:ok, [binary()]} | {:error, term()}
  def parse(body) when is_binary(body) do
    with :ok <- check_size(body),
         :ok <- check_no_doctype(body),
         {:ok, root} <- scan(body) do
      read_root(root)
    end
  end

  def parse(other), do: {:error, {:not_a_body, other}}

  defp check_size(body) when byte_size(body) > @max_body_size,
    do: {:error, {:body_too_large, byte_size(body)}}

  defp check_size(_body), do: :ok

  defp check_no_doctype(body) do
    prolog = body |> String.split(~r/<[A-Za-z_]/, parts: 2) |> hd()

    if prolog =~ ~r/<!DOCTYPE/i do
      {:error, :doctype_not_allowed}
    else
      :ok
    end
  end

  defp scan(body) do
    case :erlsom.simple_form(body, output_encoding: :utf8) do
      {:ok, root, _tail} -> {:ok, root}
      {:error, reason} -> {:error, {:malformed_xml, reason}}
    end
  catch
    :throw, {:error, reason} -> {:error, {:malformed_xml, reason}}
    :throw, reason -> {:error, {:malformed_xml, reason}}
    :exit, {:error, reason} -> {:error, {:malformed_xml, reason}}
    :exit, reason -> {:error, {:malformed_xml, reason}}
    :error, reason -> {:error, {:malformed_xml, reason}}
  end

  defp read_root({name, _attrs, children}) do
    case split_name(name) do
      {ns, "resource-lists"} when ns in [@ns, ""] ->
        {:ok, children |> collect_entries() |> Enum.uniq()}

      {_ns, other} ->
        {:error, {:not_a_resource_list, other}}
    end
  end

  # `<list>` nests, so this walks rather than looks one level down.
  defp collect_entries(children) do
    Enum.flat_map(children, fn child ->
      case element(child) do
        {ns, "entry", attrs, _grandchildren} when ns in [@ns, ""] ->
          case attribute(attrs, "uri") do
            nil -> []
            uri -> [uri]
          end

        {ns, "list", _attrs, grandchildren} when ns in [@ns, ""] ->
          collect_entries(grandchildren)

        _other ->
          []
      end
    end)
  end

  defp element({name, attrs, children}) when is_list(name) do
    {ns, local} = split_name(name)
    {ns, local, attrs, children}
  end

  defp element(_text), do: nil

  defp split_name(name) do
    case name |> to_string() |> String.split("}", parts: 2) do
      ["{" <> ns, local] -> {ns, local}
      [local] -> {"", local}
    end
  end

  defp attribute(attrs, name) do
    Enum.find_value(attrs, fn
      {attr_name, value} -> if to_string(attr_name) == name, do: to_string(value)
      _other -> nil
    end)
  end
end
