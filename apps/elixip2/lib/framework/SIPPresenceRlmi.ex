# RLMI (RFC 4662 §5): the manifest of a list NOTIFY — which resources the list
# holds, and which MIME part of the multipart body carries each one's state.

defmodule SIP.Presence.Rlmi do
  @moduledoc """
  `application/rlmi+xml`, the first part of a list NOTIFY.

  A list subscription answers one SUBSCRIBE with the state of N resources. The
  body is a `multipart/related` whose **root part is this document**: it names
  the list, says whether what follows is the full state or only what changed, and
  for each resource points at the part carrying its state through a `cid`.

  ## `version` and `fullState` are one mechanism

  `version` counts the NOTIFYs of a subscription and never resets. A watcher that
  receives version 7 after version 5 knows it lost one — and what it does about
  it is ask for the whole thing again, which is why every notifier sends
  `fullState="true"` in its first NOTIFY and false afterwards. A partial NOTIFY
  carries only the resources that changed; a full one carries them all.

  Both are the **subscription's**, not the list's: two watchers of one list have
  their own counters. `%SIP.Subscription{}.version` is where that number lives.

  ## An instance is a state, not a device

  `<resource>` is what the list names; `<instance>` is one source of state for it,
  with an `id` that must be **stable across NOTIFYs** for a watcher to be able to
  replace it rather than accumulate copies. A resource we cannot serve gets an
  instance all the same, `state="terminated"` with a `reason` — `noresource` for a
  resource this node knows nothing about. Silence would leave the watcher waiting
  on a buddy that will never arrive.
  """

  defmodule Instance do
    @moduledoc "One source of state for a resource (RFC 4662 §5.2)."
    defstruct id: nil, state: :active, cid: nil, reason: nil

    @type t :: %__MODULE__{
            id: binary() | nil,
            state: :active | :pending | :terminated,
            cid: binary() | nil,
            reason: binary() | nil
          }
  end

  defmodule Resource do
    @moduledoc "One entry of the list, and the instances holding its state."
    defstruct uri: nil, name: nil, instances: []

    @type t :: %__MODULE__{
            uri: binary() | nil,
            name: binary() | nil,
            instances: [SIP.Presence.Rlmi.Instance.t()]
          }
  end

  defstruct uri: nil, version: 0, full_state: true, name: nil, resources: []

  @type t :: %__MODULE__{
          uri: binary() | nil,
          version: non_neg_integer(),
          full_state: boolean(),
          name: binary() | nil,
          resources: [Resource.t()]
        }

  @ns "urn:ietf:params:xml:ns:rlmi"
  @max_body_size 256 * 1024

  @doc """
  The content type this document is carried as, and the `type` parameter of the
  `multipart/related` it is the root of.
  """
  @spec content_type() :: binary()
  def content_type, do: "application/rlmi+xml"

  @doc """
  An instance in the state a resource this node does not serve gets
  (RFC 4662 §5.2).

  A list routinely names buddies on domains this node knows nothing about — a
  federated deployment is the normal case, not the exception — and this is what
  the watcher is told about them until an outbound leg exists to ask their own
  server.
  """
  @spec unserved(binary()) :: Instance.t()
  def unserved(uri),
    do: %Instance{id: instance_id(uri), state: :terminated, reason: "noresource"}

  @doc """
  A stable instance id for a resource, derived from its URI.

  Derived rather than drawn at random because §5.2 requires it to survive across
  NOTIFYs: a watcher matches the instance it already holds by this id, and a fresh
  one on every push makes the buddy appear twice.
  """
  @spec instance_id(binary()) :: binary()
  def instance_id(uri),
    do: :crypto.hash(:sha, to_string(uri)) |> Base.encode16(case: :lower) |> binary_part(0, 16)

  @doc """
  Write the manifest out as `application/rlmi+xml`.

  The list `uri` is mandatory (§5.1): it is what tells the watcher which of its
  subscriptions this NOTIFY answers.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{uri: nil}), do: {:error, :no_list_uri}

  def serialize(%__MODULE__{} = list) do
    body = [
      ~s(<?xml version="1.0" encoding="UTF-8"?>\n),
      "<list xmlns=\"",
      @ns,
      "\" uri=\"",
      escape(list.uri),
      "\" version=\"",
      to_string(list.version),
      "\" fullState=\"",
      to_string(!!list.full_state),
      "\">\n",
      write_element("  ", "name", list.name),
      Enum.map(list.resources, &write_resource/1),
      "</list>\n"
    ]

    {:ok, IO.iodata_to_binary(body)}
  end

  def serialize(other), do: {:error, {:not_an_rlmi_document, other}}

  @doc """
  Read an RLMI body back into a `%SIP.Presence.Rlmi{}`.

  Here for the tests and for the watcher half; the notifier only writes. Same
  safety rules as every other document read off the network
  (`SIP.Presence.Pidf`): a size bound, a doctype refused, `:erlsom`.
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, term()}
  def parse(body) when is_binary(body) do
    with :ok <- check_size(body),
         :ok <- check_no_doctype(body),
         {:ok, root} <- scan(body) do
      read_root(root)
    end
  end

  def parse(other), do: {:error, {:not_a_body, other}}

  # ── writing ─────────────────────────────────────────────────────────────────

  defp write_resource(%Resource{} = resource) do
    [
      "  <resource uri=\"",
      escape(resource.uri),
      "\">\n",
      write_element("    ", "name", resource.name),
      Enum.map(resource.instances, &write_instance/1),
      "  </resource>\n"
    ]
  end

  defp write_instance(%Instance{} = instance) do
    [
      "    <instance id=\"",
      escape(instance.id),
      "\" state=\"",
      to_string(instance.state),
      "\"",
      write_attribute("cid", instance.cid),
      write_attribute("reason", instance.reason),
      "/>\n"
    ]
  end

  defp write_attribute(_name, nil), do: []
  defp write_attribute(name, value), do: [" ", name, "=\"", escape(value), "\""]

  defp write_element(_indent, _name, nil), do: []

  defp write_element(indent, name, value),
    do: [indent, "<", name, ">", escape(value), "</", name, ">\n"]

  defp escape(value) do
    value
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end

  # ── reading ─────────────────────────────────────────────────────────────────

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

  defp read_root({name, attrs, children}) do
    case split_name(name) do
      {ns, "list"} when ns in [@ns, ""] ->
        {:ok, read_list(attrs, children)}

      {_ns, other} ->
        {:error, {:not_an_rlmi_document, other}}
    end
  end

  defp read_list(attrs, children) do
    list = %__MODULE__{
      uri: attribute(attrs, "uri"),
      version: parse_version(attribute(attrs, "version")),
      # §5.1 makes fullState mandatory; a document without it is read as partial,
      # which is the reading that cannot invent state the sender did not send.
      full_state: attribute(attrs, "fullState") == "true"
    }

    Enum.reduce(children, list, fn child, acc ->
      case element(child) do
        {ns, "resource", child_attrs, grandchildren} when ns in [@ns, ""] ->
          %{acc | resources: acc.resources ++ [read_resource(child_attrs, grandchildren)]}

        {ns, "name", _attrs, grandchildren} when ns in [@ns, ""] ->
          %{acc | name: acc.name || text_of(grandchildren)}

        _other ->
          acc
      end
    end)
  end

  defp read_resource(attrs, children) do
    resource = %Resource{uri: attribute(attrs, "uri")}

    Enum.reduce(children, resource, fn child, acc ->
      case element(child) do
        {ns, "instance", child_attrs, _grandchildren} when ns in [@ns, ""] ->
          %{acc | instances: acc.instances ++ [read_instance(child_attrs)]}

        {ns, "name", _attrs, grandchildren} when ns in [@ns, ""] ->
          %{acc | name: acc.name || text_of(grandchildren)}

        _other ->
          acc
      end
    end)
  end

  defp read_instance(attrs) do
    %Instance{
      id: attribute(attrs, "id"),
      state: instance_state(attribute(attrs, "state")),
      cid: attribute(attrs, "cid"),
      reason: attribute(attrs, "reason")
    }
  end

  defp instance_state("active"), do: :active
  defp instance_state("pending"), do: :pending
  defp instance_state("terminated"), do: :terminated
  # Anything else, the absent attribute included: a state we cannot act on is not
  # a state we invent. `terminated` is what carries no document.
  defp instance_state(_other), do: :terminated

  defp parse_version(nil), do: 0

  defp parse_version(value) do
    case Integer.parse(value) do
      {version, _rest} when version >= 0 -> version
      _ -> 0
    end
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

  defp text_of(children) do
    case children |> Enum.filter(&is_binary/1) |> Enum.join() |> String.trim() do
      "" -> nil
      text -> text
    end
  end
end
