# PIDF (RFC 3863) and the RPID extensions (RFC 4480): the wire format of a
# presence document, read into and written back out of SIP.Presence.Doc.

defmodule SIP.Presence.Pidf do
  @moduledoc """
  `application/pidf+xml` in both directions.

  ## The parser is erlsom, and the body is untrusted

  The document arrives from the network, so the risk is not the XML — it is
  entity expansion. Three things answer it here, and they are the reason this
  module does not simply hand the body to a parser:

  1. **a bound on the body** (#{div(64 * 1024, 1024)} kB). A presence document is
     a few hundred bytes; anything past this is not one, and refusing it early
     costs nothing;
  2. **a `<!DOCTYPE` in the prolog is refused outright**. A PIDF document has no
     use for a DTD, and every entity attack needs one. Refusing the declaration
     is a stronger statement than bounding what it may expand to;
  3. **`:erlsom`** — already in the tree, pulled by `:xmlrpc`, which uses it to
     parse untrusted input for the same reason. It resolves nothing external: no
     file is opened and no URL fetched for a `SYSTEM` identifier, whatever the
     document says. Its own limits on entity nesting and expanded size
     (`max_entity_depth`, `max_expanded_entity_size`) apply underneath, so the
     refusal above is the outer of two doors rather than the only one.

  ## What it reads

  Tolerantly, the way every other reading of an inbound message is
  ([CLAUDE.md](../../CLAUDE.md), *Message Layer*): an element in a namespace
  nobody here knows is skipped rather than fatal, the namespace may be absent
  altogether, `<basic>` is matched case-insensitively, and a `timestamp` that is
  not a date simply does not produce one. What a real client sends is what
  decides — a document that loses a field is a watcher displaying nothing; a
  parser that raises is a NOTIFY that kills the scenario reading it.

  ## What it writes

  `serialize/1` emits a full document, always — v1 has no partial state — with
  the `dm`/`rpid` prefixes declared only when a person facet is actually there.
  It is **not** byte-identical to what was parsed: the round trip this module
  promises is that `parse(serialize(doc))` is `doc`, not that the bytes match. A
  document's own notion of equality is its meaning, and holding on to the
  incoming bytes to re-emit them is how a "cache" of a document nobody re-reads
  starts.
  """

  alias SIP.Presence.Doc
  alias SIP.Presence.Tuple

  require Logger

  @max_body_size 64 * 1024

  @pidf "urn:ietf:params:xml:ns:pidf"
  @dm "urn:ietf:params:xml:ns:pidf:data-model"
  @rpid "urn:ietf:params:xml:ns:pidf:rpid"

  # RFC 4480 §3.1's activities, as atoms. Anything outside this list is carried
  # through as the string it arrived as — see the note on atoms in SIP.Presence.Doc.
  @activities %{
    "appointment" => :appointment,
    "away" => :away,
    "breakfast" => :breakfast,
    "busy" => :busy,
    "dinner" => :dinner,
    "holiday" => :holiday,
    "in-transit" => :in_transit,
    "looking-for-work" => :looking_for_work,
    "lunch" => :lunch,
    "meal" => :meal,
    "meeting" => :meeting,
    "on-the-phone" => :on_the_phone,
    "other" => :other,
    "performance" => :performance,
    "permanent-absence" => :permanent_absence,
    "playing" => :playing,
    "presentation" => :presentation,
    "quiet" => :quiet,
    "reading" => :reading,
    "sleeping" => :sleeping,
    "spectator" => :spectator,
    "steering" => :steering,
    "travel" => :travel,
    "tv" => :tv,
    "unknown" => :unknown,
    "vacation" => :vacation,
    "working" => :working,
    "worship" => :worship
  }

  @activity_names Map.new(@activities, fn {name, atom} -> {atom, name} end)

  # The marks a person may carry (SIP.Presence.Doc, `marks`). A client sends one
  # or two; the bound is what keeps a stranger's document from growing the
  # person state every watcher is sent.
  @max_marks 8

  # ── Parsing ─────────────────────────────────────────────────────────────────

  @doc """
  Read a PIDF body into a `%SIP.Presence.Doc{}`.

  Refuses, without raising, a body over the size bound, one carrying a doctype,
  one that is not well-formed XML, and one whose root element is not
  `<presence>`.
  """
  @spec parse(binary()) :: {:ok, Doc.t()} | {:error, term()}
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

  # A doctype can only appear before the root element, so only the prolog is
  # looked at — a `<!DOCTYPE` inside a CDATA section is text, not a declaration,
  # and refusing a document over it would be refusing a `<note>`.
  defp check_no_doctype(body) do
    prolog = body |> String.split(~r/<[A-Za-z_]/, parts: 2) |> hd()

    if prolog =~ ~r/<!DOCTYPE/i do
      {:error, :doctype_not_allowed}
    else
      :ok
    end
  end

  # erlsom signals a malformed document by throwing or exiting, never by
  # answering: a NOTIFY carrying junk must not kill the scenario reading it.
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
      {ns, "presence"} when ns in [@pidf, ""] ->
        {:ok, read_presence(attrs, children)}

      {_ns, other} ->
        {:error, {:not_a_presence_document, other}}
    end
  end

  defp read_presence(attrs, children) do
    Enum.reduce(children, %Doc{entity: attribute(attrs, "entity")}, fn child, doc ->
      case element(child) do
        {ns, "tuple", child_attrs, grandchildren} when ns in [@pidf, ""] ->
          %{doc | tuples: doc.tuples ++ [read_tuple(child_attrs, grandchildren)]}

        {ns, "note", _attrs, grandchildren} when ns in [@pidf, ""] ->
          %{doc | note: doc.note || text_of(grandchildren)}

        {ns, "person", _attrs, grandchildren} when ns in [@dm, ""] ->
          read_person(doc, grandchildren)

        # An extension nobody here models — a `<dm:device>`, a namespace of the
        # vendor's own. The rest of the document is still perfectly readable.
        _unknown ->
          doc
      end
    end)
  end

  defp read_tuple(attrs, children) do
    Enum.reduce(children, %Tuple{id: attribute(attrs, "id")}, fn child, tuple ->
      case element(child) do
        {ns, "status", _attrs, grandchildren} when ns in [@pidf, ""] ->
          %{tuple | status: read_status(grandchildren)}

        {ns, "contact", contact_attrs, grandchildren} when ns in [@pidf, ""] ->
          %{
            tuple
            | contact: text_of(grandchildren),
              priority: read_priority(attribute(contact_attrs, "priority"))
          }

        {ns, "note", _attrs, grandchildren} when ns in [@pidf, ""] ->
          %{tuple | note: tuple.note || text_of(grandchildren)}

        {ns, "timestamp", _attrs, grandchildren} when ns in [@pidf, ""] ->
          %{tuple | timestamp: read_timestamp(text_of(grandchildren))}

        _unknown ->
          tuple
      end
    end)
  end

  defp read_person(doc, children) do
    Enum.reduce(children, doc, fn child, doc ->
      case element(child) do
        {ns, "activities", _attrs, grandchildren} when ns in [@rpid, ""] ->
          if is_nil(doc.activity) and doc.marks == [] do
            %{doc | activity: read_activity(grandchildren), marks: read_marks(grandchildren)}
          else
            doc
          end

        {ns, "note", _attrs, grandchildren} when ns in [@dm, @rpid, @pidf, ""] ->
          %{doc | note: doc.note || text_of(grandchildren)}

        _unknown ->
          doc
      end
    end)
  end

  # `<basic>` is the only status v1 reads, and it has two values. Anything else —
  # an empty element, an extension status, a typo — is "not reachable", which is
  # the safe reading of a status nobody can make sense of.
  defp read_status(children) do
    Enum.find_value(children, :closed, fn child ->
      case element(child) do
        {ns, "basic", _attrs, grandchildren} when ns in [@pidf, ""] ->
          case grandchildren |> text_of() |> to_string() |> String.trim() |> String.downcase() do
            "open" -> :open
            _closed -> :closed
          end

        _other ->
          nil
      end
    end)
  end

  # The first RPID activity element that is not RPID's own `<note>`: v1 carries
  # one activity, and a client publishing two has already said the first. An
  # element of another namespace is not an activity but a mark (`read_marks/1`):
  # read as one, `<trix:dnd/>` would come back out as `<rpid:dnd/>`.
  defp read_activity(children) do
    Enum.find_value(children, fn child ->
      case element(child) do
        {@rpid, "note", _attrs, _grandchildren} ->
          nil

        {ns, name, _attrs, _grandchildren} when ns in [@rpid, ""] ->
          Map.get(@activities, name, name)

        _other ->
          nil
      end
    end)
  end

  defp read_marks(children) do
    children
    |> Enum.flat_map(fn child ->
      case element(child) do
        {ns, name, _attrs, _grandchildren} when ns not in [@rpid, ""] -> [{ns, name}]
        _other -> []
      end
    end)
    |> Enum.uniq()
    |> Enum.take(@max_marks)
  end

  defp read_priority(nil), do: nil

  defp read_priority(value) do
    case Float.parse(to_string(value)) do
      {priority, _rest} -> priority
      :error -> nil
    end
  end

  defp read_timestamp(nil), do: nil

  defp read_timestamp(value) do
    case value |> to_string() |> String.trim() |> DateTime.from_iso8601() do
      {:ok, datetime, _offset} -> datetime
      {:error, _reason} -> nil
    end
  end

  # ── Serializing ─────────────────────────────────────────────────────────────

  @doc """
  Write a `%SIP.Presence.Doc{}` out as `application/pidf+xml`.

  The `entity` is mandatory (RFC 3863 §4.1): a document that does not say who it
  is about cannot be published or notified, so it is refused here rather than
  sent as a body a watcher will discard.
  """
  @spec serialize(Doc.t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%Doc{entity: nil}), do: {:error, :no_entity}

  def serialize(%Doc{} = doc) do
    body = [
      ~s(<?xml version="1.0" encoding="UTF-8"?>\n),
      "<presence xmlns=\"",
      @pidf,
      "\"",
      person_namespaces(doc),
      " entity=\"",
      escape(doc.entity),
      "\">\n",
      doc.tuples |> Enum.with_index(1) |> Enum.map(&write_tuple/1),
      write_person(doc),
      "</presence>\n"
    ]

    {:ok, IO.iodata_to_binary(body)}
  end

  def serialize(other), do: {:error, {:not_a_presence_document, other}}

  defp person_namespaces(doc) do
    if has_person?(doc) do
      [
        " xmlns:dm=\"",
        @dm,
        "\" xmlns:rpid=\"",
        @rpid,
        "\"",
        for({ns, prefix} <- mark_prefixes(doc), do: [" xmlns:", prefix, "=\"", escape(ns), "\""])
      ]
    else
      []
    end
  end

  defp has_person?(%Doc{activity: activity, marks: marks, note: note}),
    do: not is_nil(activity) or marks != [] or not is_nil(note)

  # One prefix per namespace the marks use, `m1`, `m2`… in order of first use:
  # the client's own prefix is not kept, and a watcher matches on the namespace.
  defp mark_prefixes(%Doc{marks: marks}) do
    marks
    |> Enum.map(&elem(&1, 0))
    |> Enum.uniq()
    |> Enum.with_index(1)
    |> Map.new(fn {ns, n} -> {ns, "m#{n}"} end)
  end

  defp write_tuple({%Tuple{} = tuple, index}) do
    [
      "  <tuple id=\"",
      escape(tuple.id || "t#{index}"),
      "\">\n",
      "    <status><basic>",
      to_string(tuple.status),
      "</basic></status>\n",
      write_contact(tuple),
      write_element("    ", "note", tuple.note),
      write_timestamp(tuple.timestamp),
      "  </tuple>\n"
    ]
  end

  defp write_contact(%Tuple{contact: nil}), do: []

  defp write_contact(%Tuple{contact: contact, priority: nil}),
    do: ["    <contact>", escape(contact), "</contact>\n"]

  defp write_contact(%Tuple{contact: contact, priority: priority}),
    do: [
      "    <contact priority=\"",
      :erlang.float_to_binary(priority * 1.0, decimals: 2),
      "\">",
      escape(contact),
      "</contact>\n"
    ]

  defp write_timestamp(nil), do: []

  defp write_timestamp(%DateTime{} = timestamp),
    do: ["    <timestamp>", DateTime.to_iso8601(timestamp), "</timestamp>\n"]

  defp write_person(doc) do
    if has_person?(doc) do
      [
        "  <dm:person id=\"p1\">\n",
        write_activities(doc),
        write_element("    ", "dm:note", doc.note),
        "  </dm:person>\n"
      ]
    else
      []
    end
  end

  defp write_activities(%Doc{activity: nil, marks: []}), do: []

  defp write_activities(%Doc{activity: activity, marks: marks} = doc) do
    prefixes = mark_prefixes(doc)

    [
      "    <rpid:activities>",
      if(activity, do: ["<rpid:", activity_name(activity), "/>"], else: []),
      for({ns, name} <- marks, ncname?(name), do: ["<", prefixes[ns], ":", name, "/>"]),
      "</rpid:activities>\n"
    ]
  end

  # A mark read off the wire has a name the XML parser accepted; one a scenario
  # built may not, and an element name is not escaped — it is left out.
  defp ncname?(name), do: name =~ ~r/\A[A-Za-z_][A-Za-z0-9._-]*\z/

  defp activity_name(activity) when is_atom(activity),
    do: Map.get(@activity_names, activity, Atom.to_string(activity))

  defp activity_name(activity) when is_binary(activity), do: escape(activity)

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

  # ── The shape erlsom hands back ─────────────────────────────────────────────

  # `simple_form/2` answers `{Name, Attributes, Content}` with names as charlists
  # — `'{namespace}local'` when the element is in a namespace, `'local'` when it
  # is not — and text as binaries. Everything below turns that into the two
  # things this module matches on: a namespace and a local name.
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

  # The text of an element: erlsom keeps mixed content as a list, so a `<note>`
  # interrupted by a comment arrives in two pieces.
  defp text_of(children) do
    case children |> Enum.filter(&is_binary/1) |> Enum.join() |> String.trim() do
      "" -> nil
      text -> text
    end
  end
end
