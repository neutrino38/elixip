# The dialog-info format (RFC 4235 §4): the wire format of a dialog-info
# document, read into and written back out of SIP.DialogInfo.Doc.

defmodule SIP.DialogInfo.Xml do
  @moduledoc """
  `application/dialog-info+xml` in both directions.

  The same three doors as `SIP.Presence.Pidf`, and for the same reason — the
  body is untrusted: a bound on its size, a `<!DOCTYPE` refused in the prolog,
  and `:erlsom` underneath, which resolves nothing external.

  ## What it reads

  Tolerantly: an element or a namespace nobody here models — `<replaces>`,
  `<referred-by>`, `<route-set>`, a vendor's extension — is skipped rather than
  fatal, the namespace may be absent altogether, and a `duration` or a `code`
  that is not a number simply does not produce one. A parser that raises on an
  odd document is a NOTIFY that kills the scenario reading it.

  ## What it writes

  `serialize/1` emits the document whole: `version`, `state`, `entity`, and one
  `<dialog>` per entry with its `<state>`, `<duration>`, `<local>` and
  `<remote>`. The round trip promised is that `parse(serialize(doc))` is `doc`,
  not that the bytes match.
  """

  alias SIP.DialogInfo.Dialog
  alias SIP.DialogInfo.Doc
  alias SIP.DialogInfo.Party

  @max_body_size 64 * 1024

  @ns "urn:ietf:params:xml:ns:dialog-info"

  @states %{
    "trying" => :trying,
    "proceeding" => :proceeding,
    "early" => :early,
    "confirmed" => :confirmed,
    "terminated" => :terminated
  }

  # RFC 4235 §4.1.4's events, as atoms. Anything outside this list is carried
  # through as the string it arrived as — see the note on atoms in
  # SIP.DialogInfo.Dialog.
  @events %{
    "cancelled" => :cancelled,
    "rejected" => :rejected,
    "replaced" => :replaced,
    "local-bye" => :local_bye,
    "remote-bye" => :remote_bye,
    "error" => :error,
    "timeout" => :timeout
  }

  @event_names Map.new(@events, fn {name, atom} -> {atom, name} end)

  # ── Parsing ─────────────────────────────────────────────────────────────────

  @doc """
  Read a dialog-info body into a `%SIP.DialogInfo.Doc{}`.

  Refuses, without raising, a body over the size bound, one carrying a doctype,
  one that is not well-formed XML, and one whose root element is not
  `<dialog-info>`.
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
      {ns, "dialog-info"} when ns in [@ns, ""] ->
        {:ok, read_document(attrs, children)}

      {_ns, other} ->
        {:error, {:not_a_dialog_info_document, other}}
    end
  end

  defp read_document(attrs, children) do
    doc = %Doc{
      entity: attribute(attrs, "entity"),
      version: read_integer(attribute(attrs, "version")) || 0,
      state: read_document_state(attribute(attrs, "state"))
    }

    Enum.reduce(children, doc, fn child, doc ->
      case element(child) do
        {ns, "dialog", child_attrs, grandchildren} when ns in [@ns, ""] ->
          %{doc | dialogs: doc.dialogs ++ [read_dialog(child_attrs, grandchildren)]}

        _unknown ->
          doc
      end
    end)
  end

  # `partial` is the only other value the schema allows; anything else is read
  # as the safe one, a document that replaces what the watcher holds.
  defp read_document_state(value) do
    case value && String.downcase(value) do
      "partial" -> :partial
      _full -> :full
    end
  end

  defp read_dialog(attrs, children) do
    dialog = %Dialog{
      id: attribute(attrs, "id"),
      call_id: attribute(attrs, "call-id"),
      local_tag: attribute(attrs, "local-tag"),
      remote_tag: attribute(attrs, "remote-tag"),
      direction: read_direction(attribute(attrs, "direction"))
    }

    Enum.reduce(children, dialog, fn child, dialog ->
      case element(child) do
        {ns, "state", state_attrs, grandchildren} when ns in [@ns, ""] ->
          %{
            dialog
            | state: read_state(text_of(grandchildren)),
              event: read_event(attribute(state_attrs, "event")),
              code: read_integer(attribute(state_attrs, "code"))
          }

        {ns, "duration", _attrs, grandchildren} when ns in [@ns, ""] ->
          %{dialog | duration: read_integer(text_of(grandchildren))}

        {ns, "local", _attrs, grandchildren} when ns in [@ns, ""] ->
          %{dialog | local: read_party(grandchildren)}

        {ns, "remote", _attrs, grandchildren} when ns in [@ns, ""] ->
          %{dialog | remote: read_party(grandchildren)}

        _unknown ->
          dialog
      end
    end)
  end

  defp read_direction(value) do
    case value && String.downcase(value) do
      "initiator" -> :initiator
      "recipient" -> :recipient
      _unknown -> nil
    end
  end

  # A state nobody has heard of is carried as it arrived: a watcher that
  # displays it as text loses nothing, and one that matches on the five atoms
  # sees "not one of them", which is the truth.
  defp read_state(nil), do: :trying

  defp read_state(value) do
    name = String.downcase(value)
    Map.get(@states, name, name)
  end

  defp read_event(nil), do: nil

  defp read_event(value) do
    name = String.downcase(value)
    Map.get(@events, name, name)
  end

  defp read_party(children) do
    Enum.reduce(children, %Party{}, fn child, party ->
      case element(child) do
        {ns, "identity", identity_attrs, grandchildren} when ns in [@ns, ""] ->
          %{
            party
            | identity: text_of(grandchildren),
              display: attribute(identity_attrs, "display")
          }

        {ns, "target", target_attrs, _grandchildren} when ns in [@ns, ""] ->
          %{party | target: attribute(target_attrs, "uri")}

        _unknown ->
          party
      end
    end)
  end

  defp read_integer(nil), do: nil

  defp read_integer(value) do
    case value |> to_string() |> String.trim() |> Integer.parse() do
      {integer, ""} -> integer
      _not_a_number -> nil
    end
  end

  # ── Serializing ─────────────────────────────────────────────────────────────

  @doc """
  Write a `%SIP.DialogInfo.Doc{}` out as `application/dialog-info+xml`.

  The `entity` is mandatory (RFC 4235 §4.1.1): a document that does not say
  whose dialogs it lists is refused here rather than sent as a body a watcher
  will discard. A dialog without an `id` gets its Call-ID, which is unique
  among the dialogs of one entity for as long as the document is.
  """
  @spec serialize(Doc.t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%Doc{entity: nil}), do: {:error, :no_entity}

  def serialize(%Doc{} = doc) do
    body = [
      ~s(<?xml version="1.0" encoding="UTF-8"?>\n),
      "<dialog-info xmlns=\"",
      @ns,
      "\" version=\"",
      Integer.to_string(doc.version),
      "\" state=\"",
      to_string(doc.state),
      "\" entity=\"",
      escape(doc.entity),
      "\">\n",
      doc.dialogs |> Enum.with_index(1) |> Enum.map(&write_dialog/1),
      "</dialog-info>\n"
    ]

    {:ok, IO.iodata_to_binary(body)}
  end

  def serialize(other), do: {:error, {:not_a_dialog_info_document, other}}

  defp write_dialog({%Dialog{} = dialog, index}) do
    [
      "  <dialog id=\"",
      escape(dialog.id || dialog.call_id || "d#{index}"),
      "\"",
      write_attribute("call-id", dialog.call_id),
      write_attribute("local-tag", dialog.local_tag),
      write_attribute("remote-tag", dialog.remote_tag),
      write_attribute("direction", dialog.direction),
      ">\n",
      "    <state",
      write_attribute("event", event_name(dialog.event)),
      write_attribute("code", dialog.code),
      ">",
      to_string(dialog.state),
      "</state>\n",
      write_duration(dialog.duration),
      write_party("local", dialog.local),
      write_party("remote", dialog.remote),
      "  </dialog>\n"
    ]
  end

  defp write_attribute(_name, nil), do: []
  defp write_attribute(name, value), do: [" ", name, "=\"", escape(value), "\""]

  defp event_name(nil), do: nil

  defp event_name(event) when is_atom(event),
    do: Map.get(@event_names, event, Atom.to_string(event))

  defp event_name(event) when is_binary(event), do: event

  defp write_duration(nil), do: []

  defp write_duration(seconds),
    do: ["    <duration>", Integer.to_string(seconds), "</duration>\n"]

  defp write_party(_name, nil), do: []

  defp write_party(name, %Party{} = party) do
    [
      "    <",
      name,
      ">\n",
      write_identity(party),
      write_target(party),
      "    </",
      name,
      ">\n"
    ]
  end

  defp write_identity(%Party{identity: nil}), do: []

  defp write_identity(%Party{identity: identity, display: display}),
    do: [
      "      <identity",
      write_attribute("display", display),
      ">",
      escape(identity),
      "</identity>\n"
    ]

  defp write_target(%Party{target: nil}), do: []

  defp write_target(%Party{target: target}),
    do: ["      <target uri=\"", escape(target), "\"/>\n"]

  defp escape(value) do
    value
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end

  # ── The shape erlsom hands back ─────────────────────────────────────────────

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
