# The `dialog` event package (RFC 4235) over dialog-info.
# The behaviour it implements is SIPEventPackage.ex; the document is
# SIP.DialogInfo.Doc and its wire format SIP.DialogInfo.Xml.

defmodule SIP.EventPackage.Dialog do
  @moduledoc """
  `Event: dialog` — the package a BLF key subscribes through, and the one the
  `dialog_state` module reports call occupancy on
  (docs/design/dialog-state-plan.md).

  Same bounds as `SIP.EventPackage.Presence`, for the same reasons: RFC 4235
  §3.4 keeps RFC 3856's default of 3600 s, and a desk phone refreshing its BLF
  keys is the same load as one refreshing its buddies.

  Nothing PUBLISHes this package: the notifier learns the state from the
  dialogs that cross the node, not from the UA. A domain serving `dialog`
  answers a PUBLISH **405**, which `Kelix.Domain` already says.
  """

  @behaviour SIP.EventPackage

  alias SIP.DialogInfo.Doc
  alias SIP.DialogInfo.Xml

  @content_type "application/dialog-info+xml"

  @impl true
  def name, do: "dialog"

  @impl true
  def default_expires, do: 3600

  @impl true
  def min_expires, do: 60

  @impl true
  def max_expires, do: 86_400

  @impl true
  def content_types, do: [@content_type]

  @impl true
  def parse(content_type, body) when is_binary(body) do
    case String.downcase(content_type) do
      @content_type -> Xml.parse(body)
      other -> {:error, {:unsupported_content_type, other}}
    end
  end

  def parse(_content_type, body), do: {:error, {:not_a_body, body}}

  @impl true
  def serialize(content_type, %Doc{} = doc) do
    case String.downcase(content_type) do
      @content_type -> Xml.serialize(doc)
      other -> {:error, {:unsupported_content_type, other}}
    end
  end

  def serialize(_content_type, other), do: {:error, {:not_a_dialog_info_document, other}}
end
