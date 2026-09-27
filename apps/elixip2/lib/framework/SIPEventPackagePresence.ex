# The `presence` event package (RFC 3856) over PIDF (RFC 3863).
# The behaviour it implements is SIPEventPackage.ex; the document is
# SIP.Presence.Doc and its wire format SIP.Presence.Pidf.

defmodule SIP.EventPackage.Presence do
  @moduledoc """
  `Event: presence` — the package the subscription layer serves a watcher
  through.

  It answers about names, bounds and bodies, and nothing else: it never reads a
  SIP message, which is what lets the same layer carry `dialog` or a proprietary
  package tomorrow without a line of it knowing about PIDF.

  ## The bounds

  | | | |
  |---|---|---|
  | `default_expires` | 3600 s | RFC 3856 §6.4, and it is the package's number, not the framework's |
  | `min_expires` | 60 s | below this a watcher refreshing is a load generator; **423** says so, with the minimum, so it can ask again |
  | `max_expires` | 86400 s | granted instead of refused: RFC 6665 §4.2.1 has the notifier shorten a lifetime it finds too long, never reject it |

  A notifier grants less whenever it wants to — `accept_subscription(expires: n)`
  is a ceiling applied on top of these — so a node with a policy of its own does
  not need a package of its own.
  """

  @behaviour SIP.EventPackage

  alias SIP.Presence.Doc
  alias SIP.Presence.Pidf

  @content_type "application/pidf+xml"

  @impl true
  def name, do: "presence"

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
      @content_type -> Pidf.parse(body)
      other -> {:error, {:unsupported_content_type, other}}
    end
  end

  def parse(_content_type, body), do: {:error, {:not_a_body, body}}

  @impl true
  def serialize(content_type, %Doc{} = doc) do
    case String.downcase(content_type) do
      @content_type -> Pidf.serialize(doc)
      other -> {:error, {:unsupported_content_type, other}}
    end
  end

  # A binary is NOT passed through: a package whose document is XML and which
  # accepts any string as a body cannot refuse anything, and the scenario handing
  # it a note instead of a document would find out from the watcher.
  def serialize(_content_type, other), do: {:error, {:not_a_presence_document, other}}
end
