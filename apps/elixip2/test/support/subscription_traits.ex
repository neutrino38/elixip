defmodule SIP.Test.SubscriptionTraits do
  @moduledoc """
  What the subscription suite has to know about the event package it is run
  against, and nothing else.

  `SIP.Test.SubscriptionSuite` is one suite run twice — over
  `SIP.Test.EventPackages.Dummy`, whose document is a line of text, and over
  `SIP.EventPackage.Presence`, whose document is PIDF. Six answers are all that
  differ between the two runs, and they are this behaviour. Anything a seventh
  callback would be needed for is the subscription layer knowing about a
  particular package, which is the thing the suite exists to disprove.
  """

  @doc "The package under test."
  @callback package() :: module()

  @doc "A document this package models, stating that the presentity is reachable or not."
  @callback document(:open | :closed) :: term()

  @doc """
  Read a NOTIFY body back into that verdict.

  The suite asserts on what a watcher *understood*, never on the bytes: `"open"`
  and a PIDF document saying the same thing are the same assertion.
  """
  @callback status_of(binary()) :: :open | :closed

  @doc "A content type this package cannot produce — the **406**."
  @callback bad_accept() :: binary()

  @doc "A lifetime it accepts."
  @callback expires() :: pos_integer()

  @doc "One below its minimum — the **423**."
  @callback too_brief() :: pos_integer()
end

defmodule SIP.Test.SubscriptionTraits.Dummy do
  @moduledoc "The suite over a package whose document is a line of text."
  @behaviour SIP.Test.SubscriptionTraits

  @impl true
  def package, do: SIP.Test.EventPackages.Dummy

  @impl true
  def document(:open), do: "open"
  def document(:closed), do: "closed"

  @impl true
  def status_of("open"), do: :open
  def status_of(_other), do: :closed

  @impl true
  def bad_accept, do: "application/pidf+xml"

  @impl true
  def expires, do: 60

  @impl true
  def too_brief, do: 5
end

defmodule SIP.Test.SubscriptionTraits.Presence do
  @moduledoc """
  The same suite over the real thing: `Event: presence`, `application/pidf+xml`,
  and a `%SIP.Presence.Doc{}` where the dummy had a string.

  Nothing else about the run changes, which is the whole claim of P4.
  """
  @behaviour SIP.Test.SubscriptionTraits

  alias SIP.Presence.Doc
  alias SIP.Presence.Pidf

  @entity "sip:bob@unit.test"

  @impl true
  def package, do: SIP.EventPackage.Presence

  @impl true
  def document(:open), do: Doc.new(@entity, :open, contact: "sip:bob@10.0.0.4")
  def document(:closed), do: Doc.new(@entity, :closed)

  @impl true
  def status_of(body) do
    case Pidf.parse(body) do
      {:ok, doc} -> Doc.status(doc)
      {:error, _reason} -> :closed
    end
  end

  @impl true
  def bad_accept, do: "text/plain"

  # Over the package's minimum of 60, and short enough that a suite waiting on an
  # expiry is not waiting on this one.
  @impl true
  def expires, do: 120

  @impl true
  def too_brief, do: 30
end
