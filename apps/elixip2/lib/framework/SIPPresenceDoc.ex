# The presence document, as RFC 3863 models it and as a scenario reads it.
# The wire format is SIPPresencePidf.ex; this file is the model both directions
# agree on.

defmodule SIP.Presence.Tuple do
  @moduledoc """
  One `<tuple>` of a presence document: **one** way of reaching the presentity,
  with a reachability verdict of its own (RFC 3863 §4.1).

  A presentity with a handset and a softphone publishes two tuples, each with its
  own `contact` and its own `status`; "is Bob reachable" is then the disjunction,
  which is what `SIP.Presence.Doc.status/1` answers. A model with one status per
  document could not say which of the two devices is the open one.

  `status` is RFC 3863's `<basic>`, and it has exactly two values — `:open` and
  `:closed`. Everything richer (what Bob is *doing*, where, on which device) is
  RPID's, and lands on the person rather than on the tuple.
  """

  @type status :: :open | :closed

  @type t :: %__MODULE__{
          id: binary() | nil,
          status: status(),
          contact: binary() | nil,
          priority: float() | nil,
          note: binary() | nil,
          timestamp: DateTime.t() | nil
        }

  defstruct id: nil,
            status: :closed,
            contact: nil,
            priority: nil,
            note: nil,
            timestamp: nil
end

defmodule SIP.Presence.Doc do
  @moduledoc """
  A presence document: who it is about (`entity`), how they can be reached
  (`tuples`), and what they are doing (`activity`, `note`).

  The three fields on the document itself are RPID's person facet (RFC 4480):
  a real client publishes `<dm:person><rpid:activities><rpid:away/>` beside its
  tuples, and a watcher displays *that* — the tuple's `open`/`closed` says only
  whether a message would arrive. They are kept where PIDF puts them rather than
  folded into each tuple: a presentity has one activity and N devices.

  `activity` is an **atom for the values RFC 4480 names** (`:away`, `:busy`,
  `:meeting`, `:on_the_phone`, …) and the raw **string** for anything else. A
  document comes off the network, so nothing here calls `String.to_atom/1`: an
  activity nobody has heard of is carried through as it arrived, and an unbounded
  atom table is not created from unauthenticated traffic.

  ## Building one

      iex> SIP.Presence.Doc.new("sip:bob@ives.fr", :open, contact: "sip:bob@10.0.0.4")
      %SIP.Presence.Doc{entity: "sip:bob@ives.fr", activity: nil, note: nil,
        tuples: [%SIP.Presence.Tuple{id: "t1", status: :open,
                                     contact: "sip:bob@10.0.0.4"}]}

  `new/3` is what a scenario calls — one line producing the document the common
  case needs. A presentity with several devices builds the `tuples` list itself.
  """

  alias SIP.Presence.Tuple

  @type activity :: atom() | binary() | nil

  @type t :: %__MODULE__{
          entity: binary() | nil,
          tuples: [Tuple.t()],
          activity: activity(),
          note: binary() | nil
        }

  defstruct entity: nil,
            tuples: [],
            activity: nil,
            note: nil

  @doc """
  A document stating one reachability for `entity`.

  Options: `:contact`, `:note`, `:activity`, `:priority`, `:timestamp`, and `:id`
  for the tuple's identifier — which defaults to `"t1"`, since a document with a
  single tuple has no use for a name of its own but PIDF makes it mandatory.

  `:note` lands on the tuple **and** on the person: PIDF allows a `<note>` in
  both places and clients differ over which one they display.
  """
  @spec new(binary(), Tuple.status(), keyword()) :: t()
  def new(entity, status \\ :open, opts \\ [])
      when is_binary(entity) and status in [:open, :closed] do
    %__MODULE__{
      entity: entity,
      activity: Keyword.get(opts, :activity),
      note: Keyword.get(opts, :note),
      tuples: [
        %Tuple{
          id: Keyword.get(opts, :id, "t1"),
          status: status,
          contact: Keyword.get(opts, :contact),
          priority: Keyword.get(opts, :priority),
          note: Keyword.get(opts, :note),
          timestamp: Keyword.get(opts, :timestamp)
        }
      ]
    }
  end

  @doc """
  The composite document of a presentity: the tuples of **every** live
  publication, under **one** person state.

  `person` is the person state the collection holds for the presentity — a
  document whose `entity`, `activity` and `note` are used and whose tuples are
  not. `publications` are the documents of the live publications, each with a
  stable key of its own, in the order their state changed.

      iex> person = %SIP.Presence.Doc{entity: "sip:bob@ives.fr", activity: :away}
      iex> desk = SIP.Presence.Doc.new("sip:bob@ives.fr", :closed)
      iex> mobile = SIP.Presence.Doc.new("sip:bob@ives.fr", :open, activity: :busy)
      iex> doc = SIP.Presence.Doc.compose(person, [{"desk", desk}, {"mobile", mobile}])
      iex> {SIP.Presence.Doc.status(doc), doc.activity, Enum.map(doc.tuples, & &1.id)}
      {:open, :away, ["t-desk-1", "t-mobile-1"]}

  The two levels compose differently (RFC 4479): reachability is per device, so
  the tuples are the union and `status/1` folds them; what the user is doing is
  one state, so the person facet each publication carries is ignored here — which
  publication sets the held state, and which clears it, is the collection's rule.

  A tuple's id is rebuilt from the publication's key and the tuple's position in
  it, `t-<key>-<n>`. The publisher's own ids cannot be kept: two devices both
  writing `t1` would collide in one document, and Linphone mints a new id on
  every PUBLISH, so a watcher would redraw a device that did not change. The `t-`
  prefix keeps the id an XML `NCName` whatever the key starts with.
  """
  @spec compose(t(), [{binary(), t()}]) :: t()
  def compose(%__MODULE__{} = person, publications) when is_list(publications) do
    tuples =
      for {key, %__MODULE__{tuples: tuples}} <- publications,
          {tuple, n} <- Enum.with_index(tuples, 1),
          do: %Tuple{tuple | id: "t-#{key}-#{n}"}

    %__MODULE__{
      entity: person.entity,
      activity: person.activity,
      note: person.note,
      tuples: tuples
    }
  end

  @doc """
  The composite reachability: `:open` as soon as **one** tuple is open.

  RFC 3863 defines no document-wide status, and a watcher that wants "is Bob
  reachable" has to fold the tuples itself. It does it here, once, rather than in
  every scenario that displays a presence state.
  """
  @spec status(t()) :: Tuple.status()
  def status(%__MODULE__{tuples: tuples}) do
    if Enum.any?(tuples, &(&1.status == :open)), do: :open, else: :closed
  end

  @doc """
  One line saying what the document states, for a log: the composite status,
  the RPID activity as the wire spells it, the note, and the device count when
  there is more than one.

      iex> SIP.Presence.Doc.new("sip:bob@ives.fr", :open, activity: :on_the_phone, note: "desk")
      ...> |> SIP.Presence.Doc.summary()
      ~s(open, on-the-phone, note "desk")
  """
  @spec summary(t()) :: binary()
  def summary(%__MODULE__{} = doc) do
    [
      to_string(status(doc)),
      activity_label(doc.activity),
      doc.note && ~s(note "#{doc.note}"),
      length(doc.tuples) > 1 && "#{length(doc.tuples)} devices"
    ]
    |> Enum.filter(&is_binary/1)
    |> Enum.join(", ")
  end

  defp activity_label(nil), do: nil

  defp activity_label(activity) when is_atom(activity),
    do: activity |> to_string() |> String.replace("_", "-")

  defp activity_label(activity), do: activity

  @doc "`status/1` as a question."
  @spec open?(t()) :: boolean()
  def open?(%__MODULE__{} = doc), do: status(doc) == :open

  @doc """
  Every contact the document offers, best first.

  The order is RFC 3863 §4.1.4's `priority`: highest first, and a tuple without
  one after every tuple that has one — an absent priority is "no preference
  expressed", never zero.
  """
  @spec contacts(t()) :: [binary()]
  def contacts(%__MODULE__{tuples: tuples}) do
    tuples
    |> Enum.filter(&(&1.status == :open and is_binary(&1.contact)))
    |> Enum.sort_by(&{&1.priority == nil, -(&1.priority || 0.0)})
    |> Enum.map(& &1.contact)
  end
end
