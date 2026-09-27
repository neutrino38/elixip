# The publication half of presence (RFC 3903): one PUBLISH, seen from the
# transaction that carries it. See docs/design/DESIGN-PRESENCE.md, "The data
# model is kamailio's", and docs/design/presence-basic-plan.md, phase P5.
#
# Two modules, in the order they are read:
#
#   * `SIP.Publication` — what one published state IS. A kamailio `presentity`
#     row, under that row's names.
#   * `SIP.Session.Publish` — the verbs a script calls: the RFC 3903 reading and
#     its refusals, then the answer.
#
# What is NOT here, on purpose: the entity-tag lifecycle and the documents
# themselves, which are the collection's state (a kelixip module's, plan
# decision 5) — one PUBLISH is one transaction, and the instance serving it is
# gone long before the refresh arrives.

defmodule SIP.Publication do
  @moduledoc """
  One published state: a resource, an event package, a document and a lifetime.

  ## It is a kamailio row

  Every field below but the last four is a column of kamailio 6.1's `presentity`
  table, carrying that column's value under that column's name
  (docs/design/DESIGN-PRESENCE.md, *The data model is kamailio's*), for the same
  reason `%SIP.Subscription{}` is an `active_watchers` row: a struct designed
  freely today is a migration tomorrow, and the migration is what never gets
  written.

    * **`expires` and `received_time` are absolute epoch seconds**, not remaining
      lifetimes — kamailio writes `expires + time(NULL)` and reads back `expires
      - time(NULL)`, and nothing converts in between. `remaining/1` is the one
      place that subtracts.
    * **`body` is the document as it came off the wire**, bytes and all. `doc` is
      what the event package made of it, and it is not a column: a row holds what
      was published, not what this release could parse of it.
    * **`etag` is opaque and case-sensitive.** It is minted by whoever owns the
      collection (`new_etag/0` is the generator), never by the publisher, and it
      is what the next refresh presents as `SIP-If-Match`.

  ## The key

  `(username, domain, event, etag)` is `presentity`'s unique key, and it is the
  one `publish/2` looks a refresh up by. It carries the **entity-tag**, not just
  the resource: RFC 3903 §4.1 lets several publishers hold state for one
  presentity at the same time — a handset and a desk phone — each with a tag of
  its own, and `resource/1` is the coarser key the fan-out notifies on.
  """

  defstruct [
    # ── the key ──────────────────────────────────────────────────────────────
    username: nil,
    domain: nil,
    event: nil,
    etag: nil,
    # ── what was published, and until when ───────────────────────────────────
    # ABSOLUTE epoch seconds, like kamailio's columns. Never remaining lifetimes.
    expires: 0,
    received_time: 0,
    body: nil,
    sender: nil,
    # ── kamailio's own bookkeeping, filled with the schema's defaults ────────
    priority: 0,
    ruid: nil,
    # ── not columns: what the framework works with ───────────────────────────
    # What this PUBLISH asks for (`SIP.Msg.Ops.publish_operation/2`).
    operation: :initial,
    # The `SIP.EventPackage` implementation, the content type the body came in,
    # and the document that package made of it.
    package: nil,
    content_type: nil,
    doc: nil
  ]

  @type t :: %__MODULE__{}

  @typedoc "What a PUBLISH asks for (RFC 3903 §4.1)."
  @type operation :: :initial | :modify | :refresh | :remove

  @doc """
  What this publication does to the state, in one line for a log: the new state
  of an initial or modifying PUBLISH, and what a refresh or a removal means.
  """
  @spec describe(t()) :: binary()
  def describe(%__MODULE__{operation: :remove}), do: "removal"
  def describe(%__MODULE__{operation: :refresh}), do: "refresh, state unchanged"

  def describe(%__MODULE__{operation: :modify, doc: doc}),
    do: "modified: " <> SIP.EventPackage.summary(doc)

  def describe(%__MODULE__{doc: doc}), do: "new: " <> SIP.EventPackage.summary(doc)

  @doc "`presentity`'s unique key: `{username, domain, event, etag}`."
  @spec key(t()) :: {binary() | nil, binary() | nil, binary() | nil, binary() | nil}
  def key(%__MODULE__{} = pub), do: {pub.username, pub.domain, pub.event, pub.etag}

  @doc """
  The resource this state is about: `{username, domain, event}`.

  The key without the entity-tag — what a watcher subscribes to, and therefore
  what the fan-out notifies on. Two publishers of one presentity share it.
  """
  @spec resource(t()) :: {binary() | nil, binary() | nil, binary() | nil}
  def resource(%__MODULE__{} = pub), do: {pub.username, pub.domain, pub.event}

  @doc "The presentity as a URI, the way `active_watchers.presentity_uri` holds it."
  @spec presentity_uri(t()) :: binary()
  def presentity_uri(%__MODULE__{username: user, domain: domain}),
    do: "sip:" <> to_string(user) <> "@" <> to_string(domain)

  @doc """
  How many seconds this publication still has, now — `expires` being absolute.

  Never negative: a lapsed publication has 0 seconds left, which is what the 200
  to its last refresh would have said.
  """
  @spec remaining(t()) :: non_neg_integer()
  def remaining(%__MODULE__{expires: expires}), do: max(expires - now(), 0)

  @doc "Set the absolute `expires` from a lifetime in seconds."
  @spec grant(t(), non_neg_integer()) :: t()
  def grant(%__MODULE__{} = pub, seconds) when is_integer(seconds) and seconds >= 0,
    do: %{pub | expires: now() + seconds}

  @doc """
  A fresh entity-tag: opaque, unguessable and unique on this node.

  Whoever owns the collection mints one per publication and hands it back in the
  `SIP-ETag` of the 200; the publisher presents it again as `SIP-If-Match`. Its
  only contract is that it is a token (RFC 3261 §25.1) the publisher can echo
  verbatim, so it is spelt like the tags the stack already generates.
  """
  @spec new_etag() :: binary()
  def new_etag, do: SIP.Msg.Ops.generate_from_or_to_tag()

  @doc "The epoch second, the way kamailio counts it (`time(NULL)`)."
  @spec now() :: integer()
  defdelegate now(), to: SIP.Subscription
end

defmodule SIP.Session.Publish do
  @moduledoc """
  What a server scenario calls when a PUBLISH lands on it (RFC 3903).

      state publish do
        case check_publish(package: "presence") do
          {:ok, pub} ->
            case Kelix.Mod.Presence.publish(sip_ctx, pub) do
              {:ok, etag, expires} ->
                reply_publish(200, etag: etag, expires: expires)
                scenario_success("published")

              {:error, 412} ->
                reply_publish(412)
                scenario_failure("stale etag")
            end

          # the verb has already answered 400 / 415 / 423 / 489
          {:error, code} ->
            scenario_failure("publish refused \#{code}")
        end
      end

  ## What the verb decides, so the script does not

  `check_publish/0,1` reads the request against the packages this node knows and
  answers the refusal itself when it cannot be served — there is nothing for a
  script to check:

  | Read | Against | Refusal |
  |---|---|---|
  | `Event` | `SIP.EventPackage.lookup/1` | **489 Bad Event** |
  | `SIP-If-Match` and the body | each other | **400 Bad Request** when it has neither |
  | `Content-Type` | the package's `content_types/0` | **415 Unsupported Media Type**, with `Accept` |
  | the body | the package's `parse/2` | **400 Bad Request** on a document it refuses |
  | `Expires` | the package's `min_expires/0` | **423 Interval Too Brief**, with `Min-Expires` |

  Above `max_expires/0` nothing is refused: the compositor grants its maximum,
  as it does for a subscription. `Expires: 0` is not a refusal either — it is how
  a publisher removes its state (RFC 3903 §4.4), and it comes back as the
  `:remove` operation.

  Each reading goes through `SIP.Msg.Ops` (CLAUDE.md, *Message Layer*); none of
  them is re-derived here.

  ## What is left to the collection

  The **412**. A stale or unknown entity-tag can only be recognised by whoever
  holds the tags, and that is the collection (`Kelix.Mod.Presence`, P7) — not
  this instance, which is one transaction old. So `check_publish/1` hands back a
  `%SIP.Publication{}` with the tag the publisher presented, the collection says
  whether it knows it, and the script replies with what it was told.

  The same goes for the entity-tag itself: `SIP.Publication.new_etag/0` mints
  one, the collection decides when to.

  ## The dialog is the transaction

  A PUBLISH is not dialog-forming. The dialog carrying it lives as long as its
  server transaction (`SIP.Dialog.start_new_dialog_for/3`, 32 s), so a scenario
  instance serving one answers it and ends — nothing waits there for a refresh
  that will arrive in an hour, in a process of its own.
  """

  require Logger

  @doc false
  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      @doc """
      Read the PUBLISH this instance is serving, answering its refusals.

      Answers `{:ok, %SIP.Publication{}}` — the presentity, the operation, the
      document and the lifetime that may be granted — or `{:error, code}`, in
      which case the refusal has already gone out on the wire. Options:

        * `:package` — the package name this scenario serves. A PUBLISH for any
          other one is answered **489** without the scenario having to look;
        * `:expires` — a ceiling of the scenario's own, applied on top of the
          package's `max_expires/0`.
      """
      defmacro check_publish(opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "check_publish")

          {var!(sip_ctx), unquote(Macro.var(:__pub_rc__, __MODULE__))} =
            SIP.Session.Publish.do_check_publish(var!(sip_ctx), unquote(opts))

          unquote(Macro.var(:__pub_rc__, __MODULE__))
        end
      end

      @doc """
      Answer the PUBLISH this instance is serving.

      On a 2xx, `:etag` and `:expires` are what the collection granted and they
      go out as `SIP-ETag` and `Expires` (RFC 3903 §6 makes both mandatory
      there). A removal carries no entity-tag — there is no state left to name —
      so passing one with `expires: 0` writes none.

      On a refusal, the header that makes it actionable is written from what the
      package says: `Min-Expires` on a 423, `Accept` on a 415. A bare string in
      place of the options is the reason phrase, as it is for `reply_invite/2`.
      """
      defmacro reply_publish(code, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "reply_publish #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.Publish.do_reply_publish(var!(sip_ctx), unquote(code), unquote(opts))
        end
      end

      @doc "The publication this instance read, or nil before `check_publish/1` accepted one."
      defmacro last_publication() do
        quote do
          SIP.Context.appdata_get(var!(sip_ctx), :publication)
        end
      end
    end
  end

  # ── The reading ─────────────────────────────────────────────────────────────

  @doc """
  Read a PUBLISH against the packages this node knows, and say what it asks for.

  Answers `{:ok, %SIP.Publication{}}` or `{:error, code, reason, fields}` —
  `fields` being what the refusal must carry: the `Min-Expires` of a 423 (RFC
  3903 §6, as mandatory there as RFC 3261 §10.3 makes it for a REGISTER) and the
  `Accept` of a 415, without which a publisher has no way to know what to send
  instead and simply gives up.

  Public because the Router asks the same question before any script runs, and
  asking it twice is how two answers to one question start.
  """
  @spec read(map(), keyword()) ::
          {:ok, SIP.Publication.t()} | {:error, 400..699, binary(), list()}
  def read(req, opts \\ []) when is_map(req) do
    with {:ok, package} <- read_package(req, opts),
         {:ok, operation, etag, requested} <- read_operation(req, package),
         {:ok, content_type, body, doc} <- read_body(req, package, operation),
         {:ok, granted} <- bound_expires(requested, package, opts) do
      {:ok, publication(req, package, operation, etag, granted, content_type, body, doc)}
    end
  end

  # No Event header at all is a PUBLISH nobody can serve (RFC 3903 §6 step 2):
  # the package is what says which state is being published, so its absence is
  # the same answer as a package we do not know.
  defp read_package(req, opts) do
    with {name, _id} <- SIP.Msg.Ops.event_package(req),
         :ok <- served?(name, Keyword.get(opts, :package)),
         {:ok, package} <- SIP.EventPackage.lookup(name) do
      {:ok, package}
    else
      _no_package ->
        Logger.info("PUBLISH refused: no event package this node serves (489)")
        {:error, 489, "Bad Event", []}
    end
  end

  # A scenario serving one package must never have to check that the inbound
  # PUBLISH concerns it (plan §1, "489 before any script").
  defp served?(_name, nil), do: :ok

  defp served?(name, served) when is_binary(served) do
    if name == String.downcase(served), do: :ok, else: :not_served
  end

  defp read_operation(req, package) do
    case SIP.Msg.Ops.publish_operation(req, package.default_expires()) do
      # Neither a tag nor a body: nothing to publish, and nothing to name
      # (RFC 3903 §11.3.2).
      :invalid ->
        {:error, 400, "Bad Request", []}

      {operation, etag, expires} ->
        {:ok, operation, etag, expires}
    end
  end

  # A refresh and a removal carry no body, and asking a package to parse one it
  # was not sent is how a refresh ends up answered 415.
  defp read_body(_req, _package, operation) when operation in [:refresh, :remove],
    do: {:ok, nil, nil, nil}

  defp read_body(req, package, _operation) do
    offered = Enum.map(package.content_types(), &String.downcase/1)
    # A body sent with no Content-Type is read as the package's own: RFC 3261
    # §20.15 defaults it, and a publisher that omits it means the one type the
    # package advertises.
    content_type = SIP.Msg.Ops.body_content_type(req) || List.first(offered)
    body = SIP.Msg.Ops.body_string(req)

    if content_type in offered do
      parse_body(package, content_type, body)
    else
      {:error, 415, "Unsupported Media Type", [accept: Enum.join(package.content_types(), ", ")]}
    end
  end

  # The document is untrusted input and the package is the only thing that knows
  # how to read it (P4 bounds what that costs). A body it refuses is stored by
  # nobody: every watcher of this resource would be sent it verbatim.
  defp parse_body(package, content_type, body) do
    case package.parse(content_type, body) do
      {:ok, doc} ->
        {:ok, content_type, body, doc}

      {:error, reason} ->
        Logger.info(
          "PUBLISH refused: #{inspect(package)} cannot read this #{content_type} " <>
            "document: #{inspect(reason)} (400)"
        )

        {:error, 400, "Invalid Document", []}
    end
  end

  defp bound_expires(requested, package, opts) do
    ceiling =
      case Keyword.get(opts, :expires) do
        seconds when is_integer(seconds) -> min(seconds, package.max_expires())
        _none -> package.max_expires()
      end

    cond do
      # A removal, not a lifetime that is "too brief" (RFC 3903 §4.4) — the same
      # distinction a rebinding REGISTER carrying `;expires=0` forced on the
      # registrar.
      requested == 0 -> {:ok, 0}
      requested < package.min_expires() -> too_brief(package)
      true -> {:ok, min(requested, ceiling)}
    end
  end

  defp too_brief(package) do
    {:error, 423, "Interval Too Brief", [{"Min-Expires", to_string(package.min_expires())}]}
  end

  defp publication(req, package, operation, etag, granted, content_type, body, doc) do
    {username, domain} = presentity(req)

    %SIP.Publication{
      username: username,
      domain: domain,
      event: package.name(),
      etag: etag,
      received_time: SIP.Publication.now(),
      body: body,
      sender: sender(req),
      operation: operation,
      package: package,
      content_type: content_type,
      doc: doc
    }
    |> SIP.Publication.grant(granted)
  end

  # The resource being published, as `presentity` holds it: the user and domain
  # of the Request-URI, which is where a PUBLISH is addressed (RFC 3903 §4.1).
  defp presentity(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{} = uri -> {uri.userpart, uri.domain}
      _ -> {nil, nil}
    end
  end

  defp sender(req) do
    case Map.get(req, :from) do
      %SIP.Uri{} = uri ->
        case SIP.Uri.serialize_ruri(uri) do
          {:ok, str} -> str
          _ -> nil
        end

      other when is_binary(other) ->
        other

      _ ->
        nil
    end
  end

  # ── The verbs ───────────────────────────────────────────────────────────────

  @doc false
  @spec do_check_publish(%SIP.Context{}, keyword()) ::
          {%SIP.Context{}, {:ok, SIP.Publication.t()} | {:error, 400..699}}
  def do_check_publish(sip_ctx = %SIP.Context{}, opts) when is_list(opts) do
    req = stored_publish!(sip_ctx)

    case read(req, opts) do
      {:ok, pub} ->
        {SIP.Context.appdata_set(sip_ctx, :publication, pub), {:ok, pub}}

      {:error, code, reason, fields} ->
        sip_ctx = reply(sip_ctx, req, code, reason, fields, "reject_publish #{code}")
        {sip_ctx, {:error, code}}
    end
  end

  @doc false
  @spec do_reply_publish(%SIP.Context{}, 100..699, keyword() | binary()) :: %SIP.Context{}
  def do_reply_publish(sip_ctx = %SIP.Context{}, code, reason) when is_binary(reason),
    do: do_reply_publish(sip_ctx, code, reason: reason)

  def do_reply_publish(sip_ctx = %SIP.Context{}, code, opts)
      when is_integer(code) and is_list(opts) do
    req = stored_publish!(sip_ctx)
    pub = SIP.Context.appdata_get(sip_ctx, :publication)
    reason = Keyword.get(opts, :reason)

    reply(sip_ctx, req, code, reason, response_fields(code, pub, opts), "reply_publish #{code}")
  end

  # A 2xx states the lifetime granted and names the state it granted it to; a
  # removal names nothing, because there is no state left (RFC 3903 §6).
  defp response_fields(code, pub, opts) when code in 200..299 do
    expires = Keyword.get(opts, :expires) || remaining(pub)

    case Keyword.get(opts, :etag) do
      etag when is_binary(etag) and expires > 0 -> [expires: expires, sipetag: etag]
      _no_etag -> [expires: expires]
    end
  end

  defp response_fields(423, pub, opts) do
    case Keyword.get(opts, :min_expires) || min_expires(pub) do
      nil -> []
      minimum -> [{"Min-Expires", to_string(minimum)}]
    end
  end

  defp response_fields(415, pub, opts) do
    case Keyword.get(opts, :accept) || content_types(pub) do
      nil -> []
      accept -> [accept: accept]
    end
  end

  defp response_fields(_code, _pub, _opts), do: []

  defp remaining(%SIP.Publication{} = pub), do: SIP.Publication.remaining(pub)
  defp remaining(_none), do: 0

  defp min_expires(%SIP.Publication{package: package}) when not is_nil(package),
    do: package.min_expires()

  defp min_expires(_none), do: nil

  defp content_types(%SIP.Publication{package: package}) when not is_nil(package),
    do: Enum.join(package.content_types(), ", ")

  defp content_types(_none), do: nil

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # The PUBLISH this instance is serving. `auto_store/2` puts every inbound one
  # there, for the same reason it stores a SUBSCRIBE: the verbs answer the
  # request that has just arrived, never the one that created the instance.
  defp stored_publish!(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :last_uas_req) ||
           SIP.Context.appdata_get(sip_ctx, :inbound_request) do
      %{method: :PUBLISH} = req ->
        req

      other ->
        raise "No inbound PUBLISH to answer (last stored request: #{inspect(other && other.method)})"
    end
  end

  defp reply(sip_ctx, req, code, reason, fields, label) do
    rc = SIP.Session.reply(sip_ctx.dialogpid, req, code, reason, fields, label)
    SIP.Context.set(sip_ctx, :lasterr, normalize(rc))
  end

  defp normalize(:ignore), do: :ok
  defp normalize(rc), do: rc
end
