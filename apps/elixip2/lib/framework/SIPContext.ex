defmodule SIP.Context do
  @moduledoc """
  A SIP session context: the SIP user agent properties (username, auth, dialog,
  media handles) of one session, local to the process running it.

  It is **`FSL.Context` extended**, not a struct of its own that happens to hold
  FSM fields too: the six fields of `FSL.Context.fields/0` are the state the
  finite state machine keeps about itself, and the ones listed below are the SIP
  session's. Which half a field belongs to is now written down rather than
  inferred, and an `@after_compile` check refuses a `defstruct` that lost the
  FSM half.

  Nothing else changes: the name, the nineteen fields, the `set/3` validation,
  `from/1` and `to/2` are as they were, and no scenario, script or mixin is
  affected.

  ## Every write is photographed

  `set/3`, `appdata_set/3` and `assert_identity/2` are the three doors a scenario
  writes this context through, and each hands what it produces to
  `FSL.Context.snapshot/1`. The context is a stack variable and an Elixir
  `rescue` clause sees the bindings of the moment the `try` was entered, so
  without the photo a state that raised after setting a call up handed the
  teardown the context of *before* its own body — no leg to release, no media
  session to free, a call left standing on both sides.
  """
  @after_compile FSL.Context

  # The SIP session's own properties — the ones `set/3` accepts as a string, and
  # `get/2` reads off the struct rather than out of appdata.
  @props [
    :username,
    :displayname,
    :authusername,
    :domain,
    :ha1,
    :ha1b,
    :algorithm,
    :ftag,
    :debug,
    :dialogpid,
    :lasterr,
    :parent_pid
  ]

  # The FSM's six (lasterr, errorreason, currentstate, laststate, parent_pid,
  # appdata) come from FSL; the rest is this binding's.
  defstruct FSL.Context.fields() ++
              [
                username: nil,
                authusername: nil,
                displayname: nil,
                domain: nil,
                ha1: nil,
                ha1b: nil,
                algorithm: "MD5",
                ftag: nil,
                debug: false,
                dialogpid: nil,
                mediaservermodule: nil,
                mediaserverpid: nil,
                asserted_identity: nil
              ]

  @doc """
  Bring the context macros into a SIP scenario: the five generic ones from
  `FSL.Context`, bound to `sip_ctx` and routed through this module's own
  `set/3` and `get/2`, plus the three that read a SIP message — `ctx_from`,
  `ctx_to` and `assert_identity`.

  Each half carries its own double-injection guard — `:fsl_context_used` in
  `FSL.Context`, `:sip_context_used` here — because a scenario reaches this
  module through two `use` lines (SIP.Scenario -> SIP.Session.CallUAC ->
  SIP.Context, and SIP.Session.RegisterUAC -> SIP.Context) and would otherwise
  redefine the macros, raising "previous clause always matches" on every one.
  Two guards and not one: a module that had already `use`d `FSL.Context`
  directly, to bind a context variable of its own, must still get the SIP
  macros if it then asks for them.

  Both are set imperatively, at expansion time, for the reason
  `FSL.Context.__using__` gives.
  """
  defmacro __using__(_opts) do
    sip_macros =
      if Module.get_attribute(__CALLER__.module, :sip_context_used) do
        nil
      else
        Module.put_attribute(__CALLER__.module, :sip_context_used, true)
        sip_macros()
      end

    quote do
      use FSL.Context,
        ctx_var: :sip_ctx,
        setter: {SIP.Context, :set},
        getter: {SIP.Context, :get}

      unquote(sip_macros)
    end
  end

  # The three that are SIP's: they read or compose a SIP URI, which is the
  # message layer's business and travels with this binding.
  defp sip_macros do
    quote do
      defmacro ctx_from() do
        quote do
          SIP.Context.from(var!(sip_ctx))
        end
      end

      defmacro ctx_to(userpart) do
        quote do
          SIP.Context.to(var!(sip_ctx), unquote(userpart))
        end
      end

      # Record the identity an authentication verdict proved for this
      # session's peer. See SIP.Context.assert_identity/2.
      defmacro assert_identity(identity) do
        quote do
          var!(sip_ctx) =
            SIP.Context.assert_identity(var!(sip_ctx), unquote(identity))
        end
      end
    end
  end

  def get(context, prop) when prop in @props do
    Map.get(context, prop)
  end

  # Media server handles are stored as top-level struct fields, not in appdata.
  def get(context, prop) when prop in [:mediaservermodule, :mediaserverpid] do
    Map.get(context, prop)
  end

  # FSM bookkeeping fields. They are FSL's, so FSL answers for them — the one
  # reading of what `currentstate` means lives there, not in each binding.
  def get(context, prop) when prop in [:currentstate, :laststate, :errorreason] do
    FSL.Context.get(context, prop)
  end

  # The proved identity of this session's peer (see assert_identity/2).
  def get(context, :asserted_identity) do
    Map.get(context, :asserted_identity)
  end

  def get(context, prop) when is_atom(prop) do
    Map.get(context.appdata, prop)
  end

  @doc "Read an application-defined value stored in the context appdata map."
  def appdata_get(context = %SIP.Context{}, prop) do
    Map.get(context.appdata, prop)
  end

  @doc "Store an application-defined value in the context appdata map."
  def appdata_set(context = %SIP.Context{}, prop, value) do
    FSL.Context.snapshot(Map.put(context, :appdata, Map.put(context.appdata, prop, value)))
  end

  @spec set(map(), list()) :: list()
  def set(context, []) do
    context
  end

  def set(context, proplist) when is_list(proplist) do
    [{prop, value} | remaining] = proplist
    new_ctx = set(context, prop, value)
    set(new_ctx, remaining)
  end

  @doc """
  Write one property of the context.

  The one door in: whatever the property is, the context that comes out is
  photographed by `FSL.Context.snapshot/1` before it is returned, so that a state
  raising later hands the teardown what it had allocated rather than the context
  it was entered with (see `FSL.Context.snapshot/1`). The clauses below are the
  validation, one per property; this is where the write is recorded.
  """
  def set(context, prop, value), do: FSL.Context.snapshot(do_set(context, prop, value))

  # Set the username, minting the From tag on the first write.
  #
  # The `if` had no `else`, so a SECOND write — a scenario that reads its account
  # from a backend after a first `config` value, a registrar instance reused for
  # another AOR — returned nil and the `Map.put` below raised a BadMapError in the
  # state that wrote it. The tag is minted once and kept: it identifies this side
  # of every dialog this session opens (RFC 3261 §19.3), so re-minting it would be
  # a worse fix than the crash it replaces.
  defp do_set(context, :username, value) when is_binary(value) do
    context =
      if is_nil(context.ftag) do
        Map.put(context, :ftag, SIP.Msg.Ops.generate_from_or_to_tag())
      else
        context
      end

    Map.put(context, :username, value)
  end

  # Set a single property that is already int he map
  defp do_set(context, prop, value) when prop in @props and is_binary(value) do
    Map.put(context, prop, value)
  end

  # Set the dialog PID
  defp do_set(context, :dialogpid, value) do
    if is_pid(value) do
      Map.put(context, :dialogpid, value)
    else
      raise "dialog PID must me a process ID"
    end
  end

  # Set the parent FSM PID (nil means this scenario has no parent and runs
  # standalone, so notify_parent / child_exit become no-ops).
  defp do_set(context, :parent_pid, nil) do
    Map.put(context, :parent_pid, nil)
  end

  defp do_set(context, :parent_pid, value) do
    if is_pid(value) do
      Map.put(context, :parent_pid, value)
    else
      raise "parent PID must be a process ID"
    end
  end

  # Set the media PID (nil clears it, e.g. after releasing media resources)
  defp do_set(context, :mediaserverpid, nil) do
    Map.put(context, :mediaserverpid, nil)
  end

  defp do_set(context, :mediaserverpid, value) do
    if is_pid(value) do
      Map.put(context, :mediaserverpid, value)
    else
      raise "mediaserver PID must me a process ID"
    end
  end

  defp do_set(context, :mediaservermodule, value) do
    if is_atom(value) and Code.ensure_loaded?(value) do
      Map.put(context, :mediaservermodule, value)
    else
      raise "mediaserver module must be a module"
    end
  end

  # Set the password
  defp do_set(ctx, :passwd, value)
      when ctx.authusername != nil and ctx.algorithm != nil and ctx.domain != nil do
    Map.put(ctx, :ha1, SIP.Auth.compute_ha1(ctx.algorithm, ctx.authusername, ctx.domain, value))
  end

  defp do_set(ctx, :passwd, _value)
      when is_nil(ctx.authusername) or is_nil(ctx.algorithm) or is_nil(ctx.domain) do
    raise "Cannot set password. One of the following has not been set: authusername, domain, algorithm"
  end

  # The FSM's own four, delegated so that the meaning of each — an atom state
  # name, a human-readable reason, an error channel that takes any term — is
  # defined once, in FSL, and not re-derived by every binding. The spellings
  # stay: `SIP.Context.set(ctx, :currentstate, …)` is what a test and a script
  # write, and FSL writes `FSL.Context.put/3`.
  defp do_set(ctx, prop, value) when prop in [:lasterr, :currentstate, :laststate, :errorreason] do
    FSL.Context.put(ctx, prop, value)
  end

  # The identity an authentication verdict proved, as the URI to assert. Written
  # through assert_identity/2 rather than here in the ordinary case.
  defp do_set(ctx, :asserted_identity, nil) do
    Map.put(ctx, :asserted_identity, nil)
  end

  defp do_set(ctx, :asserted_identity, %SIP.Uri{} = uri) do
    Map.put(ctx, :asserted_identity, uri)
  end

  defp do_set(_context, prop, _value) when is_atom(prop) do
    raise "Unsupported context property #{prop}"
  end

  @doc """
  Record the identity an authentication verdict proved for this session's peer,
  as the URI a `P-Asserted-Identity` will carry (RFC 3325).

  `identity` is the map an authentication backend answers `{:ok, identity}` with
  — `%{user: "alice", realm: "example.com"}`. The backend decides *who*; turning
  that into a URI is the message layer's business and happens here, once, so that
  no two places compose `sip:user@realm` and end up composing it differently.

      case Kelix.Mod.AuthDb.authenticate(req, sip_ctx.domain) do
        {:ok, identity} -> assert_identity(identity)
        ...
      end

  Two things follow from where the result is stored.

  **The field answers two questions with one bit.** `nil` means no authentication
  happened, so nothing is asserted; set means the digest proved this identity and
  it is the one to put on the wire. `SIP.Msg.Ops.prepare_forwarded_request/2` needs
  nothing else — no separate flag saying whether a backend ran.

  **It is the context and not the request** because a B2BUA hunt re-prepares the
  *original* request for every target it tries: an identity written onto the
  stored request would survive the first target and vanish on the second.

  The display name is deliberately left empty. The verdict has none, and the only
  one available is the `From`'s — what the caller *claims*. Copying it into a
  header whose meaning is "this was verified" would lend it a guarantee it does
  not have; if one is ever wanted it comes from the subscriber table, through the
  verdict, never from the message.
  """
  @spec assert_identity(%SIP.Context{}, map() | %SIP.Uri{} | nil) :: %SIP.Context{}
  def assert_identity(context = %SIP.Context{}, nil) do
    FSL.Context.snapshot(Map.put(context, :asserted_identity, nil))
  end

  def assert_identity(context = %SIP.Context{}, %SIP.Uri{} = uri) do
    FSL.Context.snapshot(Map.put(context, :asserted_identity, uri))
  end

  def assert_identity(context = %SIP.Context{}, identity) when is_map(identity) do
    user = Map.get(identity, :user) || Map.get(identity, "user")
    realm = Map.get(identity, :realm) || Map.get(identity, "realm") || context.domain

    if is_nil(user) or is_nil(realm) do
      raise ArgumentError,
            "assert_identity: need a user and a realm, got #{inspect(identity)}" <>
              " (context domain: #{inspect(context.domain)})"
    end

    FSL.Context.snapshot(
      Map.put(context, :asserted_identity, %SIP.Uri{
        scheme: "sip:",
        userpart: to_string(user),
        domain: to_string(realm)
      })
    )
  end

  def from(context) do
    # `hparams`: the From tag is a header field parameter (`to-param`, RFC 3261
    # §25.1), not part of the address. In `params` it would end up inside the
    # angle brackets, where a peer reads it as part of the URI and the dialog no
    # longer matches.
    from_uri = %SIP.Uri{
      displayname: context.displayname,
      userpart: context.username,
      domain: context.domain,
      hparams: %{"tag" => context.ftag}
    }

    if from_uri.userpart == nil or from_uri.domain == nil do
      raise "username or domain has not been set"
    else
      from_uri
    end
  end

  def to(context, userpart) do
    if is_nil(context.domain), do: raise("domain has not been set")
    userpart = if userpart != nil, do: userpart, else: context.username

    to_uri = %SIP.Uri{
      userpart: userpart,
      domain: context.domain
    }

    if to_uri.userpart == nil do
      raise "username not been set"
    else
      to_uri
    end
  end
end
