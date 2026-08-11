# REGISTER session layer (registrar behaviour + register UAC mixin).
# Part of the SIP.Session namespace; see SIPSession.ex for the common core.

defmodule SIP.Session.Registrar do
  defmacro __using__(_opts) do
    quote do
      require SIP.Session.ConfigRegistry

      defmacro register_init_uas() do
        quote do
          SIP.Session.ConfigRegistry.set_registration_processing_module(__MODULE__)
        end
      end
    end
  end

  @min_expires 60
  @max_expires 3600
  @max_contacts 5
  @granted_expires 3600

  # Callbacks defined for a registrar server.
  #
  # `on_new_registration/3` is invoked by the dialog layer when an inbound
  # REGISTER creates a new dialog. It receives the dialog pid, the parsed
  # REGISTER request and the pid of the server transaction that created the
  # dialog (so the application can reply on the right transaction). It returns
  # `{:accept, app_pid}` to bind the dialog to an application process — the
  # dialog then forwards `{:REGISTER, req, transaction_id, dialog_id}` to it —
  # or `{:reject, code, reason}` to refuse the registration.
  @callback on_new_registration(dialog_id :: pid, registerreq :: map, transaction_id :: pid) ::
              {:accept, pid} | {:reject, integer, binary}
  @callback on_registration_expired(dialog_id :: pid, app_pid :: pid) :: any()

  # Bounds policy only — the lifetimes themselves are read by SIP.Msg.Ops (the
  # framework's single reading of the RFC 3261 §10.2.4 precedence; see CLAUDE.md,
  # Message Layer). Here we clamp what a contact/header *states*, so a contact
  # carrying no parameter is left alone rather than being pinned to a resolved
  # value: the 200 OK must not invent a per-contact expiry the request never gave.
  #
  # The wildcard Contact (:*) has no expires parameter to bound — pass it through.
  defp adjust_contact_expires(:*), do: :*

  defp adjust_contact_expires(contact) do
    case SIP.Msg.Ops.contact_expires_param(contact) do
      nil ->
        contact

      # 0 drops this binding (§10.2.2). It is not a lifetime that is "too brief":
      # refusing it made the framework unable to answer a rebinding REGISTER at all
      # — the old contact carries `;expires=0`, so accept_registration/3 raised and
      # the registrar instance died without replying anything.
      0 ->
        contact

      expires when expires > @max_expires ->
        SIP.Uri.set_uri_param(contact, "expires", to_string(@max_expires))

      expires when expires < @min_expires ->
        throw({:reject, 423, "Interval Too Brief"})

      _ ->
        contact
    end
  end

  defp adjust_all_contacts(contacts) when is_list(contacts) do
    Enum.map(contacts, &adjust_contact_expires/1)
  end

  defp adjust_expires_header(req) do
    # Read through SIP.Msg.Ops: a header carried as text (a hand-built message)
    # compared with `>` against an integer is always "greater" in Elixir term
    # ordering, which silently rewrote every such Expires to the maximum.
    case SIP.Msg.Ops.expires_header(req) do
      nil ->
        req

      # An un-REGISTER, not a too-brief lifetime (same rule as per contact above).
      0 ->
        req

      expires when expires > @max_expires ->
        Map.put(req, :expires, @max_expires)

      expires when expires < @min_expires ->
        throw({:reject, 423, "Interval Too Brief"})

      _ ->
        req
    end
  end

  # Extract the registering identity: prefer the auth username (present after a
  # successful digest challenge — read by the message layer, which owns that
  # question), fall back to the Contact URI userpart. The fallback is the Contact
  # rather than From because what a REGISTER binds is the contact it carries.
  defp registered_username(req) do
    SIP.Msg.Ops.auth_username(req) || contact_username(req)
  end

  defp contact_username(req) do
    case List.wrap(Map.get(req, :contact)) do
      [%SIP.Uri{userpart: u} | _] when is_binary(u) -> u
      _ -> ""
    end
  end

  def set_contacts_expires(nil, _expires), do: nil

  # A wildcard Contact is never echoed back with an expiry: the 200 OK to a
  # wildcard un-REGISTER simply lists no binding (there are none left).
  def set_contacts_expires(:*, _expires), do: nil

  def set_contacts_expires(contacts, expires) when is_list(contacts),
    do: Enum.map(contacts, &set_contacts_expires(&1, expires))

  def set_contacts_expires(%SIP.Uri{} = contact, expires),
    do: SIP.Uri.set_uri_param(contact, "expires", to_string(expires))

  defp check_register(registerreq) when is_map(registerreq) do
    original_contact = Map.get(registerreq, :contact)
    contacts = List.wrap(original_contact)

    if length(contacts) > @max_contacts do
      throw({:reject, 400, "Too many contacts"})
    end

    adjusted_contacts = adjust_all_contacts(contacts)

    # Preserve original cardinality: a single URI stays a URI, not a list.
    contact =
      if is_list(original_contact),
        do: adjusted_contacts,
        else: List.first(adjusted_contacts)

    Map.put(registerreq, :contact, contact)
    |> adjust_expires_header()
  end

  # Challenge with a 401 carrying a WWW-Authenticate digest header. Two ways to say
  # what to challenge with, and the caller picks by the shape of the third argument:
  #
  #   * a **keyword list** — the dialog layer mints the nonce itself from the realm
  #     we give it (nothing is stored: the scenario validates what comes back with
  #     SIP.Auth.Nonce.validate/2). `:realm`, `:reason`, and `:algorithm`, which
  #     overrides the digest algorithm the dialog layer advertises (MD5 by default —
  #     see SIP.DialogImpl @default_challenge_algorithm). Only raise it for a peer
  #     known to keep its clear password: an elixip UAC answers from a single HA1
  #     computed with its own `ctx.algorithm`, so a mismatch is an unavoidable 403.
  #   * a **map** — an already-built digest parameter set, sent verbatim. That is
  #     what kelixip does: `Kelix.Auth.challenge_params/2` mints a *stateless* nonce
  #     of its own, so the dialog layer must not generate one. The same params feed
  #     a call challenge (`b2bua_challenge/3`), which sends them as
  #     Proxy-Authenticate — hence the header-agnostic name.
  #
  # The first argument is either the scenario context (the dialog pid is read from
  # it — a scenario never has to carry it around) or the dialog pid itself.
  def challenge_registration(ctx_or_req, req_or_dialog_pid, opts \\ [])

  def challenge_registration(sip_ctx = %SIP.Context{}, req, opts) when req.method == :REGISTER do
    challenge_registration(req, sip_ctx.dialogpid, opts)
  end

  def challenge_registration(req, dialog_pid, params)
      when req.method == :REGISTER and is_pid(dialog_pid) and is_map(params) do
    SIP.Session.reply(
      dialog_pid,
      req,
      401,
      "Unauthorized",
      [wwwauthenticate: params],
      "challenge_registration"
    )
  end

  def challenge_registration(req, dialog_pid, opts)
      when req.method == :REGISTER and is_pid(dialog_pid) and is_list(opts) do
    realm = Keyword.get(opts, :realm, "example.com")
    reason = Keyword.get(opts, :reason, "Unauthorized")

    challenge =
      case Keyword.get(opts, :algorithm) do
        nil -> realm
        algorithm -> {realm, algorithm}
      end

    SIP.Session.reply(dialog_pid, req, 401, reason, challenge, "challenge_registration")
  end

  # Accept with a 200 OK enumerating the granted binding(s).
  #
  # Two forms, again picked on the shape of the arguments:
  #
  #   * `(sip_ctx, req, granted)` — `granted` is the `%{aor, contacts, expires}` a
  #     location service (`Kelix.Mod.Registrar.save/2`) hands back: it already
  #     decided which bindings survive and for how long, each contact carrying its
  #     OWN remaining lifetime (RFC 3261 §10.3 step 8). Nothing is re-derived here;
  #     the AOR it names becomes the monitor's account for this instance.
  #   * `(req, dialog_pid, opts)` — no location service: echo the request's own
  #     Contact(s), bounded by check_register/1 (min 60, max 3600, max 5 contacts);
  #     a violation becomes the matching reject response.
  def accept_registration(sip_ctx = %SIP.Context{}, req, %{
        contacts: contacts,
        expires: expires,
        aor: aor
      })
      when req.method == :REGISTER do
    SIP.Scenario.Monitor.note_account(aor)

    SIP.Session.reply(
      sip_ctx.dialogpid,
      req,
      200,
      "OK",
      [contact: empty_to_nil(contacts), expires: expires],
      "accept_registration"
    )
  end

  def accept_registration(req, dialog_pid, opts)
      when req.method == :REGISTER and is_pid(dialog_pid) and is_list(opts) do
    expires = Keyword.get(opts, :expires, @granted_expires)

    try do
      req = check_register(req)

      contact =
        case Keyword.get(opts, :contact) do
          nil -> set_contacts_expires(Map.get(req, :contact), expires)
          c -> c
        end

      SIP.Scenario.Monitor.note_account(registered_username(req))
      SIP.Session.reply(dialog_pid, req, 200, "OK", [contact: contact], "accept_registration")
    catch
      {:reject, code, reason} ->
        reject_registration(req, dialog_pid, code, reason)
    end
  end

  # No binding left ⇒ no Contact header at all, rather than an empty one.
  defp empty_to_nil([]), do: nil
  defp empty_to_nil(contacts), do: contacts

  # Refuse the registration. `reason` is the SIP reason phrase, EXCEPT for the 423,
  # where an integer says "this is the shortest lifetime I grant": RFC 3261 §10.3
  # step 7 makes `Min-Expires` mandatory there, since without it the client has no
  # way to know what to ask for and simply gives up. Same first-argument rule as
  # above: the context or the dialog pid.
  def reject_registration(sip_ctx = %SIP.Context{}, req, code, reason)
      when req.method == :REGISTER do
    reject_registration(req, sip_ctx.dialogpid, code, reason)
  end

  def reject_registration(req, dialog_pid, 423, min_expires)
      when req.method == :REGISTER and is_pid(dialog_pid) and is_integer(min_expires) do
    SIP.Session.reply(
      dialog_pid,
      req,
      423,
      "Interval Too Brief",
      [{"Min-Expires", to_string(min_expires)}],
      "reject_reg 423"
    )
  end

  def reject_registration(req, dialog_pid, code, reason)
      when req.method == :REGISTER and is_pid(dialog_pid) do
    SIP.Session.reply(dialog_pid, req, code, reason, [], "reject_reg #{code}")
  end
end

defmodule SIP.Session.RegisterUAC do
  require Logger

  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      defmacro send_REGISTER(expire) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_REGISTER")
          var!(sip_ctx) = SIP.Session.RegisterUAC.client_register(var!(sip_ctx), unquote(expire))
        end
      end

      defmacro send_auth_REGISTER(resp_401, expire) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_auth_REGISTER")

          var!(sip_ctx) =
            SIP.Session.RegisterUAC.auth_register(
              var!(sip_ctx),
              unquote(resp_401),
              unquote(expire)
            )
        end
      end

      defmacro send_OPTIONS(opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_OPTIONS")
          var!(sip_ctx) = SIP.Session.RegisterUAC.send_options(var!(sip_ctx), unquote(opts))
        end
      end

      # Process a reply to a REGISTER request: on a 2xx with a granted
      # expiration > 0, arm the refresh timer (at half the granted expire,
      # delivering `:register_refresh`) and the OPTIONS keepalive timer
      # (delivering `:options_keepalive`). On a 2xx with expire == 0
      # (un-REGISTER) the keepalive timer is cancelled. Other replies are
      # ignored. Usually reached through `process_sip_reply/2`.
      defmacro process_register_reply(resp, transaction_id) do
        quote do
          var!(sip_ctx) =
            SIP.Session.RegisterUAC.process_register_reply(
              var!(sip_ctx),
              unquote(resp),
              unquote(transaction_id)
            )
        end
      end

      # Process a reply to an OPTIONS keepalive: on a 2xx, re-arm the next
      # `:options_keepalive` timer.
      defmacro process_options_reply(resp, transaction_id) do
        quote do
          var!(sip_ctx) =
            SIP.Session.RegisterUAC.process_options_reply(
              var!(sip_ctx),
              unquote(resp),
              unquote(transaction_id)
            )
        end
      end
    end
  end

  defp register_msg(sip_ctx = %SIP.Context{}, expire) do
    contact_uri = %SIP.Uri{
      userpart: SIP.Context.get(sip_ctx, :username),
      domain: "0.0.0.0",
      params: %{"expires" => to_string(expire)}
    }

    %{
      "Max-Forwards" => "70",
      method: :REGISTER,
      ruri: SIP.Context.to(sip_ctx, nil),
      from: SIP.Context.from(sip_ctx),
      to: SIP.Context.to(sip_ctx, nil),
      contact: contact_uri,
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }
  end

  defp options_msg(sip_ctx = %SIP.Context{}) do
    %{
      "Accept" => "*/*",
      "Accept-Encoding" => "UTF-8",
      "Accept-Language" => "en",
      "Supported" => "OPTIONS, REGISTER",
      "Max-Forwards" => "70",
      method: :OPTIONS,
      ruri: %SIP.Uri{domain: SIP.Context.get(sip_ctx, :domain)},
      from: SIP.Context.from(sip_ctx),
      to: SIP.Context.to(sip_ctx, nil),
      contact: %SIP.Uri{
        userpart: SIP.Context.get(sip_ctx, :username),
        domain: "0.0.0.0",
        params: %{"expires" => "15"}
      },
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }
  end

  @doc """
  Send an outbound REGISTER and create the dialog if needed
  Update the session sip_ctx accordingly
  """
  @spec client_register(%SIP.Context{}, integer() | keyword()) :: %SIP.Context{}
  def client_register(sip_ctx = %SIP.Context{}, opts) when is_list(opts) do
    client_register(sip_ctx, Keyword.get(opts, :timeout, 3600))
  end

  def client_register(sip_ctx = %SIP.Context{}, expire) when is_integer(expire) do
    register = register_msg(sip_ctx, expire)
    SIP.Session.send_sip_request(sip_ctx, register, expire)
  end

  @spec auth_register(%SIP.Context{}, map(), integer() | keyword()) :: %SIP.Context{}
  def auth_register(sip_ctx = %SIP.Context{}, rsp, opts) when is_map(rsp) and is_list(opts) do
    auth_register(sip_ctx, rsp, Keyword.get(opts, :timeout, 3600))
  end

  def auth_register(sip_ctx = %SIP.Context{}, rsp, expire)
      when is_map(rsp) and is_integer(rsp.response) and is_integer(expire) do
    if rsp.response != 401 do
      raise "You must provide a 401 response with auth param to auth the REGISTER"
    end

    register = register_msg(sip_ctx, expire)

    authparams = Map.get(rsp, :wwwauthenticate)

    if not is_nil(authparams) do
      warn_on_algorithm_mismatch(sip_ctx, authparams)

      register =
        SIP.Msg.Ops.add_authorization_to_req(
          register,
          authparams,
          :wwwauthenticate,
          sip_ctx.authusername,
          sip_ctx.ha1,
          :ha1
        )

      rez = SIP.Dialog.new_request(sip_ctx.dialogpid, register)
      SIP.Context.set(sip_ctx, :lasterr, rez)
      sip_ctx
    end
  end

  # The context holds one HA1, computed once from `ctx.algorithm` when the password
  # was set — the clear password is not kept, so answering a challenge that asks for
  # another algorithm is arithmetically impossible: the digest goes out wrong and
  # the server replies 403 with no clue as to why. Say it out loud instead.
  defp warn_on_algorithm_mismatch(sip_ctx, authparams) do
    challenged = Map.get(authparams, "algorithm", "MD5")

    if challenged != sip_ctx.algorithm do
      Logger.error(
        "REGISTER challenged with algorithm #{inspect(challenged)} but our HA1 was computed " <>
          "with #{inspect(sip_ctx.algorithm)}: the digest cannot match (expect a 403). " <>
          "Set `algorithm: #{inspect(challenged)}` in the scenario config block."
      )
    end
  end

  @doc """
  Manually send an OPTIONS keepalive SIP message
  """
  def send_options(sip_ctx = %SIP.Context{}, opts \\ []) when is_list(opts) do
    timeout = Keyword.get(opts, :timeout, 20)
    options = options_msg(sip_ctx)
    SIP.Session.send_sip_request(sip_ctx, options, timeout)
  end

  @spec start_options_keepalive(%SIP.Context{}) :: any()
  @doc """
  Start dialog OPTIONS keepalive in the dialog layer
  Dialog message will be sent automatically and if no
  answers are received after several attempts, the REGISTER
  Dialog will be terminated
  """
  def start_options_keepalive(ctx = %SIP.Context{}) do
    SIP.Dialog.start_options_keepalive(ctx.dialogpid)
  end

  # Appdata keys under which the armed timer references are stored, so they can
  # be re-armed or cancelled later.
  @refresh_timer_key :register_refresh_timer
  @keepalive_timer_key :options_keepalive_timer

  @doc """
  Process a reply to a REGISTER request.

  On a 2xx response, the expiration actually granted by the registrar is read
  from the returned Contact (the binding matching our username, falling back to
  the first Contact, then the `Expires` header). When that expiration is > 0 the
  refresh timer is armed at half of it (delivering `:register_refresh` to the
  scenario process), and **one** OPTIONS keepalive is started. When it is 0 — an
  un-REGISTER — the keepalive is stopped. Non-2xx replies are ignored.

  Who sends the keepalives depends on the scenario's `options_keepalive` config key:

    * `:dialog` (the default) — the dialog layer sends them and tears the dialog
      down after several unanswered ones. The scenario sees nothing.
    * `:scenario` — the scenario is handed `:options_keepalive` every period and
      sends the OPTIONS itself (`send_OPTIONS()`), which is what makes them visible
      in the monitor and the sequence diagram. The dialog stands down.

  Exactly one is started. Arming both is the defect this key exists to prevent: two
  OPTIONS went out per period, only one response was consumed, and the spare sat in
  the scenario's mailbox where every later state read the *previous* request's
  answer — a 401 challenging a refresh REGISTER surfaced 25 s later as
  "OPTIONS failed with 401".
  """
  @spec process_register_reply(%SIP.Context{}, map(), pid() | reference()) :: %SIP.Context{}
  def process_register_reply(sip_ctx = %SIP.Context{}, resp, _transaction_id)
      when is_map(resp) and resp.response in 200..299 do
    case granted_expire(sip_ctx, resp) do
      expire when is_integer(expire) and expire > 0 ->
        sip_ctx
        |> arm_timer(@refresh_timer_key, :register_refresh, max(div(expire, 2), 1))
        |> start_keepalive()

      _ ->
        # expire == 0 (un-REGISTER) or no usable Contact: stop keepalives.
        cancel_timer(sip_ctx, @keepalive_timer_key)
    end
  end

  def process_register_reply(sip_ctx = %SIP.Context{}, _resp, _transaction_id), do: sip_ctx

  # Start the one keepalive the scenario asked for. Reads `options_keepalive` from
  # the context (a scenario `config` key, stored in appdata): :scenario hands the
  # scenario a periodic `:options_keepalive` and tells the dialog to stand down;
  # anything else (the default) leaves it to the dialog layer.
  defp start_keepalive(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :options_keepalive) do
      :scenario ->
        if is_pid(sip_ctx.dialogpid), do: SIP.Dialog.app_drives_keepalive(sip_ctx.dialogpid)
        arm_timer(sip_ctx, @keepalive_timer_key, :options_keepalive, keepalive_period())

      _ ->
        if is_pid(sip_ctx.dialogpid), do: SIP.Dialog.start_options_keepalive(sip_ctx.dialogpid)
        sip_ctx
    end
  end

  @doc """
  Process a reply to an OPTIONS keepalive: on a 2xx, re-arm the next
  `:options_keepalive` timer. Other replies are ignored.
  """
  @spec process_options_reply(%SIP.Context{}, map(), pid() | reference()) :: %SIP.Context{}
  def process_options_reply(sip_ctx = %SIP.Context{}, resp, _transaction_id)
      when is_map(resp) and resp.response in 200..299 do
    arm_timer(sip_ctx, @keepalive_timer_key, :options_keepalive, keepalive_period())
  end

  def process_options_reply(sip_ctx = %SIP.Context{}, _resp, _transaction_id), do: sip_ctx

  # OPTIONS keepalive period (seconds), from the runtime config.
  defp keepalive_period() do
    Application.get_env(:elixip2, :optionkeepaliveperiod, 15)
  end

  # Read the expiration granted by the registrar in a REGISTER 2xx response.
  # Prefer the Contact binding matching our username, fall back to the first
  # Contact, then to the Expires header, else nil.
  @spec granted_expire(%SIP.Context{}, map()) :: integer() | nil
  defp granted_expire(sip_ctx, resp) do
    contacts = List.wrap(Map.get(resp, :contact))
    ours = SIP.Context.get(sip_ctx, :username)

    contact =
      Enum.find(contacts, List.first(contacts), fn
        %SIP.Uri{userpart: u} -> u == ours
        _ -> false
      end)

    # Same precedence as on the request side, read by the same framework function
    # (SIP.Msg.Ops) — with no default: when the registrar states nothing, the
    # caller keeps the lifetime it asked for rather than inventing one.
    SIP.Msg.Ops.contact_expires_param(contact) || SIP.Msg.Ops.expires_header(resp)
  end

  # Cancel a previously armed timer (if any) then start a one-shot timer that
  # delivers `msg` to the scenario process after `delay_s` seconds, storing its
  # reference under `key` in the context appdata.
  defp arm_timer(sip_ctx, key, msg, delay_s) do
    sip_ctx = cancel_timer(sip_ctx, key)
    ref = Process.send_after(self(), msg, delay_s * 1000)
    SIP.Context.appdata_set(sip_ctx, key, ref)
  end

  defp cancel_timer(sip_ctx, key) do
    case SIP.Context.appdata_get(sip_ctx, key) do
      ref when is_reference(ref) ->
        Process.cancel_timer(ref)
        SIP.Context.appdata_set(sip_ctx, key, nil)

      _ ->
        sip_ctx
    end
  end
end
