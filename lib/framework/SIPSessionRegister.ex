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

  # Calllback defined for a registrar server. They are called
  @callback on_new_registration(dialog_id :: pid, registerreq :: map) :: { :accept, pid } | { :reject, integer, binary }
  @callback on_registration_expired(dialog_id :: pid, app_pid :: pid) :: nil

  defp adjust_contact_expires(contact) do
    case SIP.Uri.get_uri_param(contact, "expires") do
      {:ok, value} ->
        case String.to_integer(value) do
          expires when expires > @max_expires ->
            SIP.Uri.set_uri_param(contact, "expires", to_string(@max_expires))

          expires when expires < @min_expires ->
            raise "Contact expire value #{value} is below the minimum allowed #{@min_expires}"

          _ ->
            contact
        end

      _ ->
        contact
    end
  end

  defp adjust_all_contacts(contacts) when is_list(contacts) do
    Enum.map(contacts, &adjust_contact_expires/1)
  end

  defp adjust_expires_header(req) do
    expires = Map.get(req, :expires)
    cond do
      is_nil(expires) -> req
      expires > @max_expires -> Map.put(req, :expires,  @max_expires)
      expires < @min_expires ->
        raise "Expires value #{expires} is too low."
      true -> req
    end
  end

  @doc """
    Helper function for registrar implementation
    Check the Expires header and the Contact header(s) for expiration values.
    If any of them is below @min_expires, reject with 423 Interval Too Brief.
    If any of them is above @max_expires, adjust to max expires
  """
  def check_register(registerreq) when is_map(registerreq) do

    contacts = List.wrap(Map.get(registerreq, :contact))
    if length(contacts) > @max_contacts do
      throw {:reject, 400, "Too many contacts"}
    end
    adjusted_contacts = adjust_all_contacts(contacts)
    Map.put(registerreq, :contact, adjusted_contacts)
          |> adjust_expires_header()

  end
end

defmodule SIP.Session.RegisterUAC do
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
          var!(sip_ctx) = SIP.Session.RegisterUAC.auth_register(var!(sip_ctx), unquote(resp_401), unquote(expire))
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
              var!(sip_ctx), unquote(resp), unquote(transaction_id))
        end
      end

      # Process a reply to an OPTIONS keepalive: on a 2xx, re-arm the next
      # `:options_keepalive` timer.
      defmacro process_options_reply(resp, transaction_id) do
        quote do
          var!(sip_ctx) =
            SIP.Session.RegisterUAC.process_options_reply(
              var!(sip_ctx), unquote(resp), unquote(transaction_id))
        end
      end
    end
  end

  defp register_msg(sip_ctx = %SIP.Context{}, expire) do
    contact_uri = %SIP.Uri{
      userpart: SIP.Context.get(sip_ctx, :username),
      domain: "0.0.0.0",
      params: %{ "expires" => to_string(expire) }
    }

    %{
      "Max-Forwards" => "70",
      method: :REGISTER,
      ruri: SIP.Context.to(sip_ctx, nil),
      from: SIP.Context.from(sip_ctx),
      to: SIP.Context.to(sip_ctx,nil),
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
      ruri: %SIP.Uri{ domain: SIP.Context.get(sip_ctx, :domain) },
      from: SIP.Context.from(sip_ctx),
      to: SIP.Context.to(sip_ctx,nil),
      contact: %SIP.Uri{ userpart: SIP.Context.get(sip_ctx, :username),
        domain: "0.0.0.0", params: %{ "expires" => "15" } },
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }
  end


  @doc"""
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
      register = SIP.Msg.Ops.add_authorization_to_req(
        register, authparams, :wwwauthenticate,
        sip_ctx.authusername, sip_ctx.ha1, :ha1)
      rez = SIP.Dialog.new_request(sip_ctx.dialogpid, register)
      SIP.Context.set(sip_ctx, :lasterr, rez)
      sip_ctx
    end
  end

  def send_options(sip_ctx = %SIP.Context{}, opts \\ []) when is_list(opts) do
    timeout = Keyword.get(opts, :timeout, 20)
    options = options_msg(sip_ctx)
    SIP.Session.send_sip_request(sip_ctx, options, timeout)
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
  scenario process) and the OPTIONS keepalive timer is armed (delivering
  `:options_keepalive`). When it is 0 — an un-REGISTER — the keepalive timer is
  cancelled. Non-2xx replies are ignored.
  """
  @spec process_register_reply(%SIP.Context{}, map(), pid() | reference()) :: %SIP.Context{}
  def process_register_reply(sip_ctx = %SIP.Context{}, resp, _transaction_id)
      when is_map(resp) and resp.response in 200..299 do
    case granted_expire(sip_ctx, resp) do
      expire when is_integer(expire) and expire > 0 ->
        sip_ctx
        |> arm_timer(@refresh_timer_key, :register_refresh, max(div(expire, 2), 1))
        |> arm_timer(@keepalive_timer_key, :options_keepalive, keepalive_period())

      _ ->
        # expire == 0 (un-REGISTER) or no usable Contact: stop keepalives.
        cancel_timer(sip_ctx, @keepalive_timer_key)
    end
  end

  def process_register_reply(sip_ctx = %SIP.Context{}, _resp, _transaction_id), do: sip_ctx

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

    with %SIP.Uri{} <- contact,
         {:ok, value} <- SIP.Uri.get_uri_param(contact, "expires") do
      String.to_integer(value)
    else
      _ -> header_expire(resp)
    end
  end

  defp header_expire(resp) do
    # The parser maps the "Expires" header to :expires with an integer value.
    case Map.get(resp, :expires) do
      v when is_binary(v) -> String.to_integer(v)
      v when is_integer(v) -> v
      _ -> nil
    end
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
