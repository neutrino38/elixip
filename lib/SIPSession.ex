defmodule SIP.Session do
  @moduledoc """
  This module defines an Agent and several behaviors.
  The behaviors are to be implemented by SIP apps in order to process requests and create processes if need.
  These behavors requires specialized callback that will be invoked when a dialog is created by a server transaction:
  eg. incoming calls, incoming registration (when implemebenting a registrar) or incoming presence / messaging

  Each of these callback function shall return a pid of an "application process" that will be bound to the dialog.
  This process will receive the various SIP requests and responses from the dialog layer. All the dirty details such
  as SIP retransmission, and refresh, etc will be handled by the dialog layer

  It is assumed by the dialog layer that the app process is processing requests as follow:

  receive do
   { <method>, <req message>, <transaction_pid>, <dialog_pid> } ->

  e.g.

  receive do
    { :BYE, <req message>, <transaction_pid>, <dialog_pid> } ->

  For SIP responses

  receive do
    { <resp code>, <resp message>, <transaction_pid>, <dialog_pid> } ->

  """
  require Logger

    @doc"""
    Send an outbound SIP request and create the dialog if needed
    Update the session sip_ctx accordingly
    """
  def send_sip_request(sip_ctx = %SIP.Context{}, req, timeout) do
    if not is_pid(sip_ctx.dialogpid) do
      case SIP.Dialog.start_dialog(req, timeout, :outbound, sip_ctx.debug) do
        { :ok, dialog_pid, _dialog_id } ->
          # Dialog created, update context and clear last error
          SIP.Context.set(sip_ctx, :dialogpid, dialog_pid) |> SIP.Context.set(:lasterr, :ok)

        { :error, err} ->
          SIP.Context.set(sip_ctx, :lasterr, err)
      end
    else
      # Send an in dialog request
      rc = SIP.Dialog.new_request(sip_ctx.dialogpid, req)
      SIP.Context.set(sip_ctx, :lasterr, rc)
    end
  end

  defmodule ConfigRegistry do
    defstruct [
      callprocessing: nil,
      mainapppid: nil,
      registration: nil,
      presence: nil,
    ]

    use Agent

    def start() do
      Agent.start( fn -> %ConfigRegistry{} end, name: __MODULE__ )
    end

    @spec set_call_processing_module(module()) :: :ok
    @doc """
    Specify which call processing module will be used by the Dialog Layer
    module: the Elixir module implementing the call behavior
    """
    def set_call_processing_module(module) do
      Agent.update(__MODULE__, fn reg ->
        %ConfigRegistry{ reg | callprocessing: module }
      end)
    end

    @spec set_registration_processing_module(module()) :: :ok
    @doc """
    Specify which registration processing will be used by the Dialog Layer
    module: the Elixir module implementing the call behavior
    """
    def set_registration_processing_module(module) do
      Agent.update(__MODULE__, fn reg ->
        %ConfigRegistry{ reg | registration: module }
      end)
    end

    defp internal_dispatch( proc_atom, fun_atom, args, errormsg ) when is_atom(fun_atom) and is_list(args) do
      # Get the module that is configured to process the request
      call_mod = Agent.get(__MODULE__, fn reg -> Map.get(reg, proc_atom) end)
      if call_mod == nil do
        # If no module is found, reject the request
        Logger.error("No processing module configured for #{proc_atom}.")
        { :reject, 500,  errormsg }
      else
        # If a module is configured, call the callback in this module
        Logger.debug("Dispatched #{proc_atom} to  #{inspect(call_mod)}.#{fun_atom}().")
        apply(call_mod, fun_atom, args)
      end
    end

    @doc """
     Call this to dispatch the on_new_end callback of the call processing
    module
    """
    def dispatch( dialog_id, req ) when is_map(req) and req.method == :INVITE do
      internal_dispatch(
        :callprocessing, :on_new_call,
        [ dialog_id, req ], "No call server defined")
    end

    def dispatch( dialog_id, req ) when is_map(req) and req.method == :REGISTER do
      internal_dispatch(
        :registration, :on_new_registration,
        [ dialog_id, req ], "No registration server defined")
    end

    def dispatch( :on_call_end, dialog_id, app_id ) when is_pid(app_id) do
      internal_dispatch(
        :callprocessing, :on_call_end,
        [ dialog_id, app_id], "No call server defined")
    end

    def dispach( :on_registration_expired, dialog_id, app_pid ) when is_pid(app_pid) do
      internal_dispatch(
        :registration, :on_new_registration,
        [ dialog_id, app_pid], "No registration server defined")
    end
  end

  defmodule Call do
    @callback on_new_call(dialog_id :: pid, invitereq :: map) :: { :accept, pid } | { :reject, integer, binary }
    @callback on_call_end(dialog_id :: pid, app_pid :: pid) :: nil
  end


  defmodule Registrar do
    defmacro __using__(_opts) do
    end

    # Calllback defined for a registrar server. They are called
    @callback on_new_registration(dialog_id :: pid, registerreq :: map) :: { :accept, pid } | { :reject, integer, binary }
    @callback on_registration_expired(dialog_id :: pid, app_pid :: pid) :: nil

  end

  defmodule RegisterUAC do
    defmacro __using__(_opts) do
      quote do
        use SIP.Context

        defmacro send_REGISTER(expire) do
          quote do
            var!(sip_ctx) = SIP.Session.RegisterUAC.client_register(var!(sip_ctx), unquote(expire))
          end
        end

        defmacro send_auth_REGISTER(resp_401, expire) do
          quote do
            var!(sip_ctx) = SIP.Session.RegisterUAC.auth_register(var!(sip_ctx), unquote(resp_401), unquote(expire))
          end
        end

        defmacro send_OPTIONS() do
          quote do
            var!(sip_ctx) = SIP.Session.RegisterUAC.send_options(var!(sip_ctx))
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
    @spec client_register(%SIP.Context{}, integer()) :: %SIP.Context{}
    def client_register(sip_ctx = %SIP.Context{}, expire) when is_integer(expire) do
      register = register_msg(sip_ctx, expire)
      SIP.Session.send_sip_request(sip_ctx, register, expire)
    end

    @spec auth_register(%SIP.Context{},map(), integer()) :: %SIP.Context{}
    def auth_register(sip_ctx = %SIP.Context{}, rsp, expire) when is_map(rsp) and is_integer(rsp.response) do
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

    def send_options(sip_ctx = %SIP.Context{}) do
      options = options_msg(sip_ctx)
      SIP.Session.send_sip_request(sip_ctx, options, 20)
    end
  end

  defmodule CallUAC do
    defp invite_msg(sip_ctx = %SIP.Context{}, ruri, body) do
      contact_uri = %SIP.Uri{
        userpart: SIP.Context.get(sip_ctx, :username),
        domain: "0.0.0.0",
        params: %{}
      }

      ruri = if is_binary(ruri), do: SIP.Uri.parse(ruri), else: ruri
      req = %{
        "Max-Forwards" => "70",
        "Supported:" => "replaces",
        method: :INVITE,
        ruri: ruri,
        from: SIP.Context.from(sip_ctx),
        to: ruri,
        contact: contact_uri,
        useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
        callid: nil,
        contentlength: 0
      }
      SIP.Msg.Ops.update_sip_msg(req, { :body, body })
    end

    @spec client_invite(%SIP.Context{}, binary(), binary() | list(), integer()) :: %SIP.Context{}
    def client_invite(sip_ctx = %SIP.Context{}, ruri, sdp_offer, timeout) when is_integer(timeout) do
      invite = invite_msg(sip_ctx, ruri, sdp_offer)
      SIP.Session.send_sip_request(sip_ctx, invite, timeout)
    end

    defmacro send_INVITE(ruri, sdp_offer, timeout) do
      quote do
        var!(sip_ctx) = SIP.Session.CallUAC.client_invite(var!(sip_ctx), unquote(ruri), unquote(sdp_offer), unquote(timeout))
      end
    end

    defp bye_message(sip_ctx) do
      %{
        "Max-Forwards" => "70",
        method: :BYE,
        ruri: SIP.Context.to(sip_ctx, nil),
        from: SIP.Context.from(sip_ctx),
        to: SIP.Context.to(sip_ctx,nil),
        useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
        callid: nil,
        contentlength: 0
      }
    end

    def ack(sip_ctx = %SIP.Context{}, transaction_id) do
      SIP.Dialog.ack(sip_ctx.dialogpid, transaction_id)
    end

    @spec client_bye(%SIP.Context{}) :: %SIP.Context{}
    def client_bye(sip_ctx = %SIP.Context{})  do
      bye = bye_message(sip_ctx)
      SIP.Session.send_sip_request(sip_ctx, bye, 0)
    end

    defmacro send_BYE() do
      quote do
        var!(sip_ctx) = SIP.Session.CallUAC.client_bye(var!(sip_ctx))
      end
    end
  end

  defmodule Common do
    require SIP.Dialog

    @doc "CANCEL an existing outbound request"
    def cancel(sip_ctx = %SIP.Context{}, transaction_id) when is_pid(transaction_id) do
      rc = SIP.Dialog.cancel(sip_ctx.dialogpid, transaction_id)
      SIP.Context.set(sip_ctx, :lasterr, rc)
    end

    defmacro send_CANCEL(transaction_id) do
        quote do
          var!(sip_ctx) = SIP.Session.Common.cancel(var!(sip_ctx), unquote(transaction_id))
        end
    end
  end

  defmodule Presence do
    @callback on_new_publish(dialog_id :: pid, pub_req :: map) :: { :accept, pid } | { :reject, integer }
    @callback on_new_subscribe(dialog_id :: pid, sub_req :: map) :: { :accept, pid } | { :reject, integer }
    @callback on_message(dialog_id :: pid, msg_req :: map) :: { :accept, pid } | { :reject, integer }
    @callback on_info(dialog_id :: pid, msg_req :: map) :: { :accept, pid } | { :reject, integer }
    @callback on_session_expired(dialog_id :: pid, app_pid :: pid) :: nil
  end

end
