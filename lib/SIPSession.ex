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
      case Agent.start( fn -> %ConfigRegistry{} end, name: __MODULE__ ) do
        { :ok, pid } -> { :ok, pid }
        # Registry already running (e.g. started by a previous test module): reuse it
        { :error, { :already_started, pid } } -> { :ok, pid }
        err -> err
      end
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

  defmodule Media do
    # NOTE: this mixin must be combined with a session module (e.g. SIP.Session.CallUAC)
    # that brings in `use SIP.Context` — the media macros rely on `var!(sip_ctx)`.
    defmacro __using__(_opts) do
      quote do
        defmacro media_connect(module, url) do
          quote do
            var!(sip_ctx) = SIP.Session.Media.use_mediaserver(var!(sip_ctx), unquote(module), unquote(url))
          end
        end

        defmacro media_start_echo() do
          quote do
            var!(sip_ctx) = SIP.Session.Media.start_echo(var!(sip_ctx))
          end
        end

        defmacro media_stop() do
          quote do
            var!(sip_ctx) = SIP.Session.Media.stop_media(var!(sip_ctx))
          end
        end
      end
    end

    def use_mediaserver(sip_ctx = %SIP.Context{}, module, url) when is_atom(module) and is_binary(url) do
      if not Code.ensure_loaded?(module) do
        raise "Media server module must be an Elixir module"
      end
      sip_ctx = SIP.Context.set(sip_ctx, :mediaservermodule, module)
      rez = apply(module, :connect, [url])

      sip_ctx = case rez do
        { :ok, pid } -> SIP.Context.set(sip_ctx, :mediaserverpid, pid)
        _ -> raise "Failed to connect to media server #{url}"
      end
      sip_ctx
    end

    @doc """
    Build a local SDP offer from the connected media server.

    Creates the peer connection on first call and stores its handle in the
    context appdata (`:mediapeerconnectionid`), so subsequent calls reuse it.
    Returns `{updated_ctx, sdp_offer}`.
    """
    @spec get_sdp_offer(%SIP.Context{}, atom()) :: {%SIP.Context{}, binary()}
    def get_sdp_offer(sip_ctx = %SIP.Context{}, webrtc_support) when is_atom(webrtc_support) do
      if not is_pid(sip_ctx.mediaserverpid) do
        raise "No media server connected to the session context"
      end

      {sip_ctx, cnx} =
        case SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid) do
          nil ->
            # Create a new peer connection and store it in the session context
            {:ok, cnx} = apply(sip_ctx.mediaservermodule, :create_peer_connection,
                               [sip_ctx.mediaserverpid, self(), [webrtc_support: webrtc_support]])
            {SIP.Context.appdata_set(sip_ctx, :mediapeerconnectionid, cnx), cnx}

          cnx ->
            # Reuse the existing peer connection
            {sip_ctx, cnx}
        end

      {:ok, offer} = apply(sip_ctx.mediaservermodule, :get_local_offer, [cnx])
      {sip_ctx, offer}
    end

    @doc """
    Feed a remote SDP answer to the media server peer connection.
    Stores the result (`:ok` / `{:error, _}`) in `:lasterr` and returns the context.
    """
    @spec process_sdp_answer(%SIP.Context{}, binary()) :: %SIP.Context{}
    def process_sdp_answer(sip_ctx = %SIP.Context{}, answer) when is_binary(answer) do
      if not is_pid(sip_ctx.mediaserverpid) do
        raise "No media server connected to the session context"
      end

      cnx = SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid)
      if is_nil(cnx) do
        raise "No media peer connection found in the session context"
      end
      rez = apply(sip_ctx.mediaservermodule, :set_remote_answer, [cnx, answer])
      SIP.Context.set(sip_ctx, :lasterr, rez)
    end

    def start_echo(sip_ctx = %SIP.Context{}) do
      if not is_pid(sip_ctx.mediaserverpid) do
        raise "No media server connected to the session context"
      end

      cnx = SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid)
      if is_nil(cnx) do
        raise "No media peer connection found in the session context"
      end

      if not is_nil(SIP.Context.appdata_get(sip_ctx, :mediaactionid)) do
        Logger.warning([dialogpid: self(), module: __MODULE__,
                     message: "Media action already started, ignoring start_echo request"])
        sip_ctx
      else
        {:ok, echo_pid} = apply(sip_ctx.mediaservermodule, :create_echo, [cnx])
        SIP.Context.appdata_set(sip_ctx, :mediaactionid, echo_pid)
        |> SIP.Context.appdata_set(:mediaaction, :echo)
      end
    end

    def stop_media(sip_ctx = %SIP.Context{}) do
      if not is_pid(sip_ctx.mediaserverpid) do
        raise "No media server connected to the session context"
      end

      action_pid = SIP.Context.appdata_get(sip_ctx, :mediaactionid)
      if not is_nil(action_pid) do
        case SIP.Context.appdata_get(sip_ctx, :mediaaction) do
          :echo -> apply(sip_ctx.mediaservermodule, :stop_echo, [action_pid])
          _ -> Logger.warning([dialogpid: self(), module: __MODULE__,
                     message: "Unknown media action #{inspect(SIP.Context.appdata_get(sip_ctx, :mediaaction))}, ignoring stop_media request"])
        end
        SIP.Context.appdata_set(sip_ctx, :mediaactionid, nil) |> SIP.Context.appdata_set(:mediaaction, nil)
      else
        Logger.warning([dialogpid: self(), module: __MODULE__,
                     message: "No media action started, ignoring stop_media request"])
        sip_ctx
      end
    end
  end


  defmodule CallUAC do
    require SIP.Session.Media

    defmacro __using__(_opts) do
      quote do
        use SIP.Context

        defmacro send_INVITE(ruri, sdp_offer, options) do
          quote do
            var!(sip_ctx) = SIP.Session.CallUAC.client_invite(var!(sip_ctx), unquote(ruri), unquote(sdp_offer), unquote(options))
          end
        end

        defmacro send_auth_INVITE(resp, ruri, sdp_offer, options) do
          quote do
            var!(sip_ctx) = SIP.Session.CallUAC.auth_invite(var!(sip_ctx), unquote(resp), unquote(ruri), unquote(sdp_offer), unquote(options))
          end
        end

        defmacro process_invite_reply(resp) do
          quote do
            var!(sip_ctx) = case unquote(resp).response do
              200 -> SIP.Session.CallUAC.process_200_ok(var!(sip_ctx), unquote(resp))
              _ -> var!(sip_ctx)
            end
          end
        end

        defmacro send_BYE() do
          quote do
            var!(sip_ctx) = SIP.Session.CallUAC.client_bye(var!(sip_ctx))
          end
        end

        defmacro send_ACK(transaction_id) do
          quote do
            SIP.Session.CallUAC.ack(var!(sip_ctx), unquote(transaction_id))
          end
        end
      end
    end

    defp invite_msg(sip_ctx = %SIP.Context{}, ruri, body) do
      contact_uri = %SIP.Uri{
        userpart: SIP.Context.get(sip_ctx, :username),
        domain: "0.0.0.0",
        params: %{}
      }

      ruri =
        if is_binary(ruri) do
          case SIP.Uri.parse(ruri) do
            { :ok, parsed } -> parsed
            err -> raise "Invalid request URI #{inspect(ruri)}: #{inspect(err)}"
          end
        else
          ruri
        end

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

    @spec client_invite(%SIP.Context{}, binary(), binary() | list() | atom(), integer() | list()) :: %SIP.Context{}
    def client_invite(sip_ctx = %SIP.Context{}, ruri, :mediaserver, options) when is_list(options) do
      if is_pid(sip_ctx.mediaserverpid) do
        timeout = Keyword.get(options, :timeout, 20)
        webrtc_support = Keyword.get(options, :webrtc, :no)
        {sip_ctx, sdp_offer} = SIP.Session.Media.get_sdp_offer(sip_ctx, webrtc_support)
        client_invite(sip_ctx, ruri, sdp_offer, timeout)
      else
        raise "No media server connected to the session context"
      end
    end

    def client_invite(sip_ctx = %SIP.Context{}, ruri, sdp_offer, timeout) when is_integer(timeout) do
      invite = invite_msg(sip_ctx, ruri, sdp_offer)
      SIP.Session.send_sip_request(sip_ctx, invite, timeout)
    end

    @doc """
    Re-send an INVITE authenticated against a 401/407 challenge response `resp`.
    Mirrors `SIP.Session.RegisterUAC.auth_register/3` for the INVITE method.
    """
    @spec auth_invite(%SIP.Context{}, map(), binary(), binary() | list() | atom(), integer() | list()) :: %SIP.Context{}
    def auth_invite(sip_ctx = %SIP.Context{}, resp, ruri, :mediaserver, options) when is_list(options) do
      if is_pid(sip_ctx.mediaserverpid) do
        timeout = Keyword.get(options, :timeout, 20)
        webrtc_support = Keyword.get(options, :webrtc, :no)
        {sip_ctx, sdp_offer} = SIP.Session.Media.get_sdp_offer(sip_ctx, webrtc_support)
        auth_invite(sip_ctx, resp, ruri, sdp_offer, timeout)
      else
        raise "No media server connected to the session context"
      end
    end

    def auth_invite(sip_ctx = %SIP.Context{}, resp, ruri, sdp_offer, _timeout)
        when is_map(resp) and is_integer(resp.response) do
      {autheader, authparams} =
        case resp.response do
          407 -> {:proxyauthenticate, Map.get(resp, :proxyauthenticate)}
          401 -> {:wwwauthenticate, Map.get(resp, :wwwauthenticate)}
          _ -> raise "You must provide a 401 or 407 response with auth params to auth the INVITE"
        end

      if is_nil(authparams) do
        raise "Missing #{autheader} header in #{resp.response} response"
      end

      invite =
        invite_msg(sip_ctx, ruri, sdp_offer)
        |> SIP.Msg.Ops.add_authorization_to_req(
          authparams, autheader, sip_ctx.authusername, sip_ctx.ha1, :ha1
        )

      rez = SIP.Dialog.new_request(sip_ctx.dialogpid, invite)
      SIP.Context.set(sip_ctx, :lasterr, rez)
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



    def process_200_ok(sip_ctx = %SIP.Context{}, resp) when resp.response == 200 do
      dlg_id = sip_ctx.dialogpid
      case Map.get(resp, :body) do
        sdp_answer when is_binary(sdp_answer) ->
          SIP.Session.Media.process_sdp_answer(sip_ctx, sdp_answer)

        [%{data: sdp_answer} | _] ->
          SIP.Session.Media.process_sdp_answer(sip_ctx, sdp_answer)

        list when is_list(list) ->
          case Enum.find(list, fn part -> to_string(part[:contenttype]) =~ "sdp" end) do
            %{data: sdp_answer} ->
              Logger.debug([dialogpid: dlg_id, module: __MODULE__,
                       message: "Processing SDP answer from 200 OK response in multipart body"])
              SIP.Session.Media.process_sdp_answer(sip_ctx, sdp_answer)

            _ ->
              Logger.warning([dialogpid: dlg_id, module: __MODULE__,
                       message: "No SDP answer found in 200 OK response, ignoring"])
              sip_ctx
          end

        _ ->
          Logger.warning([dialogpid: dlg_id, module: __MODULE__,
            message: "No SDP answer found in 200 OK response, ignoring"])

          sip_ctx
      end
    end

    def ack(sip_ctx = %SIP.Context{}, transaction_id) do
      SIP.Dialog.ack(sip_ctx.dialogpid, transaction_id)
    end

    @spec client_bye(%SIP.Context{}) :: %SIP.Context{}
    def client_bye(sip_ctx = %SIP.Context{})  do
      bye = bye_message(sip_ctx)
      SIP.Session.send_sip_request(sip_ctx, bye, 0)
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
