defmodule SIP.Session do
  @doc """
  This module defines an Agent and several behaviors.
  The behaviors are to be implemented by SIP apps in order to process requests and create processes if need.
  These behavors requires specialized callbacks that will be invoked when a dialog is created by a server transaction:
  eg. incoming calls, incoming registration (when implemebenting a registrar) or incoming presence / messaging

  Each of these callback function shall return a pid of an "application process" that will be bound to the dialog.
  This process will receive the various SIP requests and responses from the dialog layer. All the dirty details such
  as SIP retransmission, and refresh, etc will be handled by the dialog layer

  It is assumed by the dialog layer that the app process is a GenServer responding to the following:

  handle_call( { <method>, <req message>, <transaction_pid> }, <dialog_pid> ) to handle incoming SIP requests
  and it should

  e.g.

  handle_call( { :BYE, <req message>, <transaction_pid> }, <dialog_pid> ) to handle incoming SIP requests

  For SIP responses

  handle_cast( { <resp code>, <res message>, <transaction_pid> }, <dialog_pid> ) to handle SIP responses
  """
  defmodule ConfigRegistry do
    defstruct [
      callprocessing: nil,
      mainapppid: nil,
      registration: nil,
      presence: nil,

      username: nil,
      authusername: nil,
      displayname: nil,
      domain: nil,
      ha1: nil,
      ha1b: nil,

    ]

    @props [ :username, :displayname, :authusername, :domain, :ha1, :ha1b ]

    use Agent

    def start() do
      Agent.start( fn -> %ConfigRegistry{} end, name: __MODULE__ )
    end

    @doc """
    Specify which call processing module will be used by the Dialog Layer
    module: the Elixir module implementing the call behavior
    """
    def set_call_processing_module(module) do
      Agent.update(__MODULE__, fn reg ->
        %ConfigRegistry{ reg | callprocessing: module }
      end)
    end

    @spec set_registration_processing_module(any()) :: :ok
    @doc """
    Specify which registration processing will be used by the Dialog Layer
    module: the Elixir module implementing the call behavior
    """
    def set_registration_processing_module(module) do
      Agent.update(__MODULE__, fn reg ->
        %ConfigRegistry{ reg | registration: module }
      end)
    end

    @spec set(atom(), binary()) :: :nosuchproperty | :ok
    @doc """
    Set a property of the registy
    """

    def set(property, value) when is_atom(property) do
      if property in @props do
        Agent.update(
          __MODULE__,
          fn reg -> Map.put(reg, property, value) end)
      else
        :nosuchproperty
      end
    end

    @spec get(atom()) :: any()
    @doc """
    Get a property from the registy
    """

    def get(property) when is_atom(property) do
      Agent.get(__MODULE__, fn reg -> Map.get(reg, property) end)
    end

    def from() do
      from_uri = %SIP.Uri{
        displayname: get(:displayname),
        userpart: get(:username),
        domain: get(:domain),
        params: %{ "tag" => SIP.Msg.Ops.generate_from_or_to_tag() }
      }

      if from_uri.userpart == nil or from_uri.domain == nil do
        raise "username or domain has not been set"
      else
        from_uri
      end
    end


    def to( userpart ) do
      userpart = if userpart != nil, do: userpart, else: get(:username)
      to_uri = %SIP.Uri{
        userpart: userpart,
        domain: get(:domain)
      }

      if to_uri.userpart == nil or to_uri.domain == nil do
        raise "username or domain has not been set"
      else
        to_uri
      end
    end

    defp internal_dispatch( proc_atom, fun_atom, args, errormsg ) when is_atom(fun_atom) and is_list(args) do
      call_mod = ConfigRegistry.get(proc_atom)
      if call_mod == nil do
        { :reject, 500,  errormsg }
      else
        apply(call_mod, fun_atom, args)
      end
    end

    @doc """
     Call this to dispatch the on_new_end callback of the call processing
    module
    """
    def dispach( dialog_id, req ) when is_map(req) and req.method == :INVITE do
      internal_dispatch(
        :callprocessing, :on_new_call,
        [ dialog_id, req ], "No call server defined")
    end

    def dispach( dialog_id, req ) when is_map(req) and req.method == :REGISTER do
      internal_dispatch(
        :registration, :on_new_registration,
        [ dialog_id, req ], "No registration server defined")
    end

    def dispach( :on_call_end, dialog_id, app_id ) when is_pid(app_id) do
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
    @callback on_new_registration(dialog_id :: pid, registerreq :: map) :: { :accept, pid } | { :reject, integer, binary }
    @callback on_registration_expired(dialog_id :: pid, app_pid :: pid) :: nil

    @spec client_register(integer(), boolean()) :: { :ok, pid } | { :failure, binary }
    def client_register(expire \\ 600, debug \\ false) do
      register = %{
        method: :REGISTER,
        from: SIP.Session.ConfigRegistry.from(),
        to: SIP.Session.ConfigRegistry.to(nil),
        expire: expire,
        callid: nil
      }

      case SIP.Dialog.start_dialog(register, expire, :outbound, debug) do
        { :ok, dialog_id } -> { :ok, dialog_id }
        { code, err } -> { code, err }
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
