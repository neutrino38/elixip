# INVITE session layer (UAS behaviour + UAC mixin).
# Part of the SIP.Session namespace; see SIPSession.ex for the common core.

defmodule SIP.Session.Call do
  @callback on_new_call(dialog_id :: pid, invitereq :: map) :: { :accept, pid } | { :reject, integer, binary }
  @callback on_call_end(dialog_id :: pid, app_pid :: pid) :: nil
end

defmodule SIP.Session.CallUAC do
  require Logger
  require SIP.Session.Media

  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      defmacro send_INVITE(ruri, sdp_offer, options) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_INVITE")
          var!(sip_ctx) = SIP.Session.CallUAC.client_invite(var!(sip_ctx), unquote(ruri), unquote(sdp_offer), unquote(options))
        end
      end

      defmacro send_auth_INVITE(resp, ruri, sdp_offer, options) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_auth_INVITE")
          var!(sip_ctx) = SIP.Session.CallUAC.auth_invite(var!(sip_ctx), unquote(resp), unquote(ruri), unquote(sdp_offer), unquote(options))
        end
      end

      defmacro process_invite_reply(resp, transaction_id) do
        quote do
          var!(sip_ctx) =
            SIP.Session.CallUAC.process_invite_reply(
              var!(sip_ctx), unquote(resp), unquote(transaction_id))
        end
      end

      # Dispatch any SIP reply to the right per-method handler based on the
      # method carried in the response CSeq. INVITE/OPTIONS/REGISTER are
      # handled; other methods are ignored. See `SIP.Session.dispatch_reply/3`.
      defmacro process_sip_reply(resp, transaction_id) do
        quote do
          var!(sip_ctx) =
            SIP.Session.dispatch_reply(var!(sip_ctx), unquote(resp), unquote(transaction_id))
        end
      end

      defmacro send_BYE() do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_BYE")
          var!(sip_ctx) = SIP.Session.CallUAC.client_bye(var!(sip_ctx))
        end
      end

      defmacro send_ACK(transaction_id) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_ACK")
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
      "Supported" => "replaces",
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
      medias = Keyword.get(options, :media, :tc)
      {sip_ctx, sdp_offer} = SIP.Session.Media.get_sdp_offer(sip_ctx, webrtc_support, medias)
      # Cache the offer so an authenticated retry (auth_invite) reuses the exact
      # same SDP instead of rebuilding it — see auth_invite/5 for the rationale.
      sip_ctx = SIP.Context.appdata_set(sip_ctx, :localsdpoffer, sdp_offer)
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
      medias = Keyword.get(options, :media, :tc)

      # An authenticated retry after a 401/407 is the same request re-sent with
      # an Authorization header and a higher CSeq (RFC 3261 §22.2/§26.2): the
      # SDP body MUST be identical to the initial INVITE. Reuse the offer built
      # by client_invite rather than rebuilding it — rebuilding re-runs the
      # media negotiation (a second EndpointStartReceiving on an endpoint that
      # is already receiving), which the media server rejects.
      {sip_ctx, sdp_offer} =
        case SIP.Context.appdata_get(sip_ctx, :localsdpoffer) do
          nil ->
            webrtc_support = Keyword.get(options, :webrtc, :no)
            SIP.Session.Media.get_sdp_offer(sip_ctx, webrtc_support, medias)

          cached_offer ->
            {sip_ctx, cached_offer}
        end

      auth_invite(sip_ctx, resp, ruri, sdp_offer, timeout)
    else
      raise "No media server connected to the session context"
    end
  end

  def auth_invite(sip_ctx = %SIP.Context{}, resp, ruri, sdp_offer, timeout)
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

    SIP.Session.send_sip_request(sip_ctx, invite, timeout)
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



  def process_sdp_resp(sip_ctx = %SIP.Context{}, resp) when resp.response in [200, 183] do
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

  @doc """
  Process a reply to an outbound INVITE: on 200, apply the SDP answer and ACK;
  on 183, apply the early SDP answer. Other responses are ignored.
  """
  @spec process_invite_reply(%SIP.Context{}, map(), pid() | reference()) :: %SIP.Context{}
  def process_invite_reply(sip_ctx = %SIP.Context{}, resp, transaction_id) when is_map(resp) do
    case resp.response do
      200 ->
        process_sdp_resp(sip_ctx, resp)
        ack(sip_ctx, transaction_id)
        sip_ctx

      183 ->
        process_sdp_resp(sip_ctx, resp)

      # Ignore other responses for now.
      _ ->
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
