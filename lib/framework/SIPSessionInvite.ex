# INVITE session layer (UAS behaviour + UAC mixin).
# Part of the SIP.Session namespace; see SIPSession.ex for the common core.

defmodule SIP.Session.Call do
  # `transaction_id` is the server transaction (IST) that created the dialog,
  # aligned on on_new_registration/3. Replies go through the dialog, so an
  # implementation may ignore it.
  @callback on_new_call(dialog_id :: pid, invitereq :: map, transaction_id :: pid) ::
              { :accept, pid } | { :reject, integer, binary }
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

      # Reply to the most recently received INVITE / re-INVITE / UPDATE (stored
      # in the context by on_events auto_store) with a code that carries NO SDP.
      # Common to UAC and UAS: a UAC in an established dialog can receive a
      # re-INVITE/UPDATE and must be able to reply to it. SDP-bearing replies
      # (183 / 2xx to an INVITE) are the job of reply_invite_with_sdp /
      # reply_invite_with_body (phase 3); do_reply_invite guards against them.
      defmacro reply_invite(code, reason \\ nil, upd_fields \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "reply_invite #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.CallUAS.do_reply_invite(
              var!(sip_ctx), unquote(code), unquote(reason), unquote(upd_fields))
        end
      end

      # Reply 183 Session Progress or 200 OK to the stored INVITE/re-INVITE/UPDATE
      # with an SDP answer negotiated with the connected media server (the
      # scenario must have called media_connect()). A local Contact is added
      # automatically (required by a 2xx to an INVITE). On media failure the
      # reply is 500 Media Server Error (overridable with `on_media_error:
      # {code, reason}`). `opts`: :reason, :contact, :webrtc, :media,
      # :on_media_error. Common to UAC and UAS (a UAC answers a re-INVITE too).
      defmacro reply_invite_with_sdp(code, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "reply_invite_with_sdp #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.CallUAS.do_reply_invite_with_sdp(
              var!(sip_ctx), unquote(code), unquote(opts))
        end
      end

      # Reply to the stored INVITE/re-INVITE/UPDATE with an arbitrary body.
      # `bodies` is a raw binary (Content-Type application/sdp), a single
      # `%{contenttype: ct, data: bin}` map, or a one-element list of such maps
      # — the structure yielded by the SIP parser. Multipart (list > 1) awaits
      # the multipart serialization phase. `opts`: :reason, :contact and any
      # extra reply field. Common to UAC and UAS.
      defmacro reply_invite_with_body(code, bodies, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "reply_invite_with_body #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.CallUAS.do_reply_invite_with_body(
              var!(sip_ctx), unquote(code), unquote(bodies), unquote(opts))
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
    case SIP.Session.extract_sdp(resp) do
      sdp_answer when is_binary(sdp_answer) ->
        SIP.Session.Media.process_sdp_answer(sip_ctx, sdp_answer)

      _ ->
        Logger.warning(
          dialogpid: sip_ctx.dialogpid,
          module: __MODULE__,
          message: "No SDP answer found in #{resp.response} response, ignoring"
        )

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

defmodule SIP.Session.CallUAS do
  @moduledoc """
  UAS-side INVITE helpers: automatic storage of the inbound offer request and
  server reply macros.

  `auto_store/2` is called by the `on_events` instrumentation (SIP.Scenario) for
  every matched event and stashes the most recent inbound INVITE / re-INVITE /
  UPDATE (plus its server-transaction pid) in the context, so the reply macros
  need not re-pass the request.

  Reply macros:
    * `reply_invite/1..3` (no SDP), `reply_invite_with_sdp/1..2` (media-negotiated
      183/200) and `reply_invite_with_body/2..3` (arbitrary body) — defined in
      `SIP.Session.CallUAC` (common to UAC and UAS, since a UAC in a dialog can
      receive a re-INVITE/UPDATE). Backed by `do_reply_invite*` here.
    * `redirect_invite/1..3` and `challenge_invite/1..2` — server-only, injected
      by `use SIP.Session.CallUAS`.

  All replies go through `SIP.Dialog.reply/5` / `SIP.Dialog.challenge/4`, which
  do NOT check the dialog state (a scenario may deliberately reply out of order).
  """
  require Logger

  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      # 3xx redirect to one or more contacts. `contacts` is a String, a
      # %SIP.Uri{} or a list of either.
      defmacro redirect_invite(contacts, code \\ 302, reason \\ nil) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "redirect_invite #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.CallUAS.do_redirect_invite(
              var!(sip_ctx), unquote(contacts), unquote(code), unquote(reason))
        end
      end

      # 401/407 digest challenge of the inbound INVITE. Reuses the dialog layer's
      # nonce generation / storage (SIP.Dialog.challenge/4).
      defmacro challenge_invite(realm, code \\ 407) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "challenge_invite #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.CallUAS.do_challenge_invite(
              var!(sip_ctx), unquote(realm), unquote(code))
        end
      end
    end
  end

  @doc """
  Store the inbound offer request (INVITE / re-INVITE / UPDATE) and its server
  transaction pid in the context appdata (single slot `:last_uas_req` /
  `:last_uas_req_tid`), so the reply macros can serve it. No-op for any other
  event. Called by the on_events instrumentation for every matched event.
  """
  def auto_store(sip_ctx, {m, req, trans_pid, _dlg})
      when m in [:INVITE, :UPDATE] and is_map(req) do
    sip_ctx
    |> SIP.Context.appdata_set(:last_uas_req, req)
    |> SIP.Context.appdata_set(:last_uas_req_tid, trans_pid)
  end

  def auto_store(sip_ctx, _evt), do: sip_ctx

  @doc """
  Reply to the stored INVITE/UPDATE with a code that carries NO SDP. Raises for
  183 or 2xx (they require an SDP body → use reply_invite_with_sdp /
  reply_invite_with_body, phase 3), except for a 2xx answering an UPDATE that
  carried no offer (legal without SDP). Backs the `reply_invite` macro.
  """
  def do_reply_invite(sip_ctx = %SIP.Context{}, code, reason, upd_fields)
      when is_integer(code) do
    req = fetch_stored_req!(sip_ctx)

    if needs_sdp?(code) and not (req.method == :UPDATE and not has_sdp?(req)) do
      raise "reply_invite: code #{code} requires an SDP body; " <>
              "use reply_invite_with_sdp/reply_invite_with_body (phase 3)"
    end

    rc = SIP.Dialog.reply(sip_ctx.dialogpid, req, code, reason, upd_fields)
    SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
  end

  @doc """
  Reply 183/200 to the stored INVITE/UPDATE with a media-negotiated SDP answer.
  Backs the `reply_invite_with_sdp` macro. Extracts the remote offer from the
  stored request, feeds it to the media server (`SIP.Session.Media.get_sdp_answer/3`),
  and replies with the returned answer plus a local Contact. On media failure,
  replies `500 Media Server Error` (overridable via `on_media_error: {code,
  reason}`) and sets `lasterr` to `{:media_error, reason}`.
  """
  def do_reply_invite_with_sdp(sip_ctx = %SIP.Context{}, code, opts)
      when code in [183, 200] and is_list(opts) do
    req = fetch_stored_req!(sip_ctx)

    remote_offer =
      SIP.Session.extract_sdp(req) ||
        raise "reply_invite_with_sdp: the stored #{req.method} carries no SDP offer " <>
                "(delayed offer is not supported)"

    case SIP.Session.Media.get_sdp_answer(sip_ctx, remote_offer, media_opts(opts)) do
      {sip_ctx, {:ok, answer}} ->
        fields = reply_fields(sip_ctx, opts, body: answer)
        rc = SIP.Dialog.reply(sip_ctx.dialogpid, req, code, Keyword.get(opts, :reason), fields)
        SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))

      {sip_ctx, {:error, reason}} ->
        {ecode, ereason} = Keyword.get(opts, :on_media_error, {500, "Media Server Error"})

        Logger.warning(
          dialogpid: sip_ctx.dialogpid,
          module: __MODULE__,
          message:
            "Media server rejected the SDP offer (#{inspect(reason)}); replying #{ecode} #{ereason}"
        )

        _ = SIP.Dialog.reply(sip_ctx.dialogpid, req, ecode, ereason, [])
        SIP.Context.set(sip_ctx, :lasterr, {:media_error, reason})
    end
  end

  def do_reply_invite_with_sdp(_sip_ctx, code, _opts) do
    raise "reply_invite_with_sdp: unsupported code #{inspect(code)} (only 183 and 200)"
  end

  @doc """
  Reply to the stored INVITE/UPDATE with an arbitrary body. Backs the
  `reply_invite_with_body` macro. `bodies` is a raw binary, a single
  `%{contenttype, data}` map, or a one-element list of such maps (the SIP parser
  structure, accepted directly by `update_sip_msg/2`). A list of more than one
  body raises until multipart serialization lands. A local Contact is added for
  a 2xx to an INVITE/UPDATE. `opts`: `:reason`, `:contact`, extra reply fields.
  """
  def do_reply_invite_with_body(sip_ctx = %SIP.Context{}, code, bodies, opts)
      when is_integer(code) and is_list(opts) do
    req = fetch_stored_req!(sip_ctx)
    fields = reply_fields(sip_ctx, opts, body: normalize_bodies(bodies))
    rc = SIP.Dialog.reply(sip_ctx.dialogpid, req, code, Keyword.get(opts, :reason), fields)
    SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
  end

  @doc "3xx redirect + Contact(s). `contacts`: String | %SIP.Uri{} | list."
  def do_redirect_invite(sip_ctx = %SIP.Context{}, contacts, code, reason)
      when code in 300..399 do
    req = fetch_stored_req!(sip_ctx)
    rc = SIP.Dialog.reply(sip_ctx.dialogpid, req, code, reason, contact: contacts)
    SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
  end

  @doc "401/407 digest challenge (reuses the dialog nonce machinery)."
  def do_challenge_invite(sip_ctx = %SIP.Context{}, realm, code)
      when code in [401, 407] do
    req = fetch_stored_req!(sip_ctx)
    rc = SIP.Dialog.challenge(sip_ctx.dialogpid, req, code, realm)
    SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
  end

  # Prefer the auto-stored offer request; fall back to the initial inbound
  # request (stashed by the runner) for the atypical case of a reply issued
  # before any on_events clause matched.
  defp fetch_stored_req!(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :last_uas_req) ||
           SIP.Context.appdata_get(sip_ctx, :inbound_request) do
      req when is_map(req) -> req
      _ -> raise "reply_invite*: no stored INVITE/UPDATE to reply to"
    end
  end

  defp needs_sdp?(code), do: code == 183 or code in 200..299

  # Build the reply upd_fields: start from `base` (e.g. [body: sdp]) and add a
  # local Contact unless the caller supplied one — a 2xx to an INVITE/UPDATE
  # requires a Contact (see reply_to_request/5).
  defp reply_fields(sip_ctx, opts, base) do
    Keyword.put_new(base, :contact, Keyword.get(opts, :contact) || local_contact(sip_ctx))
  end

  # A local Contact URI built from the context username, mirroring the one
  # CallUAC uses for outbound INVITEs. The transport layer rewrites the
  # placeholder host/port with the actual bound address.
  defp local_contact(sip_ctx) do
    %SIP.Uri{
      userpart: SIP.Context.get(sip_ctx, :username) || "anonymous",
      domain: "0.0.0.0",
      params: %{}
    }
  end

  # Only :webrtc / :media are meaningful to the media negotiation.
  defp media_opts(opts), do: Keyword.take(opts, [:webrtc, :media])

  # Normalize the `bodies` argument accepted by reply_invite_with_body into a
  # value understood by update_sip_msg/2 ({:body, ...}). Multipart (list > 1)
  # is not serializable yet (SIP.Msg.Ops raises); reject it with a clear error.
  defp normalize_bodies(body) when is_binary(body), do: body
  defp normalize_bodies(%{contenttype: _, data: _} = part), do: [part]
  defp normalize_bodies([%{contenttype: _, data: _}] = parts), do: parts

  defp normalize_bodies(parts) when is_list(parts) and length(parts) > 1 do
    raise "reply_invite_with_body: multipart bodies are not yet supported " <>
            "(multipart serialization is a later phase)"
  end

  defp normalize_bodies(other) do
    raise "reply_invite_with_body: invalid body #{inspect(other)}; expected a binary, " <>
            "a %{contenttype, data} map, or a one-element list of such maps"
  end

  defp has_sdp?(req) do
    case Map.get(req, :body) do
      b when is_binary(b) and b != "" -> true
      [_ | _] -> true
      _ -> false
    end
  end

  # :ok and :ignore (final response already sent — e.g. the auto-487 after a
  # CANCEL, phase 1 §1.4) both mean success; any other value (transport error,
  # :invalid_sip_msg, :invalid_transaction…) is surfaced as lasterr.
  defp reply_lasterr(:ok), do: :ok
  defp reply_lasterr(:ignore), do: :ok
  defp reply_lasterr(other), do: other
end
