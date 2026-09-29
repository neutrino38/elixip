# Page-mode messaging verbs (RFC 3428): answering the MESSAGE that created an
# instance, and sending one that belongs to no dialog.
# Part of the SIP.Session namespace; see SIPSession.ex for the common core, and
# docs/design/chat-basic-plan.md, phase C3.

defmodule SIP.Session.Page do
  @moduledoc """
  What a scenario calls to take part in page-mode messaging.

      uas(:message)

      state wait_message do
        on_events do
          {:MESSAGE, _req, _trans, _dlg} ->
            reply_message(202)
            send_page("sip:carol@example.com", "hello", "text/plain")
            goto(wait_answer)
        end
      end

      state wait_answer do
        on_events do
          {:page, :answered, %{code: code}} when code in 200..299 -> scenario_success("delivered")
          {:page, :answered, %{code: code}} -> scenario_failure("refused \#{code}")
          {:page, :failed, %{reason: reason}} -> scenario_failure("not sent: \#{inspect(reason)}")
        end
      end

  ## Two verbs, two directions

  `reply_message/2` answers the out-of-dialog MESSAGE this instance is serving —
  the one that created it, or the last one it received. `send_page/4` sends a
  new one, in a transaction of its own.

  `send_MESSAGE/2` keeps its name and its in-dialog meaning. The two build
  different requests — a route set, a remote target and both tags on one side,
  none of them on the other — and one name with two meanings is a script sending
  out of dialog what it believed was inside.

  ## What comes back

  A page is answered as an **outcome**, not as a transaction:

    * `{:page, :answered, %{code: code, reason: reason, to: to, response: rsp}}`
      — the final response, whatever its code. A transaction that timed out is
      answered **408**, as RFC 3261 §8.1.3.1 reports it to a UA;
    * `{:page, :failed, %{reason: reason, to: to}}` — the request never left
      (no transport, a destination that does not resolve), or its transaction
      ended without a final response.

  The shape is the one the service building blocks return, so a script matches
  on what happened, never on a transaction pid. `to` is the target as it was
  given, which tells two pages in flight apart.

  The page does not touch the instance's own dialog. The dialog carrying it
  belongs to a relay process of its own (`SIP.Session.Page.Relay`), which turns
  the transaction's response into the event above and ends — so an instance
  answering an inbound MESSAGE still answers it on the dialog it came in on.
  """

  require Logger

  @doc false
  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      @doc """
      Answer the out-of-dialog MESSAGE this instance is serving.

      `opts` is a reason phrase, or a keyword list with `:reason` and `:fields`
      (extra response header fields, as `SIP.Dialog.reply/5` takes them).
      """
      defmacro reply_message(code, opts \\ []) do
        quote do
          var!(sip_ctx) =
            SIP.Session.Page.do_reply_message(var!(sip_ctx), unquote(code), unquote(opts))
        end
      end

      @doc """
      Send a new out-of-dialog MESSAGE to `to`, carrying `body` of type
      `content_type`. The answer arrives as a `{:page, …}` event (see
      `SIP.Session.Page`).

      `body` may instead be a MESSAGE this instance received —
      `send_page(target, last_uas_req())`. The page then carries that message
      on, rebuilt by `SIP.MsgTemplate.page_request/2`: its sender, its `To`,
      its content and its allowlisted headers, with `to` as the Request-URI.
      `content_type`, `:from` and `:headers` do not apply.

      Options:

        * `:from` — the sender (a URI string or `%SIP.Uri{}`). Defaults to the
          context's identity, else — in a UAS instance, which has none — to the
          address the MESSAGE it serves was sent to;
        * `:headers` — extra header fields, as a map or keyword list of
          `{"Name", value}`: those of `SIP.MsgTemplate.page_request/2`'s
          allowlist (Subject, Conversation-ID…);
        * `:date` — the `Date` to write (`%DateTime{}` or string);
        * `:timeout` — the lifetime of the dialog carrying the page, in seconds
          (60 by default).
      """
      defmacro send_page(to, body, content_type \\ "text/plain", opts \\ []) do
        quote do
          var!(sip_ctx) =
            SIP.Session.Page.do_send_page(
              var!(sip_ctx),
              unquote(to),
              unquote(body),
              unquote(content_type),
              unquote(opts)
            )
        end
      end
    end
  end

  # ── The UAS half ────────────────────────────────────────────────────────────

  @doc false
  @spec do_reply_message(%SIP.Context{}, 100..699, keyword() | binary()) :: %SIP.Context{}
  def do_reply_message(sip_ctx = %SIP.Context{}, code, reason) when is_binary(reason),
    do: do_reply_message(sip_ctx, code, reason: reason)

  def do_reply_message(sip_ctx = %SIP.Context{}, code, opts)
      when is_integer(code) and is_list(opts) do
    req = stored_message!(sip_ctx)
    reason = Keyword.get(opts, :reason)
    fields = Keyword.get(opts, :fields, [])

    rc = SIP.Session.reply(sip_ctx.dialogpid, req, code, reason, fields, "reply_message #{code}")
    SIP.Context.set(sip_ctx, :lasterr, normalize(rc))
  end

  # The MESSAGE this instance is serving: the last one `auto_store/2` kept, else
  # the one that spawned the instance.
  defp stored_message(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :last_uas_req) ||
           SIP.Context.appdata_get(sip_ctx, :inbound_request) do
      %{method: :MESSAGE} = req -> req
      _other -> nil
    end
  end

  defp stored_message!(sip_ctx) do
    stored_message(sip_ctx) || raise "reply_message: no inbound MESSAGE to answer"
  end

  # ── The UAC half ────────────────────────────────────────────────────────────

  @doc false
  @spec do_send_page(%SIP.Context{}, binary() | %SIP.Uri{}, binary() | nil, binary(), keyword()) ::
          %SIP.Context{}
  def do_send_page(sip_ctx = %SIP.Context{}, to, body, content_type, opts) when is_list(opts) do
    SIP.Scenario.Monitor.note_command(:sip, "send_page")

    req = page(sip_ctx, to, body, content_type, opts)
    timeout = Keyword.get(opts, :timeout, 60)

    {:ok, _relay} = SIP.Session.Page.Relay.start(req, target_label(to), timeout, sip_ctx.debug)
    SIP.Context.set(sip_ctx, :lasterr, :ok)
  end

  # A MESSAGE that arrived is sent on as it came — its sender, its content, its
  # allowlisted headers — to the new target, which stays the Request-URI only:
  # the `To` is still whom the sender wrote to.
  defp page(_sip_ctx, to, %{method: :MESSAGE} = received, _content_type, opts) do
    SIP.MsgTemplate.page_request(received, [ruri: to] ++ Keyword.take(opts, [:date]))
  end

  defp page(sip_ctx, to, body, content_type, opts) do
    %{from: sender!(sip_ctx, opts), to: to, contenttype: content_type, body: body}
    |> Map.merge(Map.new(Keyword.get(opts, :headers, [])))
    |> SIP.MsgTemplate.page_request(Keyword.take(opts, [:date]))
  end

  defp sender!(sip_ctx, opts) do
    cond do
      Keyword.has_key?(opts, :from) ->
        Keyword.fetch!(opts, :from)

      is_binary(sip_ctx.username) and is_binary(sip_ctx.domain) ->
        SIP.Context.from(sip_ctx)

      (req = stored_message(sip_ctx)) != nil ->
        req.to

      true ->
        raise "send_page: no sender — pass from:, or configure username and domain"
    end
  end

  defp target_label(%SIP.Uri{} = uri), do: to_string(uri)
  defp target_label(to), do: to

  defp normalize(:ignore), do: :ok
  defp normalize(rc), do: rc
end

defmodule SIP.Session.Page.Relay do
  @moduledoc """
  The process owning the dialog of one outbound page: it starts the dialog, waits
  for the final response and tells the scenario as a `{:page, …}` event, then
  ends — which ends the dialog too (it watches its application).

  A process of its own because the scenario's mailbox is read by patterns: the
  dialog delivers `{code, rsp, tid, dlg}` tuples, the same ones an INVITE's
  responses arrive as, and a script would have to tell them apart by Call-ID.

  When the scenario is traced, the relay is adopted into its trace before the
  dialog exists (`SIP.Scenario.SipTrace.delegate/2`), so the MESSAGE and its answer
  land in the scenario's journal, under the leg `page`.
  """

  require Logger

  # Every message the dialog sends the relay is wrapped with this tag.
  @tag :page

  # How long past the dialog timeout the relay waits for anything at all before
  # reporting a failure: the transaction layer answers a lost MESSAGE with a 408
  # after 64*T1 (32 s), well within it.
  @margin_ms 5_000

  @doc """
  Send `req` from a relay reporting to the calling process. Returns once the
  relay is running; the outcome arrives as a message.
  """
  @spec start(map(), binary(), pos_integer(), boolean()) :: {:ok, pid()}
  def start(req, to, timeout, debug) do
    owner = self()
    relay = spawn(fn -> init(owner, req, to, timeout, debug) end)
    # Before the dialog exists: the dialog binds to its application on creation,
    # and the MESSAGE goes out from inside that creation.
    :ok = SIP.Scenario.SipTrace.delegate(relay, @tag)
    send(relay, :go)
    {:ok, relay}
  end

  defp init(owner, req, to, timeout, debug) do
    ref = Process.monitor(owner)

    receive do
      :go -> :ok
      {:DOWN, ^ref, :process, _pid, _reason} -> exit(:normal)
    end

    case SIP.Dialog.start_dialog(req, timeout, :outbound, debug, tag: @tag) do
      {:ok, _dialog_pid, _dialog_id} ->
        await(owner, ref, to, timeout * 1_000 + @margin_ms)

      {:error, reason} ->
        failed(owner, to, reason)

      other ->
        failed(owner, to, other)
    end
  end

  defp await(owner, ref, to, wait_ms) do
    receive do
      {@tag, {code, rsp, _tid, _dlg}} when is_integer(code) and code >= 200 ->
        send(owner, {:page, :answered, %{code: code, reason: rsp.reason, to: to, response: rsp}})

      {@tag, {:dialog_terminated, _dlg, reason}} ->
        failed(owner, to, reason)

      {:DOWN, ^ref, :process, _pid, _reason} ->
        :ok

      # provisionals, {:onnewdialog, …}
      {@tag, _other} ->
        await(owner, ref, to, wait_ms)
    after
      wait_ms -> failed(owner, to, :timeout)
    end
  end

  defp failed(owner, to, reason) do
    Logger.info(module: __MODULE__, message: "Page to #{to} not sent: #{inspect(reason)}")
    send(owner, {:page, :failed, %{reason: reason, to: to}})
  end
end
