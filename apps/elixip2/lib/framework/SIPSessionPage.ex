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
          (60 by default);
        * `:ref` — any term, echoed as `ref:` in the `{:page, …}` event: what
          tells the answers of several pages in flight apart, and what
          `SIP.Session.Page.abandon_pages/1` silences them by;
        * `:leg` — the label of the page's lane in the journal (`page` by
          default).
      """
      @doc """
      Set this conversation aside and end the instance: what `opts` names is
      kept, and the next MESSAGE between the same two parties — over whatever
      flow — resumes the script at `:resume` with it (chat-basic-plan, C3d).

        * `:resume` — the state to resume in (required);
        * `:keep` — the appdata keys to keep; their values must be plain data,
          a pid, a reference, a port or a function is refused;
        * `:ttl` — how long to keep it, in seconds, bounded by the node.

      A transition: the instance ends successfully once the node has kept the
      conversation, as a failure when it could not (not a conversation, no
      `conversation` module, a value that is not plain data).
      """
      defmacro hibernate(opts) do
        quote do
          SIP.Session.Page.do_hibernate(
            var!(sip_ctx),
            unquote(opts),
            Process.get(:scenario_event_type)
          )
        end
      end

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

    {:ok, relay} =
      SIP.Session.Page.Relay.start(
        req,
        target_label(to),
        timeout,
        sip_ctx.debug,
        Keyword.take(opts, [:ref, :leg])
      )

    if Keyword.has_key?(opts, :ref), do: track(opts[:ref], relay)
    note_activity(sip_ctx)
    SIP.Context.set(sip_ctx, :lasterr, :ok)
  end

  # The relays started with a `:ref`, by the process that started them — the
  # instance itself, so its dictionary rather than a table of the node's. A relay
  # that has ended has nothing left to silence.
  @relays {__MODULE__, :relays}

  @doc """
  Silence the pages in flight sent with one of `refs` as their `:ref`: their
  answers will not be reported, and those already in the mailbox are taken out
  of it.

  For a sender that has made up its mind before every page is answered — a fan-out
  that won on the first 200 — and would otherwise find the late answers in its
  mailbox, where the next fan-out, or a clause matching `{:page, …}`, would take
  them for its own. The pages themselves are not stopped: a MESSAGE cannot be
  cancelled, and each one's transaction still ends, in the journal, as it
  happens.
  """
  @spec abandon_pages([term()]) :: :ok
  def abandon_pages(refs) when is_list(refs) do
    {abandoned, kept} = Enum.split_with(tracked(), fn {ref, _relay} -> ref in refs end)
    Process.put(@relays, kept)

    # An answer sent before its relay was muted precedes the relay's
    # acknowledgement, so once every relay has acknowledged, none is still on
    # its way — and each relay reports once at most.
    Enum.each(abandoned, fn {_ref, relay} -> SIP.Session.Page.Relay.mute(relay) end)
    Enum.each(refs, &flush_answer/1)
  end

  defp flush_answer(ref) do
    receive do
      {:page, _outcome, %{ref: ^ref}} -> :ok
    after
      0 -> :ok
    end
  end

  defp tracked,
    do: @relays |> Process.get([]) |> Enum.filter(fn {_ref, pid} -> Process.alive?(pid) end)

  defp track(ref, relay), do: Process.put(@relays, [{ref, relay} | tracked()])

  # ── Conversations ───────────────────────────────────────────────────────────

  @doc """
  What an instance serving a **conversation** does with an event, before the
  scenario's clause runs (called by `SIP.FSL.Host.on_event/2`).

  A conversation is one instance for many MESSAGEs (chat-basic-plan, C3b): each
  arrives on a dialog and a transaction of its own, which crossed the node
  before this instance was told. The first is written in the journal when the
  journal starts, like any UAS instance's inbound request; the next ones are
  written here, as they arrive, so a traced conversation shows every message it
  received — redacted like every SIP message the journal holds.
  """
  @spec note_event(%SIP.Context{}, term()) :: %SIP.Context{}
  def note_event(sip_ctx = %SIP.Context{}, {:MESSAGE, req, _trans, _dlg}) when is_map(req) do
    if SIP.Scenario.SequenceJournal.enabled?() and not SIP.Msg.Ops.in_dialog?(req) and
         req != SIP.Context.appdata_get(sip_ctx, :inbound_request) do
      with %{} = event <- SIP.Scenario.SipTrace.event(:in, req),
           do: SIP.Scenario.SequenceJournal.record(event)
    end

    sip_ctx
  end

  def note_event(sip_ctx, _event), do: sip_ctx

  @doc false
  # Backs `hibernate/1`. The node keeps the conversation — the instance's parent,
  # which keyed it, asked the `conversation` module to store it and answers how
  # long it granted — and the instance ends. Nothing is kept by the instance
  # itself: it is about to be gone.
  @spec do_hibernate(%SIP.Context{}, keyword(), atom() | nil) :: tuple()
  def do_hibernate(sip_ctx = %SIP.Context{}, opts, event_type) when is_list(opts) do
    resume = Keyword.fetch!(opts, :resume)
    keep = Keyword.get(opts, :keep, [])
    data = Map.new(keep, &{&1, SIP.Context.appdata_get(sip_ctx, &1)})

    with :ok <- conversation?(sip_ctx),
         :ok <- plain_data(data),
         {:ok, ttl} <- set_aside(sip_ctx, %{resume: resume, data: data, ttl: opts[:ttl]}) do
      {:terminal, :success, "hibernated for #{ttl} s", event_type, sip_ctx}
    else
      {:error, reason} ->
        Logger.warning(module: __MODULE__, message: "hibernate refused: #{inspect(reason)}")
        {:terminal, :failure, {:hibernate, reason}, event_type, sip_ctx}
    end
  end

  defp conversation?(sip_ctx) do
    if SIP.Context.appdata_get(sip_ctx, :conversation) != nil and
         is_pid(Map.get(sip_ctx, :parent_pid)),
       do: :ok,
       else: {:error, :not_a_conversation}
  end

  # What wakes must be what was kept: a pid, a reference, a port or a function
  # means nothing to the process that resumes — let alone after a restart.
  defp plain_data(data) do
    case Enum.find(data, fn {_key, value} -> not plain?(value) end) do
      nil -> :ok
      {key, _value} -> {:error, {:not_plain_data, key}}
    end
  end

  defp plain?(v) when is_pid(v) or is_reference(v) or is_port(v) or is_function(v), do: false
  defp plain?(%{} = map), do: Enum.all?(map, fn {k, v} -> plain?(k) and plain?(v) end)
  defp plain?(list) when is_list(list), do: Enum.all?(list, &plain?/1)
  defp plain?(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> plain?()
  defp plain?(_scalar), do: true

  defp set_aside(sip_ctx, snapshot) do
    GenServer.call(sip_ctx.parent_pid, {:conversation, :hibernate, self(), snapshot})
  catch
    :exit, _ -> {:error, :no_parent}
  end

  # A conversation ends after `idle_timeout` seconds with no MESSAGE in or out.
  # The node sees every one that comes in — it routes them — but not the pages
  # the instance sends, so the instance says so to whoever spawned it. Only a
  # conversation instance does: the key is in its context because the node put
  # it there, and an instance nobody keyed has nobody listening.
  defp note_activity(sip_ctx) do
    parent = Map.get(sip_ctx, :parent_pid)

    if is_pid(parent) and SIP.Context.appdata_get(sip_ctx, :conversation) != nil,
      do: send(parent, {:conversation, :activity, self()})

    :ok
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
  land in the scenario's journal, under the leg `page` — or the `:leg` it was
  given, one per device when a fan-out sends several.
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

  Options: `:ref`, echoed in the outcome's data; `:leg`, the journal label.
  """
  @spec start(map(), binary(), pos_integer(), boolean(), keyword()) :: {:ok, pid()}
  def start(req, to, timeout, debug, opts \\ []) do
    owner = self()
    report = if Keyword.has_key?(opts, :ref), do: %{to: to, ref: opts[:ref]}, else: %{to: to}
    relay = spawn(fn -> init(owner, req, report, timeout, debug) end)
    # Before the dialog exists: the dialog binds to its application on creation,
    # and the MESSAGE goes out from inside that creation.
    :ok = SIP.Scenario.SipTrace.delegate(relay, Keyword.get(opts, :leg, @tag))
    send(relay, :go)
    {:ok, relay}
  end

  @doc """
  Stop `relay` from reporting its outcome, and return once it has said so —
  or has ended. An outcome it sent before is already in the caller's mailbox.
  The page carries on: its transaction still ends as it happens.
  """
  @spec mute(pid()) :: :ok
  def mute(relay) when is_pid(relay) do
    mref = Process.monitor(relay)
    send(relay, {:mute, self(), mref})

    receive do
      {:muted, ^mref} -> Process.demonitor(mref, [:flush])
      {:DOWN, ^mref, :process, _pid, _reason} -> :ok
    end

    :ok
  end

  defp init(owner, req, report, timeout, debug) do
    ref = Process.monitor(owner)

    receive do
      :go -> :ok
      {:DOWN, ^ref, :process, _pid, _reason} -> exit(:normal)
    end

    case SIP.Dialog.start_dialog(req, timeout, :outbound, debug, tag: @tag) do
      {:ok, _dialog_pid, _dialog_id} ->
        await(owner, ref, report, timeout * 1_000 + @margin_ms)

      {:error, reason} ->
        failed(owner, report, reason)

      other ->
        failed(owner, report, other)
    end
  end

  # `owner` is nil once muted: the relay still waits for the answer — its dialog
  # ends with it, and the journal shows it — but tells nobody.
  defp await(owner, ref, report, wait_ms) do
    receive do
      {@tag, {code, rsp, _tid, _dlg}} when is_integer(code) and code >= 200 ->
        tell(
          owner,
          {:page, :answered, Map.merge(report, %{code: code, reason: rsp.reason, response: rsp})}
        )

      {@tag, {:dialog_terminated, _dlg, reason}} ->
        failed(owner, report, reason)

      {:mute, from, mref} ->
        send(from, {:muted, mref})
        await(nil, ref, report, wait_ms)

      {:DOWN, ^ref, :process, _pid, _reason} ->
        :ok

      # provisionals, {:onnewdialog, …}
      {@tag, _other} ->
        await(owner, ref, report, wait_ms)
    after
      wait_ms -> failed(owner, report, :timeout)
    end
  end

  defp failed(owner, report, reason) do
    Logger.info(module: __MODULE__, message: "Page to #{report.to} not sent: #{inspect(reason)}")
    tell(owner, {:page, :failed, Map.put(report, :reason, reason)})
  end

  defp tell(nil, _outcome), do: :ok
  defp tell(owner, outcome), do: send(owner, outcome)
end
