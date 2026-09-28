defmodule SIP.Scenario.SipTrace do
  @moduledoc """
  Cross-process sink for the SIP messages a traced scenario instance exchanges,
  feeding the scenario's `FSL.Journal` with what really went on the wire.
  `SIP.FSL.Host` plugs it in: `c:FSL.Host.journal_started/1` watches,
  `c:FSL.Host.journal_collect/0` takes.

  The journal lives in the scenario process, but the messages go through the
  dialog and transaction processes. This module bridges the two with one public
  ETS table:

    * a scenario `watch/0`es itself when its journal starts;
    * a dialog `bind/3`s itself to its application process when it learns it, and
      a scenario `adopt/1`s a dialog that existed before its journal did (a UAS
      instance is spawned by the request that created the dialog);
    * the transaction layer calls `sent/3` and `received/4` on every message it
      puts on or takes off the wire, keyed on its `app` pid — the dialog, or the
      scenario itself. A message whose `app` is bound to no watched scenario
      costs one ETS lookup.

  `take/0` hands the recorded events back to the scenario at flush time. They
  are `FSL.Journal` `:message` events (see `FSL.Diagram`): one lane per Call-ID,
  labelled with the leg tag and the peer address, the label built here — the
  renderer knows nothing of SIP.

  Zero cost when nobody traces: the table does not exist until the first
  `watch/0`, and every recording helper returns on that check. The owning
  GenServer monitors each watched scenario and drops its rows when it dies
  without flushing.
  """
  use GenServer

  @table :sip_scenario_trace

  @typedoc """
  One SIP message, as an `FSL.Journal` `:message` event. The first block is what
  the renderers draw; `method`, `code`, `reason`, `cseq` and `sdp` are the SIP
  reading of it, kept for whoever inspects the events.
  """
  @type event :: %{
          kind: :message,
          at: integer(),
          dir: :in | :out,
          lane: String.t() | nil,
          party: String.t() | nil,
          peer: String.t() | nil,
          label: String.t(),
          reply: boolean(),
          repeat: boolean(),
          method: atom() | nil,
          code: non_neg_integer() | nil,
          reason: String.t() | nil,
          cseq: String.t() | nil,
          sdp: boolean()
        }

  # ── Scenario side ───────────────────────────────────────────────────────────

  @doc "Register the calling process as a traced scenario instance."
  @spec watch() :: :ok
  def watch do
    {:ok, pid} = start()
    GenServer.call(pid, {:watch, self()})
  end

  @doc """
  Bind an already-running dialog to the calling scenario. Keeps a binding the
  dialog made itself (it knows its leg tag, this side does not).
  """
  @spec adopt(pid()) :: :ok
  def adopt(dialog_pid) when is_pid(dialog_pid) do
    case table() do
      nil -> :ok
      tab -> :ets.insert_new(tab, {{:watch, dialog_pid}, {self(), nil}})
    end

    :ok
  end

  @doc """
  Return the events recorded for the calling scenario, oldest first, and forget
  everything about it (events and bindings).
  """
  @spec take() :: [event()]
  def take do
    case table() do
      nil ->
        []

      tab ->
        events = :ets.select(tab, [{{{:event, self(), :_}, :"$1"}, [], [:"$1"]}])
        forget(tab, self())
        events
    end
  end

  # ── Dialog side ─────────────────────────────────────────────────────────────

  @doc """
  Bind `dialog_pid` to the scenario `app_pid` is traced under, with the dialog's
  leg `tag`. No-op when `app_pid` is not traced.
  """
  @spec bind(pid(), pid() | nil, atom() | nil) :: :ok
  def bind(dialog_pid, app_pid, tag) when is_pid(dialog_pid) and is_pid(app_pid) do
    with tab when tab != nil <- table(),
         {scenario, _tag} <- scenario_of(tab, app_pid) do
      :ets.insert(tab, {{:watch, dialog_pid}, {scenario, tag}})
    end

    :ok
  end

  def bind(_dialog_pid, _app_pid, _tag), do: :ok

  # ── Transaction side ────────────────────────────────────────────────────────

  @doc """
  Record a message the transaction `state` just sent: the parsed map, or the
  serialized string a retransmission re-sends (`retransmit: true`).
  """
  @spec sent(map(), map() | binary(), keyword()) :: :ok
  def sent(state, msg, opts \\ []) do
    record(state, :out, msg, {state.destip, state.destport}, opts)
  end

  @doc "Record a parsed message the transaction `state` just received."
  @spec received(map(), map(), term(), term(), keyword()) :: :ok
  def received(state, msg, remoteip, remoteport, opts \\ []) do
    peer = {remoteip || state.destip, remoteport || state.destport}
    record(state, :in, msg, peer, opts)
  end

  @doc """
  Build the event for a message without recording it — how the journal writes
  the request that spawned a UAS instance, seen before any trace was armed.
  Options: `:peer`, `:tag` (the leg), `:retransmit`.
  """
  @spec event(:in | :out, map() | binary(), keyword()) :: event() | nil
  def event(dir, msg, opts \\ []) do
    case describe(msg) do
      nil ->
        nil

      {callid, fields} ->
        repeat = Keyword.get(opts, :retransmit, false)

        Map.merge(fields, %{
          kind: :message,
          at: System.monotonic_time(:microsecond),
          dir: dir,
          lane: callid,
          party: party(Keyword.get(opts, :tag)),
          peer: Keyword.get(opts, :peer),
          label: label(fields, repeat),
          reply: is_integer(fields.code),
          repeat: repeat
        })
    end
  end

  # ── Server ──────────────────────────────────────────────────────────────────

  @impl true
  def init(:ok) do
    tab =
      :ets.new(@table, [
        :ordered_set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])

    {:ok, %{table: tab}}
  end

  @impl true
  def handle_call({:watch, pid}, _from, st) do
    Process.monitor(pid)
    :ets.insert(st.table, {{:watch, pid}, {pid, nil}})
    {:reply, :ok, st}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, st) do
    forget(st.table, pid)
    {:noreply, st}
  end

  # ── Internals ───────────────────────────────────────────────────────────────

  defp start do
    case GenServer.start(__MODULE__, :ok, name: __MODULE__) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
    end
  end

  defp table do
    case :ets.whereis(@table) do
      :undefined -> nil
      tab -> tab
    end
  end

  defp scenario_of(tab, pid) do
    case :ets.lookup(tab, {:watch, pid}) do
      [{_key, binding}] -> binding
      [] -> nil
    end
  end

  defp forget(tab, scenario) do
    :ets.select_delete(tab, [{{{:event, scenario, :_}, :_}, [], [true]}])
    :ets.match_delete(tab, {{:watch, :_}, {scenario, :_}})
  end

  defp record(state, dir, msg, peer, opts) do
    with tab when tab != nil <- table(),
         app when is_pid(app) <- Map.get(state, :app),
         {scenario, tag} <- scenario_of(tab, app),
         ev when ev != nil <-
           event(dir, msg, Keyword.merge(opts, peer: peer_label(peer, state), tag: tag)) do
      seq = :erlang.unique_integer([:monotonic, :positive])
      :ets.insert(tab, {{:event, scenario, seq}, ev})
    end

    :ok
  end

  defp peer_label({ip, port}, state) do
    "#{ip_label(ip)}:#{port}#{transport_label(Map.get(state, :tmod))}"
  end

  defp ip_label(ip) when is_tuple(ip), do: SIP.NetUtils.ip2string(ip)
  defp ip_label(ip) when is_binary(ip), do: ip
  defp ip_label(ip), do: inspect(ip)

  defp transport_label(tmod) when is_atom(tmod) and tmod != nil do
    if Code.ensure_loaded?(tmod) and function_exported?(tmod, :transport_str, 0),
      do: "/#{tmod.transport_str()}",
      else: ""
  end

  defp transport_label(_tmod), do: ""

  # A message re-sent from its serialized form is read back through the one SIP
  # parser rather than by a first-line regex of our own.
  defp describe(msgstr) when is_binary(msgstr) do
    case SIPMsg.parse(msgstr, fn _code, _errmsg, _lineno, _line -> :ok end) do
      {:ok, msg} -> describe(msg)
      _ -> nil
    end
  end

  defp describe(msg) when is_map(msg) do
    {Map.get(msg, :callid),
     %{
       method: method_of(msg),
       code: Map.get(msg, :response),
       reason: Map.get(msg, :reason),
       cseq: cseq_label(Map.get(msg, :cseq)),
       sdp: sdp?(Map.get(msg, :contenttype))
     }}
  end

  defp party(nil), do: nil
  defp party(tag), do: to_string(tag)

  # `200 OK / 1 INVITE +SDP` for a response, `INVITE #1 +SDP` for a request.
  defp label(%{code: code} = fields, repeat) when is_integer(code) do
    "#{code} #{fields.reason} / #{fields.cseq}" <> suffixes(fields, repeat)
  end

  defp label(fields, repeat) do
    cseq = if fields.cseq, do: " ##{fields.cseq |> String.split(" ") |> hd()}", else: ""
    "#{fields.method}#{cseq}" <> suffixes(fields, repeat)
  end

  defp suffixes(fields, repeat) do
    Enum.join([
      if(fields.sdp, do: " +SDP", else: ""),
      if(repeat, do: " (retransmission)", else: "")
    ])
  end

  defp method_of(%{method: method}) when is_atom(method) and method not in [false, nil],
    do: method

  defp method_of(_msg), do: nil

  defp cseq_label([num, method]), do: "#{num} #{method}"
  defp cseq_label(_cseq), do: nil

  defp sdp?(contenttype) when is_binary(contenttype), do: String.contains?(contenttype, "sdp")
  defp sdp?(_contenttype), do: false
end
