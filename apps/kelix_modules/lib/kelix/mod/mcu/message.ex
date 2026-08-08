defmodule Kelix.Mod.Mcu.Message do
  @moduledoc """
  The collaboration channel between the participants' scripts (design
  `docs/design/mcu_module.md` §20).

  A participant's script says something to its peers' scripts — a raised hand, a
  floor-control token, "I am sharing my screen". This module is the **bus**: it
  validates, addresses, rate-limits and fans out. It never writes on the wire, and it
  never renders anything into the mix — the recipient's *scenario* decides what a
  delivered message becomes (an in-dialog MESSAGE, an INFO, a state change, nothing),
  because it alone owns the SIP dialog and knows what its UA understands (§20.2).

  **This is signalling, not text.** T.140 real-time text is mixed by the media server
  for every leg that negotiated `m=text`, and that is what a Total Conversation client
  displays. Anything a human is meant to read as text in the call belongs there; this
  channel carries application state between scripts (§20.1).

  ## Where the work happens

  The roster is read straight from the registry's ETS table and **the fan-out runs in
  the sender's own process**: routing every message through the `Kelix.Mod.Mcu`
  GenServer would put a round-trip on the process that also serialises creates,
  updates and the recovery paths, for a message that needs none of its state.

  The counters that bound the channel therefore cannot live in the registry's tables,
  which are `:protected` — only their owner writes. They get one `:public` table,
  created by `Kelix.Mod.Mcu.init/1`, holding **nothing but counters**:

      {{:tokens, conf_uid, sender_ref}, tokens, last_refill_ms}   # the rate bucket
      {{:seq, conf_uid}, n}                                       # per-conference sequence
      {{:seen, conf_uid, msg_id}, expires_at_ms}                  # the loop guard
      {:settings, %{rate:, max_bytes:, queue_max:, kinds:}}       # the bounds, read per send

  No payload, no roster, no state another surface reads — which is what makes a public
  table acceptable here rather than a hole in §5. Each rate bucket also has exactly
  **one writer**: it is keyed by the sender's `ref`, and only that participant's own
  scenario process ever sends as it, so its read-modify-write needs no lock.
  """

  require Logger

  alias Kelix.Mod.Mcu.{Conference, Config, Event}

  @table :kelix_mcu_bus

  # How long a fanned-out `msg_id` is remembered for the loop guard (§20.5 G-7). Long
  # enough to catch a rebroadcast, short enough that the table cannot grow with a call.
  @seen_ttl_ms 60_000

  @type target :: :all | :others | {:part_id, pos_integer} | {:name, String.t()}
  @type report :: %{delivered: non_neg_integer, skipped: [%{part_id: term, reason: atom}]}

  # ── the table ────────────────────────────────────────────────────────────────

  @doc "Create the public counter table. Called once, by `Kelix.Mod.Mcu.init/1`."
  @spec create_table(Config.t()) :: :ok
  def create_table(%Config{} = config) do
    :ets.new(@table, [:set, :public, :named_table, write_concurrency: true])
    put_settings(config)
    :ok
  end

  @doc "Publish the bounds a send reads (`init/1`, and any later config change)."
  @spec put_settings(Config.t()) :: :ok
  def put_settings(%Config{} = config) do
    :ets.insert(
      @table,
      {:settings,
       %{
         rate: config.message_rate,
         max_bytes: config.message_max_bytes,
         queue_max: config.message_queue_max,
         kinds: config.message_kinds
       }}
    )

    :ok
  end

  @doc "Drop a participant's counters (its row is gone, §9.3)."
  @spec forget_participant(String.t(), reference) :: :ok
  def forget_participant(conf_uid, ref) do
    if alive?(), do: :ets.delete(@table, {:tokens, conf_uid, ref})
    :ok
  end

  @doc "Drop everything a conference held here (destroy, MCU loss)."
  @spec forget_conference(String.t()) :: :ok
  def forget_conference(conf_uid) do
    if alive?() do
      :ets.match_delete(@table, {{:tokens, conf_uid, :_}, :_, :_})
      :ets.match_delete(@table, {{:seen, conf_uid, :_}, :_})
      :ets.delete(@table, {:seq, conf_uid})
    end

    :ok
  end

  # ── sending ──────────────────────────────────────────────────────────────────

  @doc """
  Fan `payload` out to `target` on behalf of `sender` (a live participant row of
  `conf`).

  Returns `{:ok, %{delivered: n, skipped: [...]}}` — `delivered` counts the
  **scenarios the message was handed to**, not the UAs that received something and
  certainly not the humans who saw it (§20.7). Every recipient the bus declined to
  send to comes back in `skipped` with the reason, so the count never overstates.

  `opts`:

    * `msg_id:` — reuse the id of a message being forwarded, which is what makes the
      loop guard work: the bus refuses to fan out an id it has already fanned out;
    * `include_ringing: true` — also address the legs that are still negotiating.
      Rarely right: such a script is mid-answer and has no mix yet.
  """
  @spec send(Conference.t(), Conference.participant(), target, String.t(), binary, keyword) ::
          {:ok, report}
          | {:error,
             :no_such_target
             | :ambiguous_target
             | :rate_limited
             | :too_large
             | :bad_payload
             | :unknown_kind
             | :channel_closed
             | :duplicate_message}
  def send(%Conference{} = conf, sender, target, kind, payload, opts \\ []) do
    settings = settings()

    with :ok <- check_kind(kind, settings),
         :ok <- check_payload(payload, settings),
         {:ok, recipients} <- resolve(conf, sender, target, opts),
         {:ok, msg_id} <- claim_msg_id(conf.uid, Keyword.get(opts, :msg_id)),
         :ok <- take_token(conf.uid, sender.ref, settings.rate) do
      envelope = envelope(conf, sender, kind, payload, msg_id)
      report = fan_out(recipients, envelope, settings)

      Event.emit(:"participant.message", conf.uid, %{
        from_part_id: sender.part_id,
        kind: kind,
        # the size, never the payload: this event is logged and metered (§20.5 G-10)
        size: byte_size(payload),
        delivered: report.delivered
      })

      {:ok, report}
    end
  end

  # ── validation (§20.5 G-5) ───────────────────────────────────────────────────

  defp check_kind(_kind, %{kinds: []}), do: {:error, :channel_closed}

  defp check_kind(kind, %{kinds: kinds}) when is_binary(kind) do
    if kind in kinds, do: :ok, else: {:error, :unknown_kind}
  end

  defp check_kind(_kind, _settings), do: {:error, :unknown_kind}

  # Refused whole, never truncated: half a message is a message whose meaning nobody
  # can state, and a script that gets one back cannot tell it was cut.
  defp check_payload(payload, %{max_bytes: max}) when is_binary(payload) do
    cond do
      byte_size(payload) > max -> {:error, :too_large}
      not String.valid?(payload) -> {:error, :bad_payload}
      true -> :ok
    end
  end

  defp check_payload(_payload, _settings), do: {:error, :bad_payload}

  # ── addressing (§20.4) ───────────────────────────────────────────────────────

  defp resolve(conf, sender, target, opts) do
    include_ringing? = Keyword.get(opts, :include_ringing, false)

    case target do
      :all ->
        {:ok, addressable(conf, include_ringing?)}

      :others ->
        {:ok, Enum.reject(addressable(conf, include_ringing?), &(&1.ref == sender.ref))}

      {:part_id, part_id} ->
        one(Conference.by_part_id(conf, part_id))

      {:name, name} ->
        case Conference.by_name(conf, name) do
          {:ok, row} -> {:ok, [row]}
          :error -> {:error, :no_such_target}
          {:ambiguous, _ids} -> {:error, :ambiguous_target}
        end

      _other ->
        {:error, :no_such_target}
    end
  end

  defp one(nil), do: {:error, :no_such_target}
  defp one(row), do: {:ok, [row]}

  # §20.5 G-8: a `:ringing` leg is mid-negotiation and a `:leaving` one is winding
  # down. Neither is a peer to collaborate with unless the caller insists.
  defp addressable(conf, include_ringing?) do
    states = if include_ringing?, do: [:connected, :ringing], else: [:connected]
    Enum.filter(Conference.participants(conf), &(&1.state in states))
  end

  # ── the loop guard (§20.5 G-7) ───────────────────────────────────────────────

  defp claim_msg_id(conf_uid, nil), do: claim_msg_id(conf_uid, new_msg_id())

  defp claim_msg_id(conf_uid, msg_id) when is_binary(msg_id) do
    key = {:seen, conf_uid, msg_id}
    expires = now_ms() + @seen_ttl_ms

    if :ets.insert_new(@table, {key, expires}) do
      {:ok, msg_id}
    else
      # a live id: this is the second fan-out of the same message, i.e. the storm a
      # rebroadcasting script starts. An expired one is simply reclaimed.
      case :ets.lookup(@table, key) do
        [{^key, stale}] when stale <= expires - @seen_ttl_ms ->
          :ets.insert(@table, {key, expires})
          {:ok, msg_id}

        _ ->
          {:error, :duplicate_message}
      end
    end
  end

  defp claim_msg_id(_conf_uid, _msg_id), do: {:error, :bad_payload}

  defp new_msg_id(), do: "m-" <> (:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower))

  # ── the rate bucket (§20.5 G-4) ──────────────────────────────────────────────

  # A decayed token bucket, `rate` per second, burst `2 x rate`. Read-modify-write
  # without a lock on purpose: the key is the *sender's* ref and the fan-out runs in
  # that participant's own scenario process, so this key has exactly one writer.
  defp take_token(conf_uid, ref, rate) when rate > 0 do
    key = {:tokens, conf_uid, ref}
    burst = rate * 2
    now = now_ms()

    {tokens, last} =
      case :ets.lookup(@table, key) do
        [{^key, tokens, last}] -> {tokens, last}
        [] -> {burst, now}
      end

    # Only advance `last` by the time the tokens actually cost: advancing it to `now`
    # would truncate every sub-token interval away, and a steady fast sender would
    # never refill at all.
    gained = div((now - last) * rate, 1000)
    last = if gained > 0, do: last + div(gained * 1000, rate), else: last
    tokens = min(burst, tokens + gained)

    if tokens >= 1 do
      :ets.insert(@table, {key, tokens - 1, last})
      :ok
    else
      :ets.insert(@table, {key, tokens, last})
      {:error, :rate_limited}
    end
  end

  # rate 0 = the channel is rate-closed; kept explicit rather than dividing by zero
  defp take_token(_conf_uid, _ref, _rate), do: {:error, :rate_limited}

  # ── the envelope (§20.4, §20.5 G-9) ──────────────────────────────────────────

  defp envelope(conf, sender, kind, payload, msg_id) do
    %{
      msg_id: msg_id,
      seq: :ets.update_counter(@table, {:seq, conf.uid}, {2, 1}, {{:seq, conf.uid}, 0}),
      from: %{part_id: sender.part_id, display_name: display_name(sender)},
      kind: kind,
      payload: payload,
      sent_at: DateTime.utc_now()
    }
  end

  # Never the AOR (§20.5 G-9). A leg that set no display name falls back to the user
  # part of its name, which is what the other participants heard it announce anyway —
  # and still not the routable address.
  defp display_name(%{display_name: name}) when is_binary(name) and name != "", do: name
  defp display_name(%{name: name}) when is_binary(name), do: hd(String.split(name, "@"))
  defp display_name(_row), do: nil

  # ── delivery (§20.5 G-2, G-3, G-8) ───────────────────────────────────────────

  defp fan_out(recipients, envelope, settings) do
    {delivered, skipped} =
      Enum.reduce(recipients, {0, []}, fn row, {delivered, skipped} ->
        case deliver(row, envelope, settings) do
          :ok -> {delivered + 1, skipped}
          {:skipped, reason} -> {delivered, [%{part_id: row.part_id, reason: reason} | skipped]}
        end
      end)

    %{delivered: delivered, skipped: Enum.reverse(skipped)}
  end

  defp deliver(row, envelope, settings) do
    cond do
      # G-2: the whole reason the channel does not leak. An `on_events` block is a
      # plain receive, so a message no clause matches sits in that mailbox for the
      # rest of the call — which on a conference leg is hours.
      not Map.get(row, :accepts_messages, false) ->
        {:skipped, :not_accepted}

      not (is_pid(row.scenario) and Process.alive?(row.scenario)) ->
        {:skipped, :no_scenario}

      queue_len(row.scenario) > settings.queue_max ->
        {:skipped, :backpressure}

      true ->
        Kernel.send(row.scenario, {:mcu_message, envelope})
        :ok
    end
  end

  defp queue_len(pid) do
    case Process.info(pid, :message_queue_len) do
      {:message_queue_len, len} -> len
      nil -> 0
    end
  end

  # ── settings, table plumbing ─────────────────────────────────────────────────

  # Read per send, from the public table rather than from the GenServer: the whole
  # point of §20.6 is that a message costs no round-trip. A node whose table is not
  # there yet (a test driving the bus without the module) reads a closed channel.
  defp settings() do
    case alive?() && :ets.lookup(@table, :settings) do
      [{:settings, settings}] -> settings
      _ -> %{rate: 0, max_bytes: 0, queue_max: 0, kinds: []}
    end
  end

  defp alive?(), do: :ets.whereis(@table) != :undefined

  defp now_ms(), do: System.monotonic_time(:millisecond)
end
