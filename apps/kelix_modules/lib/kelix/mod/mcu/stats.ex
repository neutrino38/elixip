defmodule Kelix.Mod.Mcu.Stats do
  @moduledoc """
  The per-participant statistics sweep behind the `{:kelix_conference_stats, uid,
  sample}` topic (contract `docs/design/mcu-live-push.md`).

  `GetParticipantStatistics` is per participant — the media server exposes no
  conference-wide statistics RPC — so one sweep of one conference is one RPC per
  connected leg. Hence the three rules this process exists for:

    * **nothing is polled without a subscriber.** No expanded panel, no RPC, no
      work: `Push.watched_stats/0` is the whole work list.
    * **its own process.** Not the registry, which must never sit behind a sweep
      while an INVITE waits for `admit/2`; and not `Kelix.Metrics.Poller`, although
      it already ticks at 15 s and is the node's one sampling clock — it is core
      code that runs whether or not metrics are enabled, and a sweep of up to
      N × `xmlrpc_timeout_ms` inside it would stall the node's own sampling.
    * **a sweep never piles up.** The next tick is scheduled when the current sweep
      returns, so a slow media server shows up as older numbers (`since_ms` says how
      old) instead of a growing queue. The sweep shares the MCU's control channel
      with call setup, which is the real cost of the topic and the reason it is
      subscription-gated.

  The rates are derived here, from the previous sample this process keeps: every
  consumer wants the same arithmetic, and a UI computing it itself would show nothing
  after a page reload. The counters themselves are passed through as the server gave
  them (§16.3 — what the media server knows about itself, the media server is asked;
  a rate is arithmetic, not a server fact).
  """
  use GenServer
  require Logger

  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Config, Push}

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Sweep one conference now, out of band (a panel that just expanded).

  A cast: `subscribe_conference_stats/2` must return without waiting for an RPC, and
  a panel showing nothing for a whole period is what an operator reads as broken.
  """
  @spec sweep(String.t()) :: :ok
  def sweep(uid) when is_binary(uid), do: GenServer.cast(__MODULE__, {:sweep, uid})

  @impl true
  def init(opts) do
    %Config{stats_interval_ms: interval} = Keyword.fetch!(opts, :config)

    if interval > 0, do: schedule(interval)

    # {uid, part_id} => %{at_ms, medias}: the previous sample, and the only state
    # here — dropped for a leg nobody watches any more on the next full tick
    {:ok, %{interval: interval, last: %{}}}
  end

  @impl true
  def handle_cast({:sweep, uid}, state) do
    {:noreply, %{state | last: sweep_one(uid, state.last, state.interval)}}
  end

  @impl true
  def handle_info(:tick, state) do
    watched = Push.watched_stats()

    last =
      Enum.reduce(watched, state.last, &sweep_one(&1, &2, state.interval))

    # Forget the legs and conferences nobody watches any more: the full tick is the
    # only place that can tell, and a map keyed on every leg ever swept would be a
    # slow leak on a busy node.
    kept = for {{uid, _part} = key, v} <- last, uid in watched, into: %{}, do: {key, v}

    schedule(state.interval)
    {:noreply, %{state | last: kept}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── the sweep ────────────────────────────────────────────────────────────────

  defp sweep_one(uid, last, interval) do
    case Mcu.conference(uid) do
      :error ->
        last

      {:ok, conf} ->
        at_ms = System.monotonic_time(:millisecond)

        {rows, last} =
          conf
          |> Push.roster()
          |> Enum.filter(&(&1.state == :connected and is_integer(&1.part_id)))
          |> Enum.map_reduce(last, &sample_leg(&1, &2, conf, at_ms))

        Push.stats(uid, %{
          at: DateTime.utc_now(),
          mcu: conf.mcu,
          interval_ms: interval,
          participants: rows
        })

        last
    end
  end

  defp sample_leg(part, last, conf, at_ms) do
    key = {conf.uid, part.part_id}
    previous = Map.get(last, key)

    row = %{
      part_id: part.part_id,
      name: part.name,
      state: part.state,
      since_ms: nil,
      stats: %{},
      stats_error: nil
    }

    case Mcu.participant_statistics(conf, part.part_id) do
      {:ok, medias} ->
        since_ms = previous && at_ms - previous.at_ms

        row = %{
          row
          | since_ms: since_ms,
            stats: derive(medias, previous && previous.medias, since_ms)
        }

        {row, Map.put(last, key, %{at_ms: at_ms, medias: medias})}

      {:error, reason} ->
        # Reported, never hidden: an operator reading zeros must be able to tell "no
        # media" from "no answer" — the same reason `participant.show` says so. The
        # previous sample is dropped, so the next one derives no rate across the gap.
        {%{row | stats_error: reason}, Map.delete(last, key)}
    end
  end

  # A counter that went backwards means the leg was rebuilt (a recreated conference
  # keeps its uid, §9.2): the two samples are not comparable, so the interval says
  # nothing rather than a negative rate.
  defp derive(medias, nil, _since_ms), do: Map.new(medias, fn {m, c} -> {m, no_deltas(c)} end)

  defp derive(medias, _previous, since_ms) when is_nil(since_ms) or since_ms <= 0,
    do: Map.new(medias, fn {m, c} -> {m, no_deltas(c)} end)

  defp derive(medias, previous, since_ms) do
    Map.new(medias, fn {media, counters} ->
      case Map.get(previous, media) do
        nil -> {media, no_deltas(counters)}
        before -> {media, deltas(counters, before, since_ms)}
      end
    end)
  end

  defp deltas(counters, before, since_ms) do
    recv = counters.total_recv_bytes - before.total_recv_bytes
    send = counters.total_send_bytes - before.total_send_bytes
    lost = counters.lost_recv_packets - before.lost_recv_packets

    if recv < 0 or send < 0 or lost < 0 do
      no_deltas(counters)
    else
      Map.merge(counters, %{
        # bytes × 8 / ms is kbit/s exactly, no unit conversion to get wrong
        recv_kbps: round(recv * 8 / since_ms),
        send_kbps: round(send * 8 / since_ms),
        lost_recv_delta: lost
      })
    end
  end

  defp no_deltas(counters),
    do: Map.merge(counters, %{recv_kbps: nil, send_kbps: nil, lost_recv_delta: nil})

  defp schedule(interval), do: Process.send_after(self(), :tick, interval)
end
