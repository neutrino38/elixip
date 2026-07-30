defmodule Kelix.Mod.Mcu do
  @moduledoc """
  The conferencing (MCU) module — conference registry and control surface
  (design `docs/design/mcu_module.md` §5, §8).

  Delivered as a loadable `Kelix.Module`: `validate_config/1`, `child_spec/2`,
  `describe/0`, plus the REST + CLI commands of §8.3.3 declared once in
  `describe_control/0`. Its `child_spec/2` is the supervisor of §4.1
  (`Kelix.Mod.Mcu.Supervisor`): this registry, then one `{Client, EventQueue}` pair
  per configured media server.

  ## What lives where

  Conferences are held in **ETS**, not in this process's state: the hot path is one
  DID lookup per INVITE and it must not queue behind a `CreateConference` waiting on
  an MCU. Reads (`lookup_did/2`, `conference/1`, `mediaserver/1`) go straight to the
  tables; **writes go through this GenServer**, which is what serialises "create a
  conference" against the media server and makes DID allocation collision-free (§5.3)
  — two concurrent creates cannot be handed the same number.

  Conferences live in memory only: a kelixip restart loses them (§1.3, L5), and the
  MCU-side leftovers are garbage-collected (§9.4, P5).

  ## Not here yet

  `reload/2` is deliberately **not** exported: without it `kelictl module reload mcu`
  gets the clean child restart `Kelix.ModuleSupervisor` falls back to, which is
  honest — it drops the live conferences instead of pretending an MCU list can be
  swapped under them (in-place reload is §8.1's own increment).
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  alias Kelix.Mod.Mcu.{Adapter, Args, Client, Conference, Config, Event}
  alias Kelix.Mod.Mcu.Supervisor, as: McuSupervisor

  @conf_table :kelix_mcu_conferences
  @did_table :kelix_mcu_dids
  @mcu_table :kelix_mcu_servers

  # A control command may sit behind two MCU round-trips (CreateConference +
  # SetCompositionType); the RPCs are themselves bounded by xmlrpc_timeout_ms.
  @control_timeout_ms 30_000

  # The facade calls a scenario instance makes hold no RPC — they only read or
  # update a row — so they are bounded tightly: a wedged registry must answer the
  # INVITE (with a 500) rather than let the caller retransmit into the void.
  @facade_timeout_ms 5_000

  # The default mosaic and the default sidebar are the only ones this increment
  # drives (§1.2, decision 6b).
  @default_mosaic 0

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    case Config.parse(config) do
      {:ok, _parsed} -> :ok
      {:error, _reason} = err -> err
    end
  end

  def validate_config(_config), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def child_spec(name, config) do
    {:ok, parsed} = Config.parse(config)

    %{
      id: __MODULE__,
      type: :supervisor,
      start: {McuSupervisor, :start_link, [[config: parsed, module_name: to_string(name)]]}
    }
  end

  @impl Kelix.Module
  def describe(),
    do: %{
      version: "1.0",
      exports: [
        admit: 2,
        attach: 1,
        leave: 1,
        leave: 2,
        send_fpu: 1,
        lookup_did: 2,
        conference: 1,
        mediaserver: 1,
        media_config: 1
      ]
    }

  # ── reads (ETS, no GenServer hop) ─────────────────────────────────────────────

  @doc "The conference `uid` designates, `:error` if there is none."
  @spec conference(String.t()) :: {:ok, Conference.t()} | :error
  def conference(uid) when is_binary(uid) do
    case lookup(@conf_table, uid) do
      {:ok, conf} -> {:ok, conf}
      :error -> :error
    end
  end

  @doc """
  The conference reachable at `did` on `domain` — the INVITE hot path (§6.1).

  A pure ETS read: one INVITE must not queue behind whatever the registry is doing.
  """
  @spec lookup_did(String.t(), String.t()) :: {:ok, Conference.t()} | :error
  def lookup_did(domain, did) when is_binary(domain) and is_binary(did) do
    with {:ok, uid} <- lookup(@did_table, {domain, did}) do
      conference(uid)
    end
  end

  def lookup_did(_domain, _did), do: :error

  @doc """
  A configured media server: `%{name, url, rtp_ip, public_ip, status, client}`.

  `rtp_ip` / `public_ip` are what the SDP answer needs (G2: the media address comes
  from configuration, the MCU API has no `GetMediaCandidates`), and `client` is the
  control channel to drive it.
  """
  @spec mediaserver(String.t()) :: {:ok, map} | :error
  def mediaserver(name) when is_binary(name), do: lookup(@mcu_table, name)

  @doc "Every configured media server, in config order."
  @spec mediaservers() :: [map]
  def mediaservers() do
    case :ets.whereis(@mcu_table) do
      :undefined -> []
      tid -> tid |> :ets.tab2list() |> Enum.map(&elem(&1, 1)) |> Enum.sort_by(& &1.name)
    end
  end

  @doc "Every conference, newest last (for `list` and for status)."
  @spec conferences() :: [Conference.t()]
  def conferences() do
    case :ets.whereis(@conf_table) do
      :undefined -> []
      tid -> tid |> :ets.tab2list() |> Enum.map(&elem(&1, 1)) |> Enum.sort_by(& &1.created_at)
    end
  end

  defp lookup(table, key) do
    case :ets.whereis(table) do
      :undefined ->
        :error

      tid ->
        case :ets.lookup(tid, key) do
          [{^key, value}] -> {:ok, value}
          [] -> :error
        end
    end
  end

  # ── facade used by mcu.exs (§8.2) ─────────────────────────────────────────────

  @doc """
  Admit an inbound INVITE into the conference its R-URI user-part designates:
  DID lookup, quota reservation and participant row, atomically (§8.2).

  Returns `{:ok, conference, participant}` — the participant being the handle the
  script passes back to `attach/1` and `leave/1` — or `{:error, :no_such_conference
  | :full | :mcu_down}`, which the script maps onto `404` / `486` / `503` (§6.5).

  It deliberately does **not** talk to the media server: the MCU-side participant is
  created by the adapter inside `create_peer_connection/3`, so its lifetime is
  exactly the adapter connection's and a crash cannot orphan it. What is reserved
  here is the *slot*.
  """
  @spec admit(String.t(), map) ::
          {:ok, Conference.t(), Conference.participant()}
          | {:error, :no_such_conference | :full | :mcu_down | :down | :timeout}
  def admit(domain, req) when is_binary(domain) and is_map(req),
    do: Kelix.Module.safe_call(__MODULE__, {:admit, domain, req}, timeout: @facade_timeout_ms)

  @doc """
  ACK-time: start sending, join the audio mixer, and mark the participant joined
  (§6.2, second half).

  The RPCs run **from the calling scenario**, not inside the registry: a conference
  filling up must not serialise its joins behind one process. Only the row update is
  serialised, which is all that needs to be.
  """
  @spec attach(Conference.participant()) :: :ok | {:error, term}
  def attach(part) when is_map(part) do
    with {:ok, row} <- participant(part),
         {:ok, medias} <- Adapter.attach(row.conn) do
      Kelix.Module.safe_call(__MODULE__, {:joined, part.conf_uid, part.ref, medias},
        timeout: @facade_timeout_ms
      )
    else
      :error -> {:error, :no_such_participant}
      {:error, _} = err -> err
    end
  end

  @doc """
  Remove a participant: tear the MCU side down, release the slot, and emit
  `participant.left` **exactly once** (§11.1 invariant 1).

  Idempotent by contract — the reference script calls it from five places, and the
  crash reaper (§9.3) from a sixth.
  """
  @spec leave(Conference.participant(), atom) :: :ok
  def leave(part, reason \\ :bye)

  def leave(part, reason) when is_map(part) do
    # close the adapter connection first: it owns the MCU-side participant
    case participant(part) do
      {:ok, row} -> Adapter.close(row.conn)
      :error -> :ok
    end

    case Kelix.Module.safe_call(__MODULE__, {:left, part.conf_uid, part.ref, reason},
           timeout: @facade_timeout_ms
         ) do
      :ok -> :ok
      # a down or wedged registry must not turn a teardown into a raised error
      {:error, _} -> :ok
    end
  end

  def leave(_part, _reason), do: :ok

  @doc "Ask the MCU for a full intra-frame from that participant (`SendFPU`)."
  @spec send_fpu(Conference.participant()) :: :ok | {:error, term}
  def send_fpu(part) when is_map(part) do
    case participant(part) do
      {:ok, row} -> Adapter.send_fpu(row.conn)
      :error -> {:error, :no_such_participant}
    end
  end

  @doc """
  The media configuration a leg of `conference` must connect to, ready to be stored
  in the context appdata as `:mediaserver_instance`.

  A conference is **pinned** to its MCU (§1.3), so the leg cannot take whatever the
  media pool would hand out: it must reach the server holding the mixer.
  """
  @spec media_config(Conference.t()) :: keyword
  def media_config(%Conference{mcu: mcu}), do: [module: Adapter, url: "mcu://" <> mcu]

  @doc "The live row of `part` (it carries the MCU-side id and the adapter connection)."
  @spec participant(Conference.participant()) :: {:ok, Conference.participant()} | :error
  def participant(%{conf_uid: uid, ref: ref}) do
    with {:ok, conf} <- conference(uid) do
      case Map.fetch(conf.participants, ref) do
        {:ok, row} -> {:ok, row}
        :error -> :error
      end
    end
  end

  def participant(_part), do: :error

  @doc false
  # Called by the adapter connection once the MCU-side participant exists, so the
  # registry can report it and reach it (mute, FPU, stats, reaping).
  @spec bind_participant(String.t(), reference, non_neg_integer, pid) :: :ok
  def bind_participant(conf_uid, ref, part_id, conn) do
    Kelix.Module.safe_call(__MODULE__, {:bind, conf_uid, ref, part_id, conn},
      timeout: @facade_timeout_ms
    )

    :ok
  end

  # ── control surface (§8.3.3) ─────────────────────────────────────────────────

  @create_args ~w(domain name did mcu vad rate audio_codecs video_codecs text_codecs
                  video layout max_participants destroy_when_empty)

  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "conference.create",
        rest: {:post, "/conferences"},
        status: 201,
        location: "/conferences/:uid",
        errors: %{
          did_in_use: 400,
          did_required: 400,
          no_did_available: 409,
          unknown_mcu: 400,
          no_mediaserver: 400,
          mcu_down: 503,
          rpc_error: 502
        },
        rw: :w,
        args: [
          %{name: "domain", required: true},
          %{name: "name", required: false},
          %{name: "did", required: false},
          %{name: "mcu", required: false},
          %{name: "vad", required: false},
          %{name: "rate", required: false},
          %{name: "audio_codecs", required: false},
          %{name: "video_codecs", required: false},
          %{name: "text_codecs", required: false},
          %{name: "video", required: false},
          %{name: "layout", required: false},
          %{name: "max_participants", required: false},
          %{name: "destroy_when_empty", required: false}
        ],
        help: "Create a conference (allocates a DID when none is given)"
      },
      %{
        name: "conference.list",
        rest: {:get, "/conferences"},
        rw: :r,
        args: [%{name: "domain", required: false}, %{name: "did", required: false}],
        help: "List the conferences, optionally filtered by domain and/or DID"
      },
      %{
        name: "conference.show",
        rest: {:get, "/conferences/:uid"},
        errors: %{not_found: 404},
        rw: :r,
        args: [%{name: "uid", required: true}],
        help: "Show one conference and its participants"
      },
      %{
        name: "conference.delete",
        rest: {:delete, "/conferences/:uid"},
        errors: %{not_found: 404, not_empty: 409, mcu_down: 503, rpc_error: 502},
        rw: :w,
        args: [%{name: "uid", required: true}, %{name: "force", required: false}],
        help: "Destroy a conference (`force` disconnects the participants first)"
      }
    ]
  end

  @impl Kelix.Module
  def handle_control(command, args) when is_map(args) do
    do_control(command, Args.normalize(args))
  rescue
    # a malformed argument must be a 400, never a dead control request
    e ->
      Logger.error(module: __MODULE__, message: "#{command} failed: #{Exception.message(e)}")
      {:error, :bad_request}
  end

  defp do_control("conference.create", args) do
    with :ok <- Args.reject_unknown(args, @create_args),
         {:ok, spec} <- create_spec(args) do
      call({:create, spec})
    end
  end

  defp do_control("conference.list", args) do
    with :ok <- Args.reject_unknown(args, ~w(domain did)),
         {:ok, domain} <- Args.string(args, "domain"),
         {:ok, did} <- Args.string(args, "did") do
      rows =
        conferences()
        |> Enum.filter(&(is_nil(domain) or &1.domain == domain))
        |> Enum.filter(&(is_nil(did) or &1.did == did))
        |> Enum.map(&Conference.render/1)

      {:ok, rows}
    end
  end

  defp do_control("conference.show", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, conf} <- found(conference(uid)) do
      {:ok,
       conf
       |> Conference.render()
       |> Map.put(
         :participants,
         Enum.map(Conference.participants(conf), &Conference.render_participant/1)
       )}
    end
  end

  defp do_control("conference.delete", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid force)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, force} <- Args.bool(args, "force", false) do
      call({:delete, uid, force})
    end
  end

  defp do_control(command, _args) do
    Logger.warning(module: __MODULE__, message: "unknown control command #{inspect(command)}")
    {:error, :unknown_command}
  end

  defp found({:ok, value}), do: {:ok, value}
  defp found(:error), do: {:error, :not_found}

  # Decode + validate the create arguments into a spec the GenServer can apply
  # without re-parsing (and without ever raising inside the registry).
  defp create_spec(args) do
    with {:ok, domain} <- Args.required_string(args, "domain"),
         {:ok, name} <- Args.string(args, "name"),
         {:ok, did} <- Args.string(args, "did"),
         {:ok, mcu} <- Args.string(args, "mcu"),
         {:ok, vad} <- Args.int(args, "vad", nil, [0, 1, 2]),
         {:ok, rate} <- Args.int(args, "rate", nil, [8000, 16_000, 32_000, 48_000]),
         {:ok, audio} <- Args.codec_list(args, "audio_codecs", nil),
         {:ok, video_codecs} <- Args.codec_list(args, "video_codecs", nil),
         {:ok, text_codecs} <- Args.codec_list(args, "text_codecs", nil),
         {:ok, max_participants} <- Args.int(args, "max_participants", nil),
         {:ok, destroy_when_empty} <- Args.bool(args, "destroy_when_empty", nil) do
      {:ok,
       %{
         domain: domain,
         name: name,
         did: did,
         mcu: mcu,
         vad: vad,
         rate: rate,
         audio_codecs: audio,
         video_codecs: video_codecs,
         text_codecs: text_codecs,
         # `video` and `layout` are merged over the configured defaults, which are
         # only known inside the GenServer — so they travel as raw args
         video: Map.get(args, "video"),
         layout: Map.get(args, "layout"),
         max_participants: max_participants,
         destroy_when_empty: destroy_when_empty
       }}
    end
  end

  defp call(request) do
    GenServer.call(__MODULE__, request, @control_timeout_ms)
  catch
    :exit, {:noproc, _} -> {:error, :down}
    :exit, _ -> {:error, :timeout}
  end

  # ── GenServer ────────────────────────────────────────────────────────────────

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    config = Keyword.fetch!(opts, :config)

    tables = [:set, :protected, :named_table, read_concurrency: true]
    :ets.new(@conf_table, tables)
    :ets.new(@did_table, tables)
    :ets.new(@mcu_table, tables)

    # Entries exist from the start, `down` until their client announces itself, so
    # `create` on an unreachable MCU is refused with a clear error instead of
    # looking like an unknown name.
    for mcu <- config.mcus do
      :ets.insert(
        @mcu_table,
        {mcu.name, Map.merge(mcu, %{status: :down, client: nil, queue_id: nil})}
      )
    end

    Logger.info(
      module: __MODULE__,
      message:
        "mcu module started: #{length(config.mcus)} media server(s) " <>
          "(#{Enum.map_join(config.mcus, ", ", & &1.name)})"
    )

    {:ok,
     %{
       config: config,
       module_name: Keyword.get(opts, :module_name, "mcu"),
       # monitor_ref => {conference uid, participant ref}: the crash reaper of §9.3
       monitors: %{}
     }}
  end

  @impl true
  def handle_call({:create, spec}, _from, state) do
    {:reply, do_create(state, spec), state}
  end

  def handle_call({:delete, uid, force}, _from, state) do
    {:reply, do_delete(state, uid, force), state}
  end

  # the configured defaults, for the phases that build on them
  def handle_call(:config, _from, state), do: {:reply, state.config, state}

  # `from` is the scenario instance: it is the process whose death must reap the
  # participant (§9.3), so it is recorded as the row's owner.
  def handle_call({:admit, domain, req}, {scenario, _tag}, state) do
    {result, state} = do_admit(state, domain, req, scenario)
    {:reply, result, state}
  end

  def handle_call({:bind, conf_uid, ref, part_id, conn}, _from, state) do
    update_participant(conf_uid, ref, &%{&1 | part_id: part_id, conn: conn})
    {:reply, :ok, state}
  end

  def handle_call({:joined, conf_uid, ref, medias}, _from, state) do
    case fetch_row(conf_uid, ref) do
      {:ok, conf, row} ->
        update_participant(conf_uid, ref, fn part ->
          %{part | state: :connected, medias: medias, joined_at: DateTime.utc_now()}
        end)

        Event.emit(:"participant.joined", conf.uid, %{
          part_id: row.part_id,
          name: row.name,
          medias: Map.new(medias, fn {media, info} -> {media, Map.get(info, :codec)} end)
        })

        {:reply, :ok, state}

      :error ->
        {:reply, {:error, :no_such_participant}, state}
    end
  end

  def handle_call({:left, conf_uid, ref, reason}, _from, state) do
    {:reply, :ok, do_leave(state, conf_uid, ref, reason)}
  end

  @impl true
  # A client announcing itself (at start and on every health transition). This is
  # a cast-shaped `send`, not a call: the client must never block on the registry.
  def handle_info({:mcu_client, name, pid, status, info}, state) do
    {:noreply, update_mcu(state, name, pid, status, info)}
  end

  def handle_info({:mcu_health, name, status, info}, state) do
    {:noreply, update_mcu(state, name, nil, status, info)}
  end

  # The event stream is the other evidence an MCU is gone (§9.2): the control
  # channel may be idle and look fine while the server has restarted.
  def handle_info({:mcu_event_stream_down, name}, state) do
    {:noreply, update_mcu(state, name, nil, :down, %{})}
  end

  def handle_info({:mcu_event, mcu_name, event}, state) do
    handle_mcu_event(state, mcu_name, event)
    {:noreply, state}
  end

  # A participant's scenario died without a clean `leave/1`: run the same teardown.
  # This is the safety net that makes "participant lifetime = adapter connection
  # lifetime" true even for a `kill` (§9.3).
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {nil, _} ->
        {:noreply, state}

      {{conf_uid, part_ref}, monitors} ->
        state = %{state | monitors: monitors}

        # the connection usually died with its scenario; when it did not, closing it
        # is what frees the MCU-side participant
        case fetch_row(conf_uid, part_ref) do
          {:ok, _conf, row} -> Adapter.close(row.conn)
          :error -> :ok
        end

        {:noreply, do_leave(state, conf_uid, part_ref, :crash)}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── admit / join / leave ─────────────────────────────────────────────────────

  defp do_admit(state, domain, req, scenario) do
    did = ruri_user(req)

    with {:ok, conf} <- did_or_reject(domain, did),
         :ok <- mcu_up(conf),
         :ok <- room_left(conf) do
      part = new_participant(conf, req, scenario)

      :ets.insert(
        @conf_table,
        {conf.uid, %Conference{conf | participants: Map.put(conf.participants, part.ref, part)}}
      )

      Event.emit(:"participant.ringing", conf.uid, %{
        name: part.name,
        from: part.from,
        did: conf.did
      })

      {{:ok, conf, part}, monitor_scenario(state, conf.uid, part)}
    else
      {:error, reason} ->
        # §11.1 invariant 2: a rejected call never emits participant.ringing, so a
        # UI can read `ringing − joined` as "abandoned before answer"
        Event.emit(:"participant.rejected", nil, %{
          domain: domain,
          did: did,
          reason: reason,
          sip_code: sip_code(reason)
        })

        {{:error, reason}, state}
    end
  end

  # The scenario instance owns the participant: its death is what triggers the
  # reaper (§9.3), so the row is only safe to hand out once it is monitored.
  defp monitor_scenario(state, conf_uid, part) do
    if is_pid(part.scenario) do
      ref = Process.monitor(part.scenario)
      %{state | monitors: Map.put(state.monitors, ref, {conf_uid, part.ref})}
    else
      state
    end
  end

  defp did_or_reject(_domain, nil), do: {:error, :no_such_conference}

  defp did_or_reject(domain, did) do
    case lookup_did(domain, did) do
      {:ok, conf} -> {:ok, conf}
      :error -> {:error, :no_such_conference}
    end
  end

  defp mcu_up(conf) do
    case mediaserver(conf.mcu) do
      {:ok, %{status: :up, client: client}} when is_pid(client) -> :ok
      _ -> {:error, :mcu_down}
    end
  end

  defp room_left(conf), do: if(Conference.full?(conf), do: {:error, :full}, else: :ok)

  defp sip_code(:no_such_conference), do: 404
  defp sip_code(:full), do: 486
  defp sip_code(:mcu_down), do: 503
  defp sip_code(_reason), do: 500

  defp new_participant(conf, req, scenario) do
    %{
      ref: make_ref(),
      part_id: nil,
      conf_uid: conf.uid,
      name: participant_name(req),
      from: from_string(req),
      scenario: scenario,
      conn: nil,
      state: :ringing,
      medias: %{},
      admitted_at: DateTime.utc_now(),
      joined_at: nil
    }
  end

  # `CreateParticipant`'s name must not contain a dot — mcuGold replaces it with
  # `_`, and so do we (§3.3).
  defp participant_name(req) do
    (from_string(req) || "unknown")
    |> String.replace(".", "_")
  end

  defp from_string(req) do
    case uri_of(Map.get(req, :from)) do
      %SIP.Uri{userpart: user, domain: domain} when is_binary(user) -> "#{user}@#{domain}"
      _ -> nil
    end
  end

  defp uri_of(%SIP.Uri{} = uri), do: uri

  defp uri_of(header) when is_binary(header) do
    case SIP.Uri.parse(header) do
      {:ok, uri} -> uri
      _ -> nil
    end
  end

  defp uri_of(_other), do: nil

  defp ruri_user(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{userpart: user} when is_binary(user) and user != "" -> user
      _ -> nil
    end
  end

  # Emitted exactly once per participant, whatever the teardown path: the row is the
  # token, and it is removed here (§11.1 invariant 1).
  defp do_leave(state, conf_uid, part_ref, reason) do
    case fetch_row(conf_uid, part_ref) do
      :error ->
        state

      {:ok, conf, row} ->
        remaining = Map.delete(conf.participants, part_ref)
        conf = %Conference{conf | participants: remaining}
        :ets.insert(@conf_table, {conf.uid, conf})

        Event.emit(:"participant.left", conf.uid, %{
          part_id: row.part_id,
          name: row.name,
          reason: reason,
          duration_ms: duration_ms(row)
        })

        state = demonitor_participant(state, part_ref)

        # §8.3.3 / §5.1: an auto-destroying conference goes away with its last
        # participant, freeing its DID for the next allocation.
        if conf.destroy_when_empty and remaining == %{} do
          destroy(conf, :empty)
        end

        state
    end
  end

  defp duration_ms(%{joined_at: nil}), do: 0

  defp duration_ms(%{joined_at: at}),
    do: DateTime.diff(DateTime.utc_now(), at, :millisecond)

  defp fetch_row(conf_uid, part_ref) do
    with {:ok, conf} <- conference(conf_uid),
         {:ok, row} <- Map.fetch(conf.participants, part_ref) do
      {:ok, conf, row}
    else
      _ -> :error
    end
  end

  defp update_participant(conf_uid, ref, fun) do
    case fetch_row(conf_uid, ref) do
      {:ok, conf, row} ->
        participants = Map.put(conf.participants, ref, fun.(row))
        :ets.insert(@conf_table, {conf.uid, %Conference{conf | participants: participants}})
        :ok

      :error ->
        :error
    end
  end

  defp demonitor_participant(state, part_ref) do
    case Enum.find(state.monitors, fn {_ref, {_uid, r}} -> r == part_ref end) do
      {monitor_ref, _} ->
        Process.demonitor(monitor_ref, [:flush])
        %{state | monitors: Map.delete(state.monitors, monitor_ref)}

      nil ->
        state
    end
  end

  # ── media server health ──────────────────────────────────────────────────────

  defp update_mcu(state, name, pid, status, info) do
    case mediaserver(name) do
      {:ok, entry} ->
        was = entry.status

        updated = %{
          entry
          | status: status,
            client: pid || entry.client,
            queue_id: Map.get(info, :queue_id)
        }

        :ets.insert(@mcu_table, {name, updated})

        cond do
          was == status ->
            :ok

          status == :up ->
            Event.emit(:"mediaserver.up", nil, %{mcu: name})

          true ->
            Event.emit(:"mediaserver.down", nil, %{mcu: name, reason: :unreachable})
            notify_mcu_lost(name)
        end

        state

      :error ->
        Logger.warning(module: __MODULE__, message: "health for unknown mcu #{inspect(name)}")
        state
    end
  end

  # Its mixer is gone, so every call on it is over: each participant's scenario is
  # told, and hangs up on its own (§9.2). Recreating the stale conferences when the
  # server comes back is the other half, and it is its own increment — but leaving
  # the calls hanging is not an option: they would hold their slots for hours with no
  # media (G3 means SIP is the only other detection there is).
  defp notify_mcu_lost(mcu_name) do
    for conf <- conferences(),
        conf.mcu == mcu_name,
        part <- Conference.participants(conf),
        is_pid(part.scenario) do
      send(part.scenario, {:mcu_event, :server_disconnected})
    end

    :ok
  end

  # ── MCU events (§3.7) ────────────────────────────────────────────────────────

  # The `tag` is the conference uid — that is what makes an event routable back to a
  # conference without keeping an MCU-side id map, and `part_id` then names the row
  # whose scenario must hear about it.
  defp handle_mcu_event(_state, mcu_name, event) do
    tag = event_tag(event)

    case tag && conference(tag) do
      {:ok, conf} ->
        route_event(conf, event)

      _ ->
        # late events after a teardown are expected, an unknown tag is not
        Logger.debug(
          module: __MODULE__,
          message: "mcu #{mcu_name}: event for unknown conference #{inspect(tag)}"
        )
    end
  end

  defp event_tag({:fpu_requested, _conf_id, tag, _part_id}), do: tag
  defp event_tag({:media_timeout, _conf_id, tag, _part_id, _media}), do: tag
  defp event_tag({:media_connected, _conf_id, tag, _part_id, _media}), do: tag
  defp event_tag(_event), do: nil

  # Of the §11.1 vocabulary, only the FPU request (and losing a media server) is any
  # use to a script — the rest are node-level observations. The script turns it into
  # an INFO carrying picture_fast_update (§6.4, P3); until then it swallows it.
  defp route_event(conf, {:fpu_requested, _conf_id, _tag, part_id}) do
    Event.emit(:"participant.fpu_requested", conf.uid, %{part_id: part_id})

    case Conference.by_part_id(conf, part_id) do
      %{scenario: scenario} when is_pid(scenario) ->
        send(scenario, {:mcu_event, :fpu_requested})

      _ ->
        Logger.debug(
          module: __MODULE__,
          message: "conference #{conf.uid}: FPU for unknown participant #{part_id}"
        )
    end
  end

  # Types 3 and 4 arrive with the server-side work of §16.1-16.2 (P7); decoded and
  # logged now, acted on then.
  defp route_event(conf, event) do
    Logger.debug(module: __MODULE__, message: "conference #{conf.uid}: #{inspect(event)}")
  end

  # ── create ───────────────────────────────────────────────────────────────────

  defp do_create(state, spec) do
    config = state.config

    with {:ok, mcu} <- pick_mcu(config, spec.mcu),
         {:ok, did, allocated?} <- pick_did(config, spec.domain, spec.did),
         {:ok, conf} <- build_conference(config, spec, mcu, did),
         {:ok, conf} <- create_on_mcu(mcu, conf) do
      :ets.insert(@conf_table, {conf.uid, conf})
      :ets.insert(@did_table, {{conf.domain, conf.did}, conf.uid})

      Event.emit(:"conference.created", conf.uid, %{
        domain: conf.domain,
        did: conf.did,
        name: conf.name,
        mcu: conf.mcu,
        conf_id: conf.conf_id,
        allocated_did?: allocated?
      })

      reply = %{uid: conf.uid, did: conf.did, conf_id: conf.conf_id, mcu: conf.mcu}

      # The module allocates DIDs; it does not edit domains.toml (§15, consequence
      # of decision 2). A DID no dial rule matches is a conference nobody can dial,
      # so the drift is reported rather than left silent.
      case dial_plan_warning(conf) do
        nil -> {:ok, reply}
        warning -> {:ok, Map.put(reply, :warning, warning)}
      end
    end
  end

  # An explicit name must exist and be up; without one, the pool is asked first
  # (§8.4: it is a tie-breaker, not the owner of the choice — a conference is
  # pinned, which is not what a per-call pool expresses).
  defp pick_mcu(_config, name) when is_binary(name) do
    case mediaserver(name) do
      {:ok, %{status: :up} = mcu} -> {:ok, mcu}
      {:ok, _down} -> {:error, :mcu_down}
      :error -> {:error, :unknown_mcu}
    end
  end

  defp pick_mcu(_config, nil) do
    entries = mediaservers()

    cond do
      entries == [] -> {:error, :no_mediaserver}
      up = pool_preference(entries) -> {:ok, up}
      up = Enum.find(entries, &(&1.status == :up)) -> {:ok, up}
      true -> {:error, :mcu_down}
    end
  end

  defp pool_preference(entries) do
    with pid when is_pid(pid) <- Process.whereis(Kelix.MediaPool),
         {:ok, %{name: name}} <- Kelix.MediaPool.checkout() do
      Enum.find(entries, &(&1.name == name and &1.status == :up))
    else
      _ -> nil
    end
  catch
    _, _ -> nil
  end

  # An explicit DID is always honoured, **including outside the range** (§5.3): the
  # range is an allocation pool, not an admission filter.
  defp pick_did(_config, domain, did) when is_binary(did) do
    if :ets.member(@did_table, {domain, did}),
      do: {:error, :did_in_use},
      else: {:ok, did, false}
  end

  defp pick_did(config, domain, nil) do
    case Config.range_for(config, domain) do
      nil ->
        {:error, :did_required}

      {lo, hi} ->
        case Enum.find(lo..hi, &(not :ets.member(@did_table, {domain, Integer.to_string(&1)}))) do
          nil -> {:error, :no_did_available}
          number -> {:ok, Integer.to_string(number), true}
        end
    end
  end

  defp build_conference(config, spec, mcu, did) do
    layout_default = %{
      comp: config.layout_comp,
      size: config.video.size,
      auto: config.auto_layout
    }

    with {:ok, video} <-
           Args.sub_map(%{"video" => spec.video}, "video", config.video, [
             :size,
             :fps,
             :bitrate,
             :intra_period
           ]),
         {:ok, layout} <-
           Args.sub_map(%{"layout" => spec.layout}, "layout", layout_default, [
             :comp,
             :size,
             :auto
           ]) do
      {:ok,
       %Conference{
         uid: new_uid(),
         name: spec.name || "conference #{did}",
         domain: spec.domain,
         did: did,
         mcu: mcu.name,
         vad: spec.vad || config.vad,
         rate: spec.rate || config.rate,
         codecs: %{
           audio: spec.audio_codecs || config.audio_codecs,
           video: spec.video_codecs || config.video_codecs,
           text: spec.text_codecs || config.text_codecs
         },
         dtmf: config.dtmf,
         video: video,
         layout: layout,
         max_participants: spec.max_participants || config.max_participants,
         destroy_when_empty:
           if(is_nil(spec.destroy_when_empty),
             do: config.destroy_when_empty,
             else: spec.destroy_when_empty
           ),
         created_at: DateTime.utc_now()
       }}
    end
  end

  # CreateConference then SetCompositionType. A failure at any step leaves
  # **nothing** registered and deletes what was created MCU-side (§9.1).
  defp create_on_mcu(%{queue_id: nil}, _conf), do: {:error, :mcu_down}

  defp create_on_mcu(mcu, conf) do
    # The queueId is passed at creation: it is what binds this conference's events
    # to the stream we poll, so creating one without it would produce a conference
    # whose FPU requests reach nobody.
    with {:ok, conf_id} <-
           rpc_create(mcu, "CreateConference", [conf.uid, conf.vad, conf.rate, mcu.queue_id]),
         conf = %Conference{conf | conf_id: conf_id},
         :ok <- set_composition(mcu, conf) do
      {:ok, conf}
    end
  end

  defp set_composition(mcu, conf) do
    case rpc(mcu, "SetCompositionType", [
           conf.conf_id,
           @default_mosaic,
           conf.layout.comp,
           conf.layout.size
         ]) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        # release what was acquired: a conference the controller does not know about
        # would sit on the MCU forever
        rpc(mcu, "DeleteConference", [conf.conf_id])
        {:error, reason}
    end
  end

  # ── delete ───────────────────────────────────────────────────────────────────

  defp do_delete(state, uid, force) do
    with {:ok, conf} <- found(conference(uid)) do
      cond do
        Conference.count(conf) > 0 and not force ->
          {:error, :not_empty}

        true ->
          disconnected = disconnect_participants(state, conf)
          destroy(conf, if(force and disconnected > 0, do: :api_force, else: :api))
          {:ok, %{uid: uid, disconnected: disconnected}}
      end
    end
  end

  # Ask every participant's scenario to hang up. We do **not** hold the registry
  # for `shutdown_grace_ms` waiting for them: the MCU-side DeleteConference below
  # removes their participants anyway, and a leg that reports back afterwards meets
  # an idempotent `leave/1`.
  defp disconnect_participants(_state, conf) do
    conf
    |> Conference.participants()
    |> Enum.count(fn part ->
      if is_pid(part.scenario) and Process.alive?(part.scenario) do
        send(part.scenario, {:scenario_ctl, :shutdown, :conference_deleted})
        true
      else
        false
      end
    end)
  end

  @doc false
  # Drop a conference: MCU side first (that is the resource that leaks), then the
  # local rows. Emitted exactly once, before the row is dropped (§11.1).
  def destroy(%Conference{} = conf, reason) do
    Event.emit(:"conference.destroyed", conf.uid, %{
      reason: reason,
      participants_at_end: Conference.count(conf)
    })

    case mediaserver(conf.mcu) do
      {:ok, mcu} -> rpc(mcu, "DeleteConference", [conf.conf_id])
      :error -> :ok
    end

    :ets.delete(@did_table, {conf.domain, conf.did})
    :ets.delete(@conf_table, conf.uid)
    :ok
  end

  # ── RPC helpers ──────────────────────────────────────────────────────────────

  defp rpc(%{client: nil}, _method, _params), do: {:error, :mcu_down}

  defp rpc(%{client: client}, method, params) do
    case Client.call(client, method, params) do
      {:ok, _} = ok -> ok
      {:error, :mcu_down} = err -> err
      {:error, reason} -> {:error, rpc_reason(reason)}
    end
  end

  defp rpc_create(%{client: nil}, _method, _params), do: {:error, :mcu_down}

  defp rpc_create(%{client: client}, method, params) do
    case Client.create(client, method, params) do
      {:ok, id} -> {:ok, id}
      {:error, :mcu_down} = err -> err
      {:error, reason} -> {:error, rpc_reason(reason)}
    end
  end

  # An RPC failure the operator can act on is a 502 (the MCU refused), not a 400
  # (the request was fine). The detail is in the logs, where it belongs.
  defp rpc_reason(reason) do
    Logger.warning(module: __MODULE__, message: "mcu rpc failed: #{inspect(reason)}")
    :rpc_error
  end

  # ── misc ─────────────────────────────────────────────────────────────────────

  defp new_uid(), do: "c-" <> (:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower))

  # Does any `calls` rule of that domain match the DID? Only the *existence* of a
  # rule is checked, not which script it points at: the module has no business
  # knowing the reference script's file name (a deployment renames it, §7).
  defp dial_plan_warning(conf) do
    with pid when is_pid(pid) <- Process.whereis(Kelix.Domains),
         %Kelix.Domain{dial_plan: rules} <-
           Kelix.Domains.lookup(Kelix.Domains.current(), conf.domain),
         false <- Enum.any?(rules, &Kelix.DialRule.matches?(&1, conf.did)) do
      message =
        "DID #{conf.did} matches no call rule on #{conf.domain}: " <>
          "nobody can dial this conference until domains.toml routes it"

      Logger.warning(module: __MODULE__, message: message)
      message
    else
      _ -> nil
    end
  end
end
