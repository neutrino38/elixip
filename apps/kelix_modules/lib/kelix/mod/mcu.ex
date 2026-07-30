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

  alias Kelix.Mod.Mcu.{Args, Client, Conference, Config, Event}
  alias Kelix.Mod.Mcu.Supervisor, as: McuSupervisor

  @conf_table :kelix_mcu_conferences
  @did_table :kelix_mcu_dids
  @mcu_table :kelix_mcu_servers

  # A control command may sit behind two MCU round-trips (CreateConference +
  # SetCompositionType); the RPCs are themselves bounded by xmlrpc_timeout_ms.
  @control_timeout_ms 30_000

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
      exports: [lookup_did: 2, conference: 1, mediaserver: 1]
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

    {:ok, %{config: config, module_name: Keyword.get(opts, :module_name, "mcu")}}
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

  def handle_info(_msg, state), do: {:noreply, state}

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
        end

        state

      :error ->
        Logger.warning(module: __MODULE__, message: "health for unknown mcu #{inspect(name)}")
        state
    end
  end

  # ── MCU events (§3.7) ────────────────────────────────────────────────────────

  # The `tag` is the conference uid — that is what makes an event routable back to
  # a conference without keeping an MCU-side id map. Per-participant routing to the
  # owning scenario lands with the call path (P2).
  defp handle_mcu_event(_state, mcu_name, event) do
    tag = event_tag(event)

    case tag && conference(tag) do
      {:ok, conf} ->
        log_event(conf, event)

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

  defp log_event(conf, {:fpu_requested, _conf_id, _tag, part_id}) do
    Event.emit(:"participant.fpu_requested", conf.uid, %{part_id: part_id})
  end

  defp log_event(conf, event) do
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
