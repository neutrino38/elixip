defmodule Kelix.Mod.Mcu do
  @moduledoc """
  The conferencing (MCU) module — conference registry and control surface
  (design `docs/design/mcu_module.md` §5, §8).

  Delivered as a loadable `Kelix.Module`: `validate_config/1`, `child_spec/2`,
  `describe/0`, plus the REST + CLI commands of §8.3.3 declared once in
  `describe_control/0`. Its `child_spec/2` is the supervisor of §4.1
  (`Kelix.Mod.Mcu.Supervisor`): this registry, then one `{Client, EventQueue}` pair
  per media server.

  The media servers are **not** declared in `[module.mcu]`: they are the
  `[mediaserver.pool.*]` entries (§8.4), read once at boot by
  `mediaservers_from_pool/0`. The pool is then consulted per conference-create for
  its `enabled` switch, while the health that decides is this module's own control
  channel.

  That channel is also the fastest detector on the node — it is permanent, so it
  sees a media server die within its reconnect cycle, where the pool's periodic
  probe may be a cycle away. Every health *transition* therefore calls
  `Kelix.MediaPool.recheck/3`. That call is a trigger, not a verdict: the pool
  re-measures on its own channel and keeps owning `healthy` (`Kelix.MediaPool`).
  The direction matters — this module depends on `:kelixip`, never the reverse, so
  the core keeps working with no module loaded, only slower to notice.

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

  alias Kelix.Metrics.Emit
  alias Kelix.Mod.Mcu.{Adapter, Args, Client, Conference, Config, Event, Vocabulary}
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

  # What the context-aware facade (`admit/4`, `attach/2`, `leave/3`) answers — and
  # stores in `sip_ctx.lasterr` — when the session already runs a JSR309 media
  # session: MCU and JSR309 calls are mutually exclusive.
  @jsr309_error :jsr309_media_already_in_use

  # The default mosaic and the default sidebar are the only ones this increment
  # drives (§1.2, decision 6b).
  @default_mosaic 0
  @default_sidebar 0

  # `SetParticipantBackground` with a non-positive participant id is the *mixer's*
  # logo — the picture drawn in every empty mosaic slot (§8.3.8, `multiconf.cpp`).
  @mixer_logo_part_id 0

  # `SetParticipantDisplayName`: mosaic id `-1` targets every *existing* mosaic of
  # the conference, and ISO 15924 script code `0` picks the font from the name's
  # characters. Wire order is (confId, mosaicId, partId, name, scriptCode) —
  # `mosaicId` BEFORE `partId`, whatever older docs said (MCU-API.md §6.5).
  @all_mosaics -1
  @autodetect_script 0

  # What `recording.start` may write. The server picks the container from the
  # extension and errors on anything else, so refusing it here turns a "Could not
  # record broadcast" into a message naming the two it accepts.
  @record_extensions ~w(.mp4 .flv)

  # `Mosaic::SlotReset`: the one `holds` value that clears the pin instead of setting
  # one, so it is the one the write path has to recognise.
  @slot_reset Vocabulary.slot_wire("reset")

  # ── argument vocabularies, shared by both frontals and the facade (§17.2) ─────

  @create_args ~w(domain name did mcu vad rate audio_codecs video_codecs text_codecs
                  video layout logo max_participants destroy_when_empty)

  @update_args ~w(uid name vad rate layout video logo max_participants destroy_when_empty)

  # Fields a client may read but never send (§8.3.3). Named as read-only rather than
  # merely unknown: an operator who tries to move `conf_id` or `did` deserves to be
  # told which of the two it is.
  @conference_readonly ~w(conf_id created_at participants stale domain did mcu
                          audio_codecs video_codecs text_codecs)
  @participant_readonly ~w(name state medias joined_at conn scenario)

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
      start:
        {McuSupervisor, :start_link,
         [
           [
             config: parsed,
             module_name: to_string(name),
             mediaservers: mediaservers_from_pool()
           ]
         ]}
    }
  end

  @doc """
  The media servers this module drives: the `[mediaserver.pool.*]` entries whose
  adapter is the Medooze one (§8.4).

  Read from `Kelix.Config` rather than from `Kelix.MediaPool`, which the boot order
  starts *after* the modules — and the list is a config fact, not a pool state. The
  pool is consulted at conference-create time instead, for `enabled` and the
  round-robin.

  Only `mendooze` entries become control channels: this module speaks the MCU
  XML-RPC dialect, so a `mockup` entry would get a client retrying against a URL
  nothing answers. The ones left out are named in the log rather than dropped
  silently.
  """
  @spec mediaservers_from_pool([map]) :: [%{name: String.t(), url: String.t()}]
  def mediaservers_from_pool(entries \\ pool_entries()) do
    {mine, others} = Enum.split_with(entries, &(&1.module == :mendooze))

    if others != [] do
      Logger.info(
        module: __MODULE__,
        message:
          "mcu module ignores #{length(others)} pool entry/entries driven by another " <>
            "adapter: #{Enum.map_join(others, ", ", &"#{&1.name} (#{inspect(&1.module)})")}"
      )
    end

    Enum.map(mine, &Map.take(&1, [:name, :url]))
  end

  defp pool_entries() do
    if Process.whereis(Kelix.Config), do: Kelix.Config.current().mediaserver_pool, else: []
  end

  @impl Kelix.Module
  def describe(),
    do: %{
      version: "1.0",
      exports: [
        # conference lifecycle from a scenario (§17, P5b)
        create_conference: 2,
        ensure_conference: 3,
        update_conference: 2,
        destroy_conference: 2,
        conferences: 1,
        # the call path (§8.2)
        admit: 2,
        attach: 1,
        leave: 1,
        leave: 2,
        send_fpu: 1,
        mute: 3,
        kick: 2,
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
  A media server this module drives: `%{name, url, status, client, queue_id}`.

  `client` is the control channel to drive it and `status` our own view of that
  channel — the health a conference depends on. No media address here: the server
  reports the one to advertise on each `StartReceiving` (§16.5), so a leg needs
  nothing from this entry's configuration.
  """
  @spec mediaserver(String.t()) :: {:ok, map} | :error
  def mediaserver(name) when is_binary(name), do: lookup(@mcu_table, name)

  @doc "Every media server this module drives, in name order."
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

  # ── what the module says about itself (§11) ───────────────────────────────────

  @doc """
  One-line state for `kelictl status` (§11): conferences, participants, and how many
  of the configured media servers this module can currently reach.

  Read by `Kelix.Control.status/0` through the module registry, so the core names no
  module — anything exporting `status/0` contributes a line.
  """
  @spec status() :: map
  def status() do
    confs = conferences()
    servers = mediaservers()

    %{
      conferences: length(confs),
      participants: Enum.sum(Enum.map(confs, &Conference.count/1)),
      mediaservers: "#{Enum.count(servers, &(&1.status == :up))}/#{length(servers)} up",
      stale: Enum.count(confs, & &1.stale)
    }
  end

  @doc """
  Emit the point-in-time gauges of §11 (`kelix_mcu_conferences`,
  `kelix_mcu_participants`, `kelix_mcu_mediaserver_up`).

  Called on `Kelix.Metrics.Poller`'s tick rather than on a timer of our own: one
  sampling clock for the node, and nothing to stop when metrics are disabled — the
  telemetry calls are no-ops with no reporter attached.
  """
  @spec poll_metrics() :: :ok
  def poll_metrics() do
    confs = conferences()

    for mcu <- mediaservers() do
      Emit.mcu_mediaserver_up(mcu.name, mcu.status == :up)
      Emit.mcu_conferences(mcu.name, Enum.count(confs, &(&1.mcu == mcu.name)))
    end

    for conf <- confs do
      Emit.mcu_participants(conf.mcu, conf.uid, Conference.count(conf))
    end

    :ok
  end

  # ── conference lifecycle from a scenario (§17, P5b) ───────────────────────────

  @doc """
  Create a conference from a scenario (§17.2).

  `opts` is a keyword list with atom keys — `name:`, `did:`, `mcu:`, `vad:`, `rate:`,
  `audio_codecs:`, `video_codecs:`, `text_codecs:`, `video:`, `layout:`,
  `max_participants:`, `destroy_when_empty:`, `owner:` — validated by exactly the same
  code as the REST body of `conference.create`, so the two produce indistinguishable
  conferences (§17.2).

  ## Ownership

  `owner: :caller` (the default) hands the conference's lifetime to the **calling
  instance**: when it dies, the conference is destroyed *if it is empty*, and left
  alone if anyone joined — the creator was merely the first to arrive (§17.3). Without
  it, a script that dies before anyone joins leaks a conference permanently: the §9.4
  sweep cannot collect a row our own registry holds.

  It also covers the case where this very call times out. The registry finishes the
  creation regardless, so `{:error, :timeout}` would otherwise leave a conference
  nobody knows about; the monitor reaps it when the instance gives up and dies.

  `owner: :none` is the persistent room a script destroys explicitly.
  """
  @spec create_conference(String.t(), keyword) ::
          {:ok, Conference.t()} | {:error, atom | String.t()}
  def create_conference(domain, opts \\ []) when is_binary(domain) and is_list(opts) do
    with {:ok, spec, owner} <- create_args(domain, opts),
         {:ok, conf, _warning} <- lifecycle_call({:create, spec, owner}) do
      {:ok, conf}
    end
  end

  @doc """
  The conference on `did`, created if there is none — **atomically** (§17.4).

  Returns `{:ok, conference, :created | :existing}`. The atomicity is the point: two
  INVITEs arriving together on the same unknown DID would otherwise both see "no
  conference", both create one, and the second caller would meet `:did_in_use` while
  already ringing. Running the lookup and the creation in the registry process removes
  that race, which a script cannot fix on its own.

  A conference that already existed is **not** adopted: it outlived nothing of ours,
  so `owner:` applies only to the `:created` case.
  """
  @spec ensure_conference(String.t(), String.t(), keyword) ::
          {:ok, Conference.t(), :created | :existing} | {:error, atom | String.t()}
  def ensure_conference(domain, did, opts \\ [])
      when is_binary(domain) and is_binary(did) and is_list(opts) do
    with {:ok, spec, owner} <- create_args(domain, Keyword.put(opts, :did, did)),
         {:ok, conf, origin, _warning} <- lifecycle_call({:ensure, spec, owner}) do
      {:ok, conf, origin}
    end
  end

  @doc """
  Update a conference from a scenario: the same partial merge as
  `conference.update` (§8.3.3), with atom keys. Returns the fields that changed.
  """
  @spec update_conference(String.t(), keyword) :: {:ok, [atom]} | {:error, atom | String.t()}
  def update_conference(uid, changes) when is_binary(uid) and is_list(changes) do
    args = changes |> Args.stringify_keys() |> Map.put("uid", uid)

    with :ok <- Args.reject_readonly(args, @conference_readonly),
         :ok <- Args.reject_unknown(args, @update_args),
         {:ok, decoded} <- update_changes(args),
         {:ok, %{changed: changed}} <- lifecycle_call({:update, uid, decoded}) do
      {:ok, changed}
    end
  end

  @doc """
  Destroy a conference from a scenario. `force: true` disconnects the participants
  first (as `conference.delete` does); without it a populated conference is
  `{:error, :not_empty}`.
  """
  @spec destroy_conference(String.t(), keyword) :: :ok | {:error, atom}
  def destroy_conference(uid, opts \\ []) when is_binary(uid) and is_list(opts) do
    case lifecycle_call({:delete, uid, Keyword.get(opts, :force, false)}) do
      {:ok, _report} -> :ok
      {:error, _} = err -> err
    end
  end

  @doc "The conferences of one domain (pure ETS read, for a script that lists)."
  @spec conferences(String.t()) :: [Conference.t()]
  def conferences(domain) when is_binary(domain),
    do: Enum.filter(conferences(), &(&1.domain == domain))

  # Build the spec + the ownership choice from a keyword list, reusing the control
  # commands' validation verbatim (§17.2). `owner` is deliberately NOT part of the
  # spec the control path can reach: a REST caller's "instance" is the HTTP request
  # process, so `owner: :caller` there would destroy the conference the moment the
  # response was sent.
  defp create_args(domain, opts) do
    args = opts |> Args.stringify_keys() |> Map.put("domain", domain)
    {owner, args} = Map.pop(args, "owner", :caller)

    with :ok <- Args.reject_unknown(args, @create_args),
         :ok <- valid_owner(owner),
         {:ok, spec} <- create_spec(args) do
      {:ok, spec, owner}
    end
  end

  defp valid_owner(owner) when owner in [:caller, :none], do: :ok
  defp valid_owner(other), do: {:error, "owner must be :caller or :none, got #{inspect(other)}"}

  # A lifecycle call can sit behind two MCU round-trips, so it is bounded by the
  # control timeout rather than the tight facade one — and a script must therefore do
  # it *before* answering, which is what the ad-hoc reference script does.
  defp lifecycle_call(request) do
    Kelix.Module.safe_call(__MODULE__, request, timeout: @control_timeout_ms)
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

  Options:

    * `:displayname` — overlay a name banner on this leg's tile
      (`SetParticipantDisplayName`). Either the string to show, or `:auto`, which
      takes the INVITE From header's display name and falls back to the From URI's
      user part. Resolved here (only this call still holds the request), stored on
      the row, and sent at `attach/1` time — the MCU-side participant does not
      exist yet during admit. Anything else is `{:error, :bad_displayname}`.
  """
  @spec admit(String.t(), map, keyword) ::
          {:ok, Conference.t(), Conference.participant()}
          | {:error,
             :no_such_conference | :full | :mcu_down | :bad_displayname | :down | :timeout}
  def admit(domain, req, opts \\ [])

  def admit(domain, req, opts) when is_binary(domain) and is_map(req) and is_list(opts) do
    with {:ok, display_name} <- requested_displayname(Keyword.get(opts, :displayname), req) do
      Kelix.Module.safe_call(__MODULE__, {:admit, domain, req, display_name},
        timeout: @facade_timeout_ms
      )
    end
  end

  def admit(sip_ctx = %SIP.Context{}, domain, req), do: admit(sip_ctx, domain, req, [])

  @doc """
  Context-aware `admit/3`, for scenario scripts. The verdict travels through the
  context, never through the return value — this returns the updated `sip_ctx`
  only, and the scenario tests `sip_ctx.lasterr` and reacts:

    * `:ok` — admitted; the conference and the participant handle are stored in
      the context appdata under `:mcu_conf` and `:mcu_part` (where the
      context-aware `attach/1` and `leave/2` read them back);
    * `{:error, reason}` — `admit/3`'s verdicts, for the script to map onto a
      SIP response;
    * `#{inspect(@jsr309_error)}` — an MCU call and a JSR309 media session are
      mutually exclusive on the same SIP session: the context already carries a
      JSR309 peer connection, so the call is refused without touching the
      conference and an error is logged. A pending `goto` aborts the scenario
      on any non-`:ok` value.
  """
  @spec admit(%SIP.Context{}, String.t(), map, keyword) :: %SIP.Context{}
  def admit(sip_ctx = %SIP.Context{}, domain, req, opts) do
    case no_jsr309_media(sip_ctx) do
      {:ok, sip_ctx} ->
        case admit(domain, req, opts) do
          {:ok, conf, part} ->
            sip_ctx
            |> SIP.Context.appdata_set(:mcu_conf, conf)
            |> SIP.Context.appdata_set(:mcu_part, part)

          {:error, _reason} = err ->
            SIP.Context.set(sip_ctx, :lasterr, err)
        end

      {:error, sip_ctx} ->
        sip_ctx
    end
  end

  @doc """
  ACK-time: start sending, join the audio mixer, and mark the participant joined
  (§6.2, second half).

  The RPCs run **from the calling scenario**, not inside the registry: a conference
  filling up must not serialise its joins behind one process. Only the row update is
  serialised, which is all that needs to be.
  """
  @spec attach(%SIP.Context{}) :: %SIP.Context{}
  @spec attach(Conference.participant()) :: :ok | {:error, term}

  # Context-aware clause, for scenario scripts — must stay ahead of the
  # `is_map/1` clause below: a %SIP.Context{} is a map too. Same JSR309 mutual
  # exclusion as `admit/4`, same contract: the verdict goes to `sip_ctx.lasterr`
  # (`:ok`, `{:error, reason}` or the JSR309 refusal), never to the return value
  # — this returns the updated context only. The participant is read back from
  # the `:mcu_part` appdata key `admit/4` stored. The MCU leg's own peer
  # connection (created by the media macros on this module's adapter between
  # admit and attach) passes the check; only a *JSR309* media session refuses
  # the call.
  def attach(sip_ctx = %SIP.Context{}) do
    case no_jsr309_media(sip_ctx) do
      {:ok, sip_ctx} ->
        rez =
          case SIP.Context.appdata_get(sip_ctx, :mcu_part) do
            nil -> {:error, :no_such_participant}
            part -> attach(part)
          end

        SIP.Context.set(sip_ctx, :lasterr, rez)

      {:error, sip_ctx} ->
        sip_ctx
    end
  end

  def attach(part) when is_map(part) do
    with {:ok, row} <- participant(part),
         {:ok, medias} <- Adapter.attach(row.conn) do
      set_display_name(row)

      Kelix.Module.safe_call(__MODULE__, {:joined, part.conf_uid, part.ref, medias},
        timeout: @facade_timeout_ms
      )
    else
      :error -> {:error, :no_such_participant}
      {:error, _} = err -> err
    end
  end

  # The banner of admit/3's `:displayname` option, sent from the calling scenario
  # like the rest of attach — the MCU-side participant exists from
  # `create_peer_connection/3` onwards, which `SetParticipantDisplayName` requires
  # (MCU-API.md §6.5). Cosmetic by contract: a refusal (unsupported script, missing
  # font — `mcu.log` has the detail) is logged and must not keep the leg out of the
  # mix, so this always answers `:ok`.
  defp set_display_name(%{display_name: name, part_id: part_id} = row)
       when is_binary(name) and is_integer(part_id) do
    result =
      with {:ok, conf} <- conference(row.conf_uid),
           {:ok, mcu} <- mediaserver(conf.mcu) do
        rpc(mcu, "SetParticipantDisplayName", [
          conf.conf_id,
          @all_mosaics,
          part_id,
          name,
          @autodetect_script
        ])
      end

    case result do
      {:ok, _} ->
        :ok

      other ->
        Logger.warning(
          module: __MODULE__,
          message:
            "SetParticipantDisplayName(#{inspect(name)}) for participant #{part_id} " <>
              "failed: #{inspect(other)}"
        )

        :ok
    end
  end

  defp set_display_name(_row), do: :ok

  @doc """
  Remove a participant: tear the MCU side down, release the slot, and emit
  `participant.left` **exactly once** (§11.1 invariant 1).

  Idempotent by contract — the reference script calls it from five places, and the
  crash reaper (§9.3) from a sixth.
  """
  @spec leave(%SIP.Context{}, atom) :: %SIP.Context{}
  @spec leave(Conference.participant(), atom) :: :ok
  def leave(part, reason \\ :bye)

  # Context-aware clause, for scenario scripts — must stay ahead of the
  # `is_map/1` clause below: a %SIP.Context{} is a map too. Same JSR309 mutual
  # exclusion as `admit/4`, verdict in `sip_ctx.lasterr`, participant read back
  # from the `:mcu_part` appdata key `admit/4` stored (nothing to do when it is
  # absent — leave stays idempotent). Returns the updated context only.
  def leave(sip_ctx = %SIP.Context{}, reason) do
    case no_jsr309_media(sip_ctx) do
      {:ok, sip_ctx} ->
        case SIP.Context.appdata_get(sip_ctx, :mcu_part) do
          nil -> sip_ctx
          part -> SIP.Context.set(sip_ctx, :lasterr, leave(part, reason))
        end

      {:error, sip_ctx} ->
        sip_ctx
    end
  end

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

  # ── JSR309 mutual exclusion ───────────────────────────────────────────────────
  # A session context can only carry ONE media leg. "A JSR309 session is in
  # progress" means the media macros already created a peer connection
  # (`:mediapeerconnectionid`) on a media server OTHER than this module's adapter:
  # the MCU leg's own connection — stored under the same key by
  # `reply_invite_with_sdp` between admit and attach — must keep passing, or the
  # check would refuse every normal MCU call at ACK time.
  defp no_jsr309_media(sip_ctx = %SIP.Context{}) do
    cnx = SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid)

    if is_nil(cnx) or sip_ctx.mediaservermodule == Adapter do
      {:ok, SIP.Context.set(sip_ctx, :lasterr, :ok)}
    else
      Logger.error(
        module: __MODULE__,
        message: "A JSR309 media session is already in progress. Cannot handle an MCU call here"
      )

      {:error, SIP.Context.set(sip_ctx, :lasterr, @jsr309_error)}
    end
  end

  @doc """
  Mute or unmute one media of a participant (`SetMute`).

  Backs `participant.update` (§8.3.3) and is exported for completeness: a derived
  script that wants a moderated conference — everyone muted until the chair says
  otherwise — needs it without going through the control API.
  """
  @spec mute(Conference.participant(), MediaServer.media(), boolean) :: :ok | {:error, term}
  def mute(part, media, muted?) when is_map(part) and is_boolean(muted?) do
    case participant(part) do
      {:ok, row} -> do_mute(part.conf_uid, row.part_id, %{media => muted?})
      :error -> {:error, :no_such_participant}
    end
    |> case do
      {:ok, _changed} -> :ok
      other -> other
    end
  end

  @doc """
  Disconnect a participant by its MCU-side id (`kelictl mcu participant.delete`).

  The scenario is asked to wind down — it sends the BYE and releases its media — so
  the caller sees the same teardown a hang-up produces, not a row yanked from under a
  live dialog.
  """
  @spec kick(String.t(), non_neg_integer) :: :ok | {:error, :not_found | term}
  def kick(uid, part_id) when is_binary(uid) and is_integer(part_id) do
    case call({:kick, uid, part_id}) do
      {:ok, _} -> :ok
      other -> other
    end
  end

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

  # Human names for the MCU wire integers (§3.6), declared as CLI render labels:
  # `kelictl` shows `hd720p` / `3x3`, the API and the XML-RPC keep the numbers.
  # String keys throughout — the hint must survive the JSON of `GET /modules`.
  #
  # Read from `Vocabulary`, which is also what *accepts* those names as input: a
  # second table here would render a mosaic the parser refuses (§8.3.7).
  @conference_labels %{
    "video.size" => Vocabulary.size_names(),
    "layout.size" => Vocabulary.size_names(),
    "layout.comp" => Vocabulary.mosaic_names(),
    "vad" => Vocabulary.vad_names()
  }

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
          %{name: "vad", required: false, help: Vocabulary.vad_help()},
          %{name: "rate", required: false},
          %{name: "audio_codecs", required: false},
          %{name: "video_codecs", required: false},
          %{name: "text_codecs", required: false},
          %{name: "video", required: false, help: Vocabulary.video_help()},
          %{name: "layout", required: false, help: Vocabulary.layout_help()},
          %{name: "logo", required: false, help: Vocabulary.logo_help()},
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
        render: %{
          kind: :table,
          columns: ~w(name domain did uid max_participants created_at)
        },
        help: "List the conferences, optionally filtered by domain and/or DID"
      },
      %{
        name: "conference.show",
        rest: {:get, "/conferences/:uid"},
        errors: %{not_found: 404},
        rw: :r,
        args: [%{name: "uid", required: true}],
        render: %{
          kind: :detail,
          fields:
            ~w(name domain did uid mcu conf_id stale created_at max_participants destroy_when_empty vad rate codecs video layout logo recording participants),
          labels: @conference_labels,
          # the roster, not the media detail of each leg — that is `participant.show`
          nested: %{"participants" => %{columns: ~w(part_id name from state joined_at)}}
        },
        help: "Show one conference and its participants"
      },
      %{
        name: "conference.update",
        # PUT with partial-merge semantics, PATCH as the honest verb for a strict
        # client — one declaration, two methods (§8.3.2, decision 6a)
        rest: {[:put, :patch], "/conferences/:uid"},
        errors: %{not_found: 404, mcu_down: 503, rpc_error: 502},
        rw: :w,
        args: [
          %{name: "uid", required: true},
          %{name: "name", required: false},
          %{name: "vad", required: false, help: Vocabulary.vad_help()},
          %{name: "rate", required: false},
          %{name: "layout", required: false, help: Vocabulary.layout_help()},
          %{name: "video", required: false, help: Vocabulary.video_help()},
          %{name: "logo", required: false, help: Vocabulary.logo_help()},
          %{name: "max_participants", required: false},
          %{name: "destroy_when_empty", required: false}
        ],
        help: "Update a conference (merges the fields given; omitted ones are untouched)"
      },
      %{
        name: "conference.delete",
        rest: {:delete, "/conferences/:uid"},
        errors: %{not_found: 404, not_empty: 409, mcu_down: 503, rpc_error: 502},
        rw: :w,
        args: [%{name: "uid", required: true}, %{name: "force", required: false}],
        help: "Destroy a conference (`force` disconnects the participants first)"
      },
      %{
        name: "participant.list",
        rest: {:get, "/conferences/:uid/participants"},
        errors: %{not_found: 404},
        rw: :r,
        args: [%{name: "uid", required: true}],
        render: %{kind: :table, columns: ~w(part_id name from state joined_at)},
        help: "List a conference's participants"
      },
      %{
        name: "participant.show",
        rest: {:get, "/conferences/:uid/participants/:part_id"},
        errors: %{not_found: 404},
        rw: :r,
        args: [%{name: "uid", required: true}, %{name: "part_id", required: true}],
        render: %{
          kind: :detail,
          fields: ~w(name from part_id state joined_at medias)
        },
        help: "Show one participant, with its media server statistics"
      },
      %{
        name: "participant.update",
        rest: {[:put, :patch], "/conferences/:uid/participants/:part_id"},
        errors: %{not_found: 404, mcu_down: 503, rpc_error: 502},
        rw: :w,
        args: [
          %{name: "uid", required: true},
          %{name: "part_id", required: true},
          %{name: "muted", required: false}
        ],
        help: ~s(Mute or unmute a participant: muted={"audio":true,"video":false})
      },
      # ── the inspection surface (§8.3.8) ──────────────────────────────────────
      %{
        name: "recording.start",
        rest: {:post, "/conferences/:uid/recording"},
        status: 201,
        location: "/conferences/:uid/recording",
        errors: %{
          not_found: 404,
          already_recording: 409,
          mcu_down: 503,
          rpc_error: 502
        },
        rw: :w,
        args: [
          %{name: "uid", required: true},
          %{name: "file", required: false, help: Vocabulary.record_file_help()}
        ],
        render: %{kind: :detail, fields: ~w(uid file path mcu)},
        help: "Record the mix to a file on the media server (one recording per conference)"
      },
      %{
        name: "recording.show",
        rest: {:get, "/conferences/:uid/recording"},
        errors: %{not_found: 404},
        rw: :r,
        args: [%{name: "uid", required: true}],
        render: %{
          kind: :detail,
          fields: ~w(recording file path mcu started_at duration_s)
        },
        help: "Whether this conference is being recorded, and into which file"
      },
      %{
        name: "recording.stop",
        rest: {:delete, "/conferences/:uid/recording"},
        errors: %{not_found: 404, not_recording: 404, mcu_down: 503, rpc_error: 502},
        rw: :w,
        args: [%{name: "uid", required: true}],
        render: %{kind: :detail, fields: ~w(uid file duration_s)},
        help: "Stop the recording and close the file"
      },
      %{
        name: "slot.list",
        rest: {:get, "/conferences/:uid/slots"},
        errors: %{not_found: 404, mcu_down: 503, rpc_error: 502},
        rw: :r,
        args: [%{name: "uid", required: true}],
        render: %{
          kind: :detail,
          fields: ~w(layout vad logo slots),
          labels: @conference_labels,
          nested: %{"slots" => %{columns: ~w(slot holds pinned part_id name)}}
        },
        help: "The mosaic slot map: what each slot was told to hold, and who is in it now"
      },
      %{
        name: "slot.update",
        rest: {[:put, :patch], "/conferences/:uid/slots/:slot"},
        errors: %{not_found: 404, mcu_down: 503, rpc_error: 502},
        rw: :w,
        args: [
          %{name: "uid", required: true},
          %{name: "slot", required: true, help: Vocabulary.slot_help()},
          %{name: "holds", required: true, help: Vocabulary.holds_help()}
        ],
        render: %{kind: :detail, fields: ~w(slot holds part_id)},
        help: "Pin a mosaic slot: the active speaker, a participant, locked or free"
      },
      %{
        name: "participant.delete",
        rest: {:delete, "/conferences/:uid/participants/:part_id"},
        errors: %{not_found: 404},
        rw: :w,
        args: [%{name: "uid", required: true}, %{name: "part_id", required: true}],
        help: "Disconnect a participant (BYE, then teardown)"
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
         {:ok, spec} <- create_spec(args),
         # `owner: :none`: a REST caller has no instance to own the conference — its
         # "caller" is the HTTP request process, which dies as the response is sent
         {:ok, conf, warning} <- call({:create, spec, :none}) do
      {:ok, create_reply(conf, warning)}
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

  # §8.3.3: a partial merge. Omitted fields are left untouched — a PUT here never
  # resets one to its default, which is the dangerous reading of PUT and the reason
  # the semantics are stated in the design rather than implied.
  defp do_control("conference.update", args) do
    with :ok <- Args.reject_readonly(args, @conference_readonly),
         :ok <- Args.reject_unknown(args, @update_args),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, changes} <- update_changes(args) do
      call({:update, uid, changes})
    end
  end

  defp do_control("participant.list", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, conf} <- found(conference(uid)) do
      {:ok, Enum.map(Conference.participants(conf), &Conference.render_participant/1)}
    end
  end

  defp do_control("participant.show", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid part_id)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, part_id} <- part_id(args),
         {:ok, conf, row} <- find_participant(uid, part_id) do
      {:ok, Map.merge(Conference.render_participant(row), statistics(conf, row))}
    end
  end

  defp do_control("participant.update", args) do
    with :ok <- Args.reject_readonly(args, @participant_readonly),
         :ok <- Args.reject_unknown(args, ~w(uid part_id muted)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, part_id} <- part_id(args),
         {:ok, muted} <- muted_changes(args) do
      call({:mute, uid, part_id, muted})
    end
  end

  defp do_control("participant.delete", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid part_id)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, part_id} <- part_id(args) do
      call({:kick, uid, part_id})
    end
  end

  # ── the inspection surface (§8.3.8) ──────────────────────────────────────────

  defp do_control("recording.start", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid file)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, file} <- Args.string(args, "file") do
      call({:record_start, uid, file})
    end
  end

  # A read: the answer is our own row, since the server has no "am I recording?" RPC
  # to ask and the file is ours to remember (§8.3.8, decision 3).
  defp do_control("recording.show", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, conf} <- found(conference(uid)) do
      {:ok, recording_view(conf)}
    end
  end

  defp do_control("recording.stop", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid)),
         {:ok, uid} <- Args.required_string(args, "uid") do
      call({:record_stop, uid})
    end
  end

  # A read too, but one RPC deep: who is in which slot is the *mixer's* state, and it
  # moves on its own every VAD period — so it is asked for, never cached.
  defp do_control("slot.list", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, conf} <- found(conference(uid)) do
      slot_map(conf)
    end
  end

  defp do_control("slot.update", args) do
    with :ok <- Args.reject_unknown(args, ~w(uid slot holds)),
         {:ok, uid} <- Args.required_string(args, "uid"),
         {:ok, slot} <- slot_number(args),
         {:ok, holds} <- Vocabulary.holds(Map.get(args, "holds")) do
      call({:slot, uid, slot, holds})
    end
  end

  defp do_control(command, _args) do
    Logger.warning(module: __MODULE__, message: "unknown control command #{inspect(command)}")
    {:error, :unknown_command}
  end

  defp found({:ok, value}), do: {:ok, value}
  defp found(:error), do: {:error, :not_found}

  # What a REST/CLI client gets back: the handle, the DID it must dial, and the
  # dial-plan warning when the two can no longer meet (§6.1).
  defp create_reply(conf, warning) do
    reply = %{uid: conf.uid, did: conf.did, conf_id: conf.conf_id, mcu: conf.mcu}
    if warning, do: Map.put(reply, :warning, warning), else: reply
  end

  # A path param arrives as a string, a CLI `part_id=7` token as an integer.
  # An optional `logo`: a bare image name, validated here so a create or an update
  # refuses a path before anything reaches the media server (§8.3.8, decision 1).
  defp optional_logo(args) do
    case Map.get(args, "logo") do
      nil -> {:ok, nil}
      name when is_binary(name) -> with :ok <- valid_basename(name, "logo"), do: {:ok, name}
      other -> {:error, "logo must be a file name, got #{inspect(other)}"}
    end
  end

  # The slot number, from a path param (a string) or a JSON body (an integer) —
  # 0-based, as the media server numbers and logs them (§8.3.8).
  defp slot_number(args) do
    case Map.get(args, "slot") do
      n when is_integer(n) and n >= 0 ->
        {:ok, n}

      s when is_binary(s) ->
        case Integer.parse(s) do
          {n, ""} when n >= 0 -> {:ok, n}
          _ -> {:error, "slot must be a slot number, 0-based"}
        end

      nil ->
        {:error, "slot is required (0-based; slot.list shows them)"}

      other ->
        {:error, "slot must be a slot number, got #{inspect(other)}"}
    end
  end

  defp part_id(args) do
    case Map.get(args, "part_id") do
      id when is_integer(id) and id >= 0 ->
        {:ok, id}

      id when is_binary(id) ->
        case Integer.parse(id) do
          {n, ""} when n >= 0 -> {:ok, n}
          _ -> {:error, "part_id must be a non-negative integer"}
        end

      nil ->
        {:error, "part_id is required"}

      other ->
        {:error, "part_id must be a non-negative integer, got #{inspect(other)}"}
    end
  end

  defp find_participant(uid, part_id) do
    with {:ok, conf} <- found(conference(uid)) do
      case Conference.by_part_id(conf, part_id) do
        nil -> {:error, :not_found}
        row -> {:ok, conf, row}
      end
    end
  end

  # The media server's own view of the leg (`GetParticipantStatistics`, §3.3): sent /
  # received packets and bytes per media. A failure is reported rather than hidden —
  # an operator reading zeros must be able to tell "no media" from "no answer".
  defp statistics(conf, row) do
    case mediaserver(conf.mcu) do
      {:ok, mcu} ->
        case rpc(mcu, "GetParticipantStatistics", [conf.conf_id, row.part_id]) do
          {:ok, rows} -> %{stats: decode_statistics(rows)}
          {:error, reason} -> %{stats: %{}, stats_error: reason}
        end

      :error ->
        %{stats: %{}, stats_error: :unknown_mcu}
    end
  end

  # `returnVal` is one `(s i i i i i i i)` row per media, in the server's own field
  # order — read off `xmlrpcmcu.cpp:GetParticipantStatistics`, which is authoritative:
  # `isReceiving` comes **before** `isSending`, the reverse of the order §3.3 lists
  # them in. Named here so a caller never has to know that.
  defp decode_statistics(rows) when is_list(rows) do
    for [media, receiving, sending, lost, recv_packets, sent_packets, recv_bytes, sent_bytes] <-
          rows,
        into: %{} do
      {media,
       %{
         receiving: receiving == 1,
         sending: sending == 1,
         lost_recv_packets: lost,
         num_recv_packets: recv_packets,
         num_send_packets: sent_packets,
         total_recv_bytes: recv_bytes,
         total_send_bytes: sent_bytes
       }}
    end
  end

  defp decode_statistics(_rows), do: %{}

  # Decode the update body into the changes to apply, keeping only what was sent:
  # that map *is* the partial-merge semantics.
  defp update_changes(args) do
    Enum.reduce_while(
      [
        {"name", &Args.string(&1, "name")},
        {"vad", &Vocabulary.vad(Map.get(&1, "vad"))},
        {"rate", &Args.int(&1, "rate", nil, [8000, 16_000, 32_000, 48_000])},
        {"max_participants", &Args.int(&1, "max_participants", nil)},
        {"destroy_when_empty", &Args.bool(&1, "destroy_when_empty", nil)},
        # `video` and `layout` are merged over the conference's current values, which
        # only the registry holds — so they are decoded here (names → wire ids, the
        # short layout form → fields) and travel as a partial map
        {"video", &Vocabulary.video(Map.get(&1, "video"))},
        {"layout", &Vocabulary.layout(Map.get(&1, "layout"))},
        {"logo", &optional_logo(&1)}
      ],
      {:ok, %{}},
      fn {key, getter}, {:ok, acc} ->
        if Map.has_key?(args, key) do
          case getter.(args) do
            {:ok, value} -> {:cont, {:ok, Map.put(acc, String.to_existing_atom(key), value)}}
            {:error, _} = err -> {:halt, err}
          end
        else
          {:cont, {:ok, acc}}
        end
      end
    )
  end

  # `muted` is a per-media map: `%{"audio" => true}` mutes the audio only and leaves
  # the video as it was.
  defp muted_changes(args) do
    case Map.get(args, "muted") do
      nil ->
        {:ok, %{}}

      map when is_map(map) ->
        Enum.reduce_while(map, {:ok, %{}}, fn {media, value}, {:ok, acc} ->
          cond do
            media not in ~w(audio video text) ->
              {:halt, {:error, "muted: unknown media #{inspect(media)}"}}

            not is_boolean(value) ->
              {:halt, {:error, "muted.#{media} must be a boolean"}}

            true ->
              {:cont, {:ok, Map.put(acc, String.to_existing_atom(media), value)}}
          end
        end)

      other ->
        {:error, ~s(muted must be a table like {"audio":true}, got #{inspect(other)})}
    end
  end

  # Decode + validate the create arguments into a spec the GenServer can apply
  # without re-parsing (and without ever raising inside the registry).
  defp create_spec(args) do
    with {:ok, domain} <- Args.required_string(args, "domain"),
         {:ok, name} <- Args.string(args, "name"),
         {:ok, did} <- Args.string(args, "did"),
         {:ok, mcu} <- Args.string(args, "mcu"),
         {:ok, vad} <- Vocabulary.vad(Map.get(args, "vad")),
         {:ok, rate} <- Args.int(args, "rate", nil, [8000, 16_000, 32_000, 48_000]),
         # the codec vocabulary is the config's, checked here too: a per-conference
         # list is exactly as dangerous as a configured one (Config.validate_codecs/2)
         {:ok, audio, dtmf} <- Config.validate_codecs(:audio, Map.get(args, "audio_codecs")),
         {:ok, video_codecs, _} <- Config.validate_codecs(:video, Map.get(args, "video_codecs")),
         {:ok, text_codecs, _} <- Config.validate_codecs(:text, Map.get(args, "text_codecs")),
         {:ok, max_participants} <- Args.int(args, "max_participants", nil),
         {:ok, destroy_when_empty} <- Args.bool(args, "destroy_when_empty", nil),
         # names → wire ids, and the short `layout` form → the fields it names: the
         # merge over the configured defaults happens in the registry, but the
         # *reading* of what was asked for belongs here, before anything is created
         {:ok, video} <- Vocabulary.video(Map.get(args, "video")),
         {:ok, layout} <- Vocabulary.layout(Map.get(args, "layout")),
         {:ok, logo} <- optional_logo(args) do
      {:ok,
       %{
         domain: domain,
         name: name,
         did: did,
         mcu: mcu,
         vad: vad,
         rate: rate,
         audio_codecs: audio,
         # an explicit audio list decides this conference's DTMF too, exactly as the
         # config block's does (TELEPHONE-EVENT is a flag, not a mixer codec)
         dtmf: if(is_nil(audio), do: nil, else: dtmf),
         video_codecs: video_codecs,
         text_codecs: text_codecs,
         video: video,
         layout: layout,
         logo: logo,
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
    mcus = Keyword.get(opts, :mediaservers, [])

    tables = [:set, :protected, :named_table, read_concurrency: true]
    :ets.new(@conf_table, tables)
    :ets.new(@did_table, tables)
    :ets.new(@mcu_table, tables)

    # Entries exist from the start, `down` until their client announces itself, so
    # `create` on an unreachable MCU is refused with a clear error instead of
    # looking like an unknown name.
    for mcu <- mcus do
      :ets.insert(
        @mcu_table,
        {mcu.name, Map.merge(mcu, %{status: :down, client: nil, queue_id: nil})}
      )
    end

    Logger.info(
      module: __MODULE__,
      message:
        "mcu module started: #{length(mcus)} media server(s) " <>
          "(#{Enum.map_join(mcus, ", ", & &1.name)})"
    )

    {:ok,
     %{
       config: config,
       module_name: Keyword.get(opts, :module_name, "mcu"),
       # round-robin cursor over the pool, for a create that names no mcu (§8.4).
       # Held here because creates are serialised through this process anyway.
       cursor: 0,
       # the media pool to ask for the `enabled` switch; overridable so a test can
       # run its own pool next to the node's singleton
       pool: Keyword.get(opts, :pool, Kelix.MediaPool),
       # monitor_ref => {conference uid, participant ref}: the crash reaper of §9.3
       monitors: %{},
       # monitor_ref => conference uid: the creator of a script-made conference
       # (§17.3). Separate from `monitors` because the verdict differs — a dead
       # creator only takes an *empty* conference with it.
       conf_monitors: %{}
     }}
  end

  @impl true
  # `from` is the creating instance: with `owner: :caller` its death reaps an empty
  # conference (§17.3), the same way a participant's scenario reaps its row (§9.3).
  def handle_call({:create, spec, owner}, {caller, _tag}, state) do
    case do_create(state, spec) do
      {:ok, conf, warning, state} ->
        {:reply, {:ok, conf, warning}, own_conference(state, conf.uid, owner, caller)}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  # Atomic get-or-create (§17.4): the lookup and the creation happen in the same
  # message, so two INVITEs on the same unknown DID cannot both create one.
  def handle_call({:ensure, spec, owner}, {caller, _tag}, state) do
    case lookup_did(spec.domain, spec.did) do
      {:ok, conf} ->
        # it existed before us: not ours to own, and nothing to warn about
        {:reply, {:ok, conf, :existing, nil}, state}

      :error ->
        case do_create(state, spec) do
          {:ok, conf, warning, state} ->
            {:reply, {:ok, conf, :created, warning},
             own_conference(state, conf.uid, owner, caller)}

          {:error, _} = err ->
            {:reply, err, state}
        end
    end
  end

  def handle_call({:delete, uid, force}, _from, state) do
    case do_delete(state, uid, force) do
      {{:ok, _report} = reply, state} -> {:reply, reply, state}
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:update, uid, changes}, _from, state) do
    {:reply, do_update(state, uid, changes), state}
  end

  def handle_call({:mute, uid, part_id, muted}, _from, state) do
    {:reply, do_mute(uid, part_id, muted), state}
  end

  def handle_call({:kick, uid, part_id}, _from, state) do
    case find_participant(uid, part_id) do
      {:ok, _conf, row} ->
        # BYE + teardown: the scenario's cooperative shutdown does both (it sends the
        # BYE, releases the media and calls `leave/2`), which is why this is a message
        # and not a teardown we run behind its back.
        if is_pid(row.scenario) and Process.alive?(row.scenario) do
          send(row.scenario, {:scenario_ctl, :shutdown, :kicked})
          {:reply, {:ok, %{part_id: part_id}}, state}
        else
          # its scenario is already gone: reap the row ourselves rather than leave a
          # participant nobody will ever remove
          Adapter.close(row.conn)
          {:reply, {:ok, %{part_id: part_id}}, do_leave(state, uid, row.ref, :kick)}
        end

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  # §8.3.8. Writes, so they go through here: a recording is a singleton per conference
  # and a slot pin is a row update, and both must be serialised against the create /
  # recover paths that touch the same row.
  def handle_call({:record_start, uid, file}, _from, state) do
    {:reply, do_record_start(state, uid, file), state}
  end

  def handle_call({:record_stop, uid}, _from, state) do
    {:reply, do_record_stop(uid), state}
  end

  def handle_call({:slot, uid, slot, holds}, _from, state) do
    {:reply, do_slot(uid, slot, holds), state}
  end

  # the configured defaults, for the phases that build on them
  def handle_call(:config, _from, state), do: {:reply, state.config, state}

  # `from` is the scenario instance: it is the process whose death must reap the
  # participant (§9.3), so it is recorded as the row's owner.
  def handle_call({:admit, domain, req, display_name}, {scenario, _tag}, state) do
    {result, state} = do_admit(state, domain, req, scenario, display_name)
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
          %{
            part
            | state: :connected,
              medias: medias,
              joined_at: part.joined_at || DateTime.utc_now()
          }
        end)

        # One join, one event (§11.1, invariant 3): attach/1 may legitimately run
        # again on the same leg — a renegotiation, or a retransmitted ACK reaching
        # a script without the in_conference state — and only the first entry into
        # the mix is a participant.joined. The medias above still refresh: a
        # renegotiation may have changed them.
        if row.state != :connected do
          Event.emit(:"participant.joined", conf.uid, %{
            part_id: row.part_id,
            name: row.name,
            medias: Map.new(medias, fn {media, info} -> {media, Map.get(info, :codec)} end)
          })

          Emit.mcu_call(:joined)
        end

        # a leg joining the mosaic — or renegotiating video in or out — changes
        # how many tiles the layout must show
        follow_auto_layout(conf.uid)

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
    case Map.pop(state.conf_monitors, ref) do
      {nil, _} -> participant_down(ref, state)
      {uid, monitors} -> {:noreply, creator_gone(%{state | conf_monitors: monitors}, uid)}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp participant_down(ref, state) do
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

  # ── admit / join / leave ─────────────────────────────────────────────────────

  defp do_admit(state, domain, req, scenario, display_name) do
    did = ruri_user(req)

    with {:ok, conf} <- did_or_reject(domain, did),
         :ok <- mcu_up(conf),
         :ok <- room_left(conf) do
      part = new_participant(conf, req, scenario, display_name)

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

        Emit.mcu_call(sip_code(reason))
        {{:error, reason}, state}
    end
  end

  # ── conference ownership (§17.3) ──────────────────────────────────────────────

  # `owner: :caller` monitors the creating instance. Same mechanism as the
  # participant reaper, a separate map because the verdict differs: a dead
  # participant is always removed, a dead creator only takes an **empty** conference
  # with it.
  defp own_conference(state, _uid, :none, _caller), do: state

  defp own_conference(state, uid, :caller, caller) when is_pid(caller) do
    ref = Process.monitor(caller)
    %{state | conf_monitors: Map.put(state.conf_monitors, ref, uid)}
  end

  defp own_conference(state, _uid, _owner, _caller), do: state

  # The creating instance is gone. An empty conference goes with it; a populated one
  # stays, because the creator was only the first to arrive and tearing a live mix
  # down because one leg hung up would be absurd.
  defp creator_gone(state, uid) do
    case conference(uid) do
      {:ok, conf} ->
        if Conference.count(conf) == 0 do
          destroy(state, conf, :creator_gone)
        else
          Logger.debug(
            module: __MODULE__,
            message:
              "conference #{uid}: creator gone but #{Conference.count(conf)} participant(s) " <>
                "remain; keeping it"
          )

          state
        end

      :error ->
        state
    end
  end

  # Stop watching a conference's creator (it is being destroyed by another path).
  defp disown_conference(state, uid) do
    case Enum.find(state.conf_monitors, fn {_ref, owned} -> owned == uid end) do
      {ref, _uid} ->
        Process.demonitor(ref, [:flush])
        %{state | conf_monitors: Map.delete(state.conf_monitors, ref)}

      nil ->
        state
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

  defp new_participant(conf, req, scenario, display_name) do
    %{
      ref: make_ref(),
      part_id: nil,
      conf_uid: conf.uid,
      name: participant_name(req),
      display_name: display_name,
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

  # Resolve admit/3's `:displayname` option into what the banner will show — or nil
  # for no banner at all, which is also what an empty string means (the RPC's
  # "clear" form has nothing to clear at admit time).
  defp requested_displayname(nil, _req), do: {:ok, nil}
  defp requested_displayname("", _req), do: {:ok, nil}
  defp requested_displayname(name, _req) when is_binary(name), do: {:ok, name}

  defp requested_displayname(:auto, req) do
    case uri_of(Map.get(req, :from)) do
      %SIP.Uri{displayname: shown} when is_binary(shown) and shown != "" -> {:ok, shown}
      %SIP.Uri{userpart: user} when is_binary(user) and user != "" -> {:ok, user}
      _ -> {:ok, nil}
    end
  end

  defp requested_displayname(_other, _req), do: {:error, :bad_displayname}

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

        # §11.1 keeps `reason` an atom; the SIP code a media-refused leg carries is
        # metric detail, not vocabulary, so it is split out here.
        Event.emit(:"participant.left", conf.uid, %{
          part_id: row.part_id,
          name: row.name,
          reason: event_reason(reason),
          duration_ms: duration_ms(row)
        })

        emit_left_metric(reason, row)

        state = demonitor_participant(state, part_ref)

        # §8.3.3 / §5.1: an auto-destroying conference goes away with its last
        # participant, freeing its DID for the next allocation.
        if conf.destroy_when_empty and remaining == %{} do
          destroy(state, conf, :empty)
        else
          # one tile fewer: the automatic layout tightens back up
          follow_auto_layout(conf.uid)
          state
        end
    end
  end

  defp event_reason({:no_media, _code}), do: :no_media
  defp event_reason(reason), do: reason

  # A leg that never joined is counted by the code it was refused with; one that did
  # was already counted as `joined` when it entered the mix.
  defp emit_left_metric({:no_media, code}, _row), do: Emit.mcu_call(code)
  defp emit_left_metric(_reason, _row), do: :ok

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
            Kelix.MediaPool.recheck(name, :up, state.pool)
            # §9.2 then §9.4, in that order: recreate what is ours before sweeping
            # what is not, or the sweep would delete the conferences we are about to
            # rebuild.
            recreate_stale(state.config, updated)
            gc_orphans(state.config, updated)

          true ->
            Event.emit(:"mediaserver.down", nil, %{mcu: name, reason: :unreachable})
            # Before the teardown below, not after: the pool must stop handing this
            # MCU out for new calls while we clean up the ones it just lost.
            Kelix.MediaPool.recheck(name, :down, state.pool)
            mark_stale(name)
            notify_mcu_lost(name)
        end

        state

      :error ->
        Logger.warning(module: __MODULE__, message: "health for unknown mcu #{inspect(name)}")
        state
    end
  end

  # ── automatic layout (§1.1 point 3, §6.2 last step) ──────────────────────────

  @doc """
  The mosaic layout for `n` video participants (`comp` values of §3.6).

  A ladder rather than a formula, because the MCU's layouts are not a grid family:
  two participants belong side by side (`1+1`), not in a 2x2 with two black tiles,
  and five fit a `1+4` better than a 3x3. Each step is the smallest layout that
  holds `n` tiles.

  This is the *policy* half of "an optional automatic layout that follows the
  participant count"; `auto: false` on a conference means the operator owns it and
  nothing here fires.
  """
  @spec auto_comp(non_neg_integer) :: non_neg_integer
  def auto_comp(n) when n <= 1, do: 0
  def auto_comp(2), do: 6
  def auto_comp(n) when n <= 4, do: 1
  def auto_comp(5), do: 10
  def auto_comp(6), do: 5
  def auto_comp(n) when n <= 8, do: 4
  def auto_comp(9), do: 2
  def auto_comp(n) when n <= 16, do: 9
  def auto_comp(_n), do: 11

  # Re-evaluate the mosaic after a join or a leave. Only conferences that asked for
  # it move, only when the layout actually changes (an unchanged `comp` would be an
  # RPC per join for nothing), and only video legs count — an audio-only participant
  # occupies no tile.
  #
  # With no video leg at all the layout is left alone rather than reset to 1x1: an
  # audio-only conference must issue no mosaic RPC, and the last configured layout is
  # the right thing to find when video comes back.
  defp follow_auto_layout(uid) do
    with {:ok, %Conference{layout: %{auto: true}} = conf} <- conference(uid),
         tiles when tiles > 0 <- video_participants(conf),
         comp = auto_comp(tiles),
         true <- comp != conf.layout.comp,
         {:ok, mcu} <- mediaserver(conf.mcu),
         {:ok, _} <-
           rpc(mcu, "SetCompositionType", [conf.conf_id, @default_mosaic, comp, conf.layout.size]) do
      layout = %{conf.layout | comp: comp}
      :ets.insert(@conf_table, {conf.uid, %Conference{conf | layout: layout}})

      Event.emit(:"conference.layout_changed", conf.uid, %{
        comp: comp,
        size: conf.layout.size,
        auto?: true
      })
    else
      _ -> :ok
    end
  end

  defp video_participants(conf) do
    conf
    |> Conference.participants()
    |> Enum.count(&(&1.state == :connected and Map.has_key?(&1.medias, :video)))
  end

  # ── MCU restart (§9.2) and orphan collection (§9.4) ───────────────────────────

  # The conference row and its DID survive the server; `conf_id` does not.
  defp mark_stale(mcu_name) do
    for conf <- conferences(), conf.mcu == mcu_name, not conf.stale do
      # The recording died with the server and is **not** resumed when it comes back
      # (§8.3.8, decision 5): reopening it would produce a second, truncated file
      # nobody asked for. The pins are kept — they are policy, and `replay_slots/2`
      # puts them back.
      if conf.recording, do: emit_recording_stopped(conf, conf.recording, :mcu_lost)

      :ets.insert(
        @conf_table,
        {conf.uid, %Conference{conf | stale: true, conf_id: nil, recording: nil}}
      )
    end

    :ok
  end

  # Recreate every stale conference of a server that came back: **same `uid`** (so
  # its DID answers again and REST clients keep their handle), new `conf_id`. The
  # participants are not restored — those calls are gone, and their scenarios were
  # told so when the server went away. This is mcuGold's `Conference.restart()`,
  # minus the mosaic/sidebar zoo.
  defp recreate_stale(config, mcu) do
    for conf <- conferences(), conf.mcu == mcu.name, conf.stale do
      case create_on_mcu(config, mcu, %Conference{conf | participants: %{}}) do
        {:ok, recreated} ->
          :ets.insert(@conf_table, {conf.uid, %Conference{recreated | stale: false}})

          Event.emit(:"conference.created", conf.uid, %{
            domain: conf.domain,
            did: conf.did,
            name: conf.name,
            mcu: conf.mcu,
            conf_id: recreated.conf_id,
            recreated?: true
          })

        {:error, reason} ->
          Logger.error(
            module: __MODULE__,
            message:
              "conference #{conf.uid}: could not recreate on #{mcu.name}: #{inspect(reason)}"
          )
      end
    end

    :ok
  end

  @doc """
  Delete every conference the MCU holds that this node does not know about (§9.4).

  After a kelixip restart the media server may still hold the conferences of the
  process that died: our registry is empty, so they are leftovers with no controller.
  Safe because a kelixip node owns its MCUs exclusively — and gated on `gc_orphans`
  for the day that stops being true.

  **Deletes nothing** when `GetConferences` cannot be read with confidence: the shape
  of that reply is documented loosely, and a misparse here would destroy live
  conferences rather than leak dead ones.
  """
  @spec gc_orphans(Config.t(), map) :: :ok
  def gc_orphans(%Config{gc_orphans: false}, _mcu), do: :ok

  def gc_orphans(%Config{}, mcu) do
    # `returnVal` **is** the row list, not a list wrapping it: `xmlok()` passes the
    # array straight into the envelope (`xmlhandler.cpp`), so a server holding nothing
    # answers `returnVal: []`. Read off the server source, because the earlier reading
    # (rows at `returnVal[0]`) collected nothing and the stub agreed with it.
    case rpc(mcu, "GetConferences", []) do
      {:ok, rows} when is_list(rows) ->
        # Keyed on the MCU-side **id**, not on the tag, although the tag *is* our uid.
        # Older media servers report it truncated to its first character ("c" for
        # "c-a8592bc0"): a `std::wstring` handed to xmlrpc-c's `%s`, fixed in
        # `xmlrpcmcu.cpp` on 2026-07-30 but not in builds already deployed. Matching on
        # a truncated tag matches nothing, and the failure is not a sweep that
        # under-collects: right after `recreate_stale/1` rebuilt our conferences, this
        # pass would delete every one of them. The id is unambiguous and immune either
        # way; the tag stays in the log line, where a truncated value is merely
        # unhelpful.
        ours = MapSet.new(conferences(), & &1.conf_id)

        for {conf_id, tag} <- Enum.flat_map(rows, &decode_conference_row/1),
            not MapSet.member?(ours, conf_id) do
          Logger.warning(
            module: __MODULE__,
            message:
              "mcu #{mcu.name}: deleting orphan conference #{conf_id} (tag #{inspect(tag)})"
          )

          rpc(mcu, "DeleteConference", [conf_id])
        end

        :ok

      {:ok, other} ->
        Logger.warning(
          module: __MODULE__,
          message:
            "mcu #{mcu.name}: GetConferences returned #{inspect(other)}; " <>
              "no orphan collected (deleting on a shape we cannot read would be worse)"
        )

        :ok

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message: "mcu #{mcu.name}: GetConferences failed: #{inspect(reason)}"
        )

        :ok
    end
  end

  # `(i id, s name, i numPart)` per §3.2 — as an array, or as a struct on a server
  # that names its fields. Anything else is skipped rather than guessed at.
  defp decode_conference_row([id, tag | _rest]) when is_integer(id) and is_binary(tag),
    do: [{id, tag}]

  defp decode_conference_row(%{} = row) do
    id = Map.get(row, "id")
    tag = Map.get(row, "tag") || Map.get(row, "name")

    if is_integer(id) and is_binary(tag), do: [{id, tag}], else: []
  end

  defp decode_conference_row(_row), do: []

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

    with {:ok, mcu, state} <- pick_mcu(state, spec.mcu),
         {:ok, did, allocated?} <- pick_did(config, spec.domain, spec.did),
         {:ok, conf} <- build_conference(config, spec, mcu, did),
         {:ok, conf} <- create_on_mcu(config, mcu, conf) do
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

      # The module allocates DIDs; it does not edit domains.toml (§15, consequence
      # of decision 2). A DID no dial rule matches is a conference nobody can dial,
      # so the drift is reported rather than left silent. The conference itself is
      # returned, so a script gets the object and a REST client its rendering.
      {:ok, conf, dial_plan_warning(conf), state}
    end
  end

  # An explicit name must exist and be up. A conference is **pinned** to its media
  # server for its whole life (§1.3), so naming one is always honoured — that
  # pinning is a runtime property of the conference, independent of the pool the
  # list was declared in.
  defp pick_mcu(state, name) when is_binary(name) do
    case mediaserver(name) do
      {:ok, %{status: :up} = mcu} -> {:ok, mcu, state}
      {:ok, _down} -> {:error, :mcu_down}
      :error -> {:error, :unknown_mcu}
    end
  end

  # Without a name: round-robin over the servers that are `enabled` in the pool and
  # `up` on our own control channel (§8.4).
  defp pick_mcu(state, nil) do
    entries = mediaservers()

    serviceable =
      Enum.filter(entries, &(&1.status == :up and enabled_in_pool?(state.pool, &1.name)))

    cond do
      entries == [] ->
        {:error, :no_mediaserver}

      serviceable == [] ->
        {:error, :mcu_down}

      true ->
        idx = rem(state.cursor, length(serviceable))
        {:ok, Enum.at(serviceable, idx), %{state | cursor: idx + 1}}
    end
  end

  # The pool's `enabled` flag is an operator switch: toggling an entry off must stop
  # new conferences landing on it (live ones stay — same semantics as for calls).
  #
  # Its `healthy` flag is deliberately **not** consulted: the pool probes the
  # point-to-point adapter's own channel (`/jsr309`), while a conference rides the
  # control channel this module holds (`/mcu`). A server whose JSR-309 side is
  # unreachable can serve conferences perfectly, so our `status` is the health that
  # decides here. A pool that has no opinion (not running, or the entry unknown to
  # it) vetoes nothing.
  defp enabled_in_pool?(pool, name) do
    with pid when is_pid(pid) <- GenServer.whereis(pool),
         %{enabled: enabled} <- Enum.find(Kelix.MediaPool.status(pool), &(&1.name == name)) do
      enabled
    else
      _ -> true
    end
  catch
    _, _ -> true
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
         # the conference's own logo, else the configured one: `logo_file` is what
         # puts the company picture in every empty slot with no command at all
         logo: spec.logo || config.logo_file,
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
         dtmf: if(is_nil(spec.dtmf), do: config.dtmf, else: spec.dtmf),
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
  defp create_on_mcu(_config, %{queue_id: nil}, _conf), do: {:error, :mcu_down}

  defp create_on_mcu(config, mcu, conf) do
    # The queueId is passed at creation: it is what binds this conference's events
    # to the stream we poll, so creating one without it would produce a conference
    # whose FPU requests reach nobody.
    with {:ok, conf_id} <-
           rpc_create(mcu, "CreateConference", [conf.uid, conf.vad, conf.rate, mcu.queue_id]),
         conf = %Conference{conf | conf_id: conf_id},
         :ok <- set_composition(mcu, conf) do
      {:ok, conf |> apply_logo(mcu, config) |> replay_slots(mcu)}
    end
  end

  # A picture must never be why a conference cannot be created — a mistyped
  # `logo_file` would otherwise take the whole MCU down, one call at a time. So the
  # logo is applied **after** the conference exists and a failure only warns, leaving
  # `logo: nil` so `conference.show` reports honestly what is on the mixer. An
  # *explicit* `conference.update logo=…` is the opposite: the operator asked, so the
  # server's refusal is returned to them (`do_update/3`).
  #
  # Both only ever see a *transport* failure: the server answers `1` whether or not the
  # image loaded (`SetParticipantBackground`, `multiconf.cpp` — `LoadLogo`'s failure is
  # in its own log and nowhere else), so `logo` records what was asked for. L14.
  defp apply_logo(%Conference{logo: nil} = conf, _mcu, _config), do: conf

  defp apply_logo(%Conference{} = conf, mcu, config) do
    case set_logo(mcu, conf, conf.logo, config.image_dir) do
      :ok ->
        conf

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message:
            "conference #{conf.uid}: logo #{inspect(conf.logo)} not applied: #{inspect(reason)}"
        )

        %Conference{conf | logo: nil}
    end
  end

  # The pins are *our* policy (§8.3.8, decision 5), so a conference recreated after a
  # media-server restart gets them back with its composition — otherwise an operator's
  # pinned mosaic would silently become whatever the mixer felt like. A pin the new
  # composition cannot hold is dropped, and said so.
  defp replay_slots(%Conference{slots: slots} = conf, _mcu) when map_size(slots) == 0, do: conf

  defp replay_slots(%Conference{} = conf, mcu) do
    kept =
      for {slot, wire} <- conf.slots, valid_slot(conf, slot) == :ok, into: %{} do
        case rpc(mcu, "SetMosaicSlot", [conf.conf_id, @default_mosaic, slot, wire]) do
          {:ok, _} ->
            {slot, wire}

          {:error, reason} ->
            Logger.warning(
              module: __MODULE__,
              message: "conference #{conf.uid}: slot #{slot} not replayed: #{inspect(reason)}"
            )

            {slot, wire}
        end
      end

    dropped = map_size(conf.slots) - map_size(kept)

    if dropped > 0,
      do:
        Logger.warning(
          module: __MODULE__,
          message:
            "conference #{conf.uid}: #{dropped} pinned slot(s) do not fit the mosaic anymore"
        )

    %Conference{conf | slots: kept}
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

  # ── update (§8.3.3) ──────────────────────────────────────────────────────────

  # Two kinds of field, and the difference is not cosmetic: `vad`/`rate`/`layout` are
  # the *mixer's* state and go to the media server now; `name`, `video`,
  # `max_participants` and `destroy_when_empty` are ours and apply to **new**
  # participants — renegotiating a live encoder is out of scope (§8.3, L7).
  defp do_update(state, uid, changes) do
    with {:ok, conf} <- found(conference(uid)),
         {:ok, mcu} <- update_target(conf),
         {:ok, conf, video} <- merged_video(state, conf, changes),
         {:ok, conf, layout} <- merged_layout(state, conf, changes),
         :ok <- push_mixer_changes(mcu, conf, changes, layout),
         :ok <- maybe_set_logo(state, mcu, conf, changes) do
      updated = %Conference{
        conf
        | name: Map.get(changes, :name, conf.name),
          vad: Map.get(changes, :vad, conf.vad),
          rate: Map.get(changes, :rate, conf.rate),
          video: video,
          layout: layout,
          logo: Map.get(changes, :logo, conf.logo),
          max_participants: Map.get(changes, :max_participants, conf.max_participants),
          destroy_when_empty: Map.get(changes, :destroy_when_empty, conf.destroy_when_empty)
      }

      :ets.insert(@conf_table, {uid, updated})
      changed = changes |> Map.keys() |> Enum.sort()
      Event.emit(:"conference.updated", uid, %{changed: changed})

      if Map.has_key?(changes, :layout) do
        Event.emit(:"conference.layout_changed", uid, %{
          comp: layout.comp,
          size: layout.size,
          auto?: layout.auto
        })
      end

      {:ok, %{uid: uid, changed: changed}}
    end
  end

  # Only a change the mixer must hear about needs the server; a purely local update
  # (a rename) works on a conference whose MCU is momentarily down.
  defp update_target(conf) do
    case mediaserver(conf.mcu) do
      {:ok, mcu} -> {:ok, mcu}
      :error -> {:error, :mcu_down}
    end
  end

  defp merged_video(_state, conf, changes) do
    case Args.sub_map(%{"video" => Map.get(changes, :video)}, "video", conf.video, [
           :size,
           :fps,
           :bitrate,
           :intra_period
         ]) do
      {:ok, video} -> {:ok, conf, video}
      {:error, _} = err -> err
    end
  end

  defp merged_layout(_state, conf, changes) do
    case Args.sub_map(%{"layout" => Map.get(changes, :layout)}, "layout", conf.layout, [
           :comp,
           :size,
           :auto
         ]) do
      {:ok, layout} -> {:ok, conf, layout}
      {:error, _} = err -> err
    end
  end

  defp push_mixer_changes(mcu, conf, changes, layout) do
    vad_rate? = Map.has_key?(changes, :vad) or Map.has_key?(changes, :rate)

    with :ok <- maybe_update_conference(mcu, conf, changes, vad_rate?),
         :ok <- maybe_set_composition(mcu, conf, changes, layout) do
      :ok
    end
  end

  defp maybe_update_conference(_mcu, _conf, _changes, false), do: :ok

  defp maybe_update_conference(mcu, conf, changes, true) do
    vad = Map.get(changes, :vad, conf.vad)
    rate = Map.get(changes, :rate, conf.rate)

    case rpc(mcu, "UpdateConference", [conf.conf_id, vad, rate]) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  defp maybe_set_composition(mcu, conf, changes, layout) do
    if Map.has_key?(changes, :layout) do
      case rpc(mcu, "SetCompositionType", [
             conf.conf_id,
             @default_mosaic,
             layout.comp,
             layout.size
           ]) do
        {:ok, _} -> :ok
        {:error, _} = err -> err
      end
    else
      :ok
    end
  end

  # An explicit `logo` update is the operator's own ask, so the server's refusal (an
  # image it cannot read, most often) is **returned** rather than warned about — the
  # opposite of the create path, where a picture must not fail a conference.
  defp maybe_set_logo(state, mcu, conf, changes) do
    case Map.fetch(changes, :logo) do
      :error -> :ok
      {:ok, nil} -> {:error, "logo cannot be unset on a live conference (L11)"}
      {:ok, logo} -> set_logo(mcu, conf, logo, state.config.image_dir)
    end
  end

  # ── mute (§8.3.3 participant.update) ─────────────────────────────────────────

  defp do_mute(uid, part_id, muted) do
    with {:ok, _conf, row} <- find_participant(uid, part_id) do
      muted
      |> Enum.reduce_while(:ok, fn {media, muted?}, :ok ->
        case Adapter.mute(row.conn, media, muted?) do
          :ok ->
            Event.emit(:"participant.muted", uid, %{
              part_id: part_id,
              media: media,
              muted: muted?
            })

            {:cont, :ok}

          {:error, _} = err ->
            {:halt, err}
        end
      end)
      |> case do
        :ok -> {:ok, %{part_id: part_id, changed: muted |> Map.keys() |> Enum.sort()}}
        err -> err
      end
    end
  end

  # ── recording, slots, logo (§8.3.8) ──────────────────────────────────────────

  defp recording_view(%Conference{recording: nil} = conf),
    do: %{recording: false, file: nil, path: nil, mcu: conf.mcu, started_at: nil, duration_s: nil}

  defp recording_view(%Conference{recording: rec} = conf) do
    %{
      recording: true,
      file: rec.file,
      path: rec.path,
      mcu: conf.mcu,
      started_at: rec.started_at,
      duration_s: DateTime.diff(DateTime.utc_now(), rec.started_at)
    }
  end

  # `GetMosaicPositions` answers the **occupancy** — the participant displayed in each
  # slot, or 0 for nobody — never a slot state: `mosaicPos` only ever holds a positive
  # `partId` or `SlotFree` (`mosaic.cpp`). What each slot was *told* to hold is ours
  # (`conf.slots`), and the gap between the two is exactly what a VAD reshuffle looks
  # like: `holds: "vad"` with a `part_id` that moves.
  defp slot_map(conf) do
    with {:ok, mcu} <- update_target(conf),
         {:ok, positions} <- rpc(mcu, "GetMosaicPositions", [conf.conf_id, @default_mosaic]) do
      {:ok,
       %{
         layout: conf.layout,
         vad: conf.vad,
         logo: conf.logo,
         slots: slot_rows(conf, positions)
       }}
    end
  end

  defp slot_rows(conf, positions) when is_list(positions) do
    for {shown, slot} <- Enum.with_index(positions) do
      pinned = Map.get(conf.slots, slot)
      part = if is_integer(shown) and shown > 0, do: Conference.by_part_id(conf, shown)

      %{
        slot: slot,
        holds: Vocabulary.holds_name(pinned || 0),
        pinned: if(is_integer(pinned) and pinned > 0, do: pinned),
        part_id: part && part.part_id,
        name: part && part.name
      }
    end
  end

  # A server too old to answer the array (or one that answered something else) must not
  # be reported as an empty mosaic: say so instead.
  defp slot_rows(_conf, _other), do: []

  defp do_record_start(state, uid, file) do
    with {:ok, conf} <- found(conference(uid)),
         :ok <- not_recording(conf),
         {:ok, mcu} <- update_target(conf),
         {:ok, name, path} <- record_target(state.config, conf, file),
         {:ok, _} <-
           rpc(mcu, "StartRecordingBroadcaster", [
             conf.conf_id,
             path,
             @default_mosaic,
             @default_sidebar
           ]) do
      recording = %{file: name, path: path, started_at: DateTime.utc_now()}
      :ets.insert(@conf_table, {uid, %Conference{conf | recording: recording}})
      Event.emit(:"conference.recording_started", uid, %{file: name, mcu: conf.mcu})
      {:ok, %{uid: uid, file: name, path: path, mcu: conf.mcu}}
    end
  end

  defp do_record_stop(uid) do
    with {:ok, conf} <- found(conference(uid)),
         {:ok, recording} <- recording_of(conf),
         {:ok, mcu} <- update_target(conf),
         {:ok, _} <- rpc(mcu, "StopRecordingBroadcaster", [conf.conf_id]) do
      :ets.insert(@conf_table, {uid, %Conference{conf | recording: nil}})
      duration = DateTime.diff(DateTime.utc_now(), recording.started_at)
      emit_recording_stopped(conf, recording, :api, duration)
      {:ok, %{uid: uid, file: recording.file, duration_s: duration}}
    end
  end

  defp not_recording(%Conference{recording: nil}), do: :ok
  defp not_recording(%Conference{}), do: {:error, :already_recording}

  defp recording_of(%Conference{recording: nil}), do: {:error, :not_recording}
  defp recording_of(%Conference{recording: recording}), do: {:ok, recording}

  # Emitted from every path that ends a recording, not only from `recording.stop`:
  # destroying the conference and losing the media server both close the file, and a
  # consumer that only saw `recording_started` would believe it is still running.
  defp emit_recording_stopped(conf, recording, reason, duration) do
    Event.emit(:"conference.recording_stopped", conf.uid, %{
      file: recording.file,
      mcu: conf.mcu,
      duration_s: duration,
      reason: reason
    })
  end

  defp emit_recording_stopped(conf, recording, reason),
    do:
      emit_recording_stopped(
        conf,
        recording,
        reason,
        DateTime.diff(DateTime.utc_now(), recording.started_at)
      )

  # The file the media server will write. A **basename** under the configured
  # `record_dir` and nothing else: the server writes wherever it has rights, so a path
  # a client could choose would be a file-write primitive on that host for anyone
  # holding the control token (§8.3.8, decision 1).
  defp record_target(%Config{record_dir: nil}, _conf, _file) do
    {:error,
     "record_dir is not set in [module.mcu]: there is nowhere on the media server to write"}
  end

  defp record_target(%Config{record_dir: dir}, conf, nil),
    do: {:ok, default_record_name(conf), Path.join(dir, default_record_name(conf))}

  defp record_target(%Config{record_dir: dir}, _conf, file) do
    with :ok <- valid_basename(file, "file"),
         :ok <- valid_record_extension(file) do
      {:ok, file, Path.join(dir, file)}
    end
  end

  defp default_record_name(conf) do
    stamp =
      DateTime.utc_now()
      |> Calendar.strftime("%Y%m%d-%H%M%S")

    "#{conf.uid}-#{stamp}.mp4"
  end

  defp valid_record_extension(file) do
    if String.downcase(Path.extname(file)) in @record_extensions,
      do: :ok,
      else:
        {:error,
         "file must end in #{Enum.join(@record_extensions, " or ")} " <>
           "(the media server picks the container from the extension), got #{inspect(file)}"}
  end

  # No directory, no traversal, nothing hidden: the module appends this to a configured
  # directory, and that is the whole guarantee.
  defp valid_basename(name, key) do
    cond do
      not is_binary(name) or name == "" ->
        {:error, "#{key} must be a file name"}

      Path.basename(name) != name or name in [".", ".."] ->
        {:error, "#{key} must be a bare file name, with no directory: got #{inspect(name)}"}

      String.starts_with?(name, ".") ->
        {:error, "#{key} must not start with a dot: got #{inspect(name)}"}

      true ->
        :ok
    end
  end

  defp do_slot(uid, slot, holds) do
    with {:ok, conf} <- found(conference(uid)),
         {:ok, mcu} <- update_target(conf),
         :ok <- valid_slot(conf, slot),
         {:ok, wire} <- resolve_holds(conf, holds),
         {:ok, _} <-
           rpc(mcu, "SetMosaicSlot", [conf.conf_id, @default_mosaic, slot, wire]) do
      # `reset` is the one value that removes the pin instead of recording one: the
      # slot goes back to being the mixer's business, so we must stop replaying it.
      slots =
        if wire == @slot_reset,
          do: Map.delete(conf.slots, slot),
          else: Map.put(conf.slots, slot, wire)

      # Pinning implies `manual`, for the reason naming a mosaic does (§8.3.7): the
      # automatic layout changes the composition, and a smaller mosaic drops the pins
      # that no longer fit — the operator would watch their slot move on its own.
      layout = %{conf.layout | auto: false}
      :ets.insert(@conf_table, {uid, %Conference{conf | slots: slots, layout: layout}})

      holds_name = Vocabulary.holds_name(wire)
      part_id = if wire > 0, do: wire

      Event.emit(:"conference.slot_changed", uid, %{
        slot: slot,
        holds: holds_name,
        part_id: part_id
      })

      if conf.layout.auto,
        do:
          Event.emit(:"conference.layout_changed", uid, %{
            comp: layout.comp,
            size: layout.size,
            auto?: false
          })

      {:ok, %{slot: slot, holds: holds_name, part_id: part_id}}
    end
  end

  # Judged by the **server's** slot table, not by arithmetic on the name: `1+4` has 16
  # slots, and a bound computed from "1 + 4" would refuse a pin the mixer accepts.
  defp valid_slot(conf, slot) do
    case Vocabulary.slots_for(conf.layout.comp) do
      nil ->
        :ok

      slots when slot < slots ->
        :ok

      slots ->
        {:error,
         "slot must be 0..#{slots - 1} on a #{Vocabulary.mosaic_names()[to_string(conf.layout.comp)]} mosaic"}
    end
  end

  # A name is resolved against this conference's roster — never guessed: two matches is
  # a refusal naming both, so an operator is told to use the `part_id` instead of
  # discovering later that the wrong leg was pinned.
  defp resolve_holds(_conf, {:state, wire}), do: {:ok, wire}

  defp resolve_holds(conf, {:part_id, part_id}) do
    case Conference.by_part_id(conf, part_id) do
      nil -> {:error, :not_found}
      _row -> {:ok, part_id}
    end
  end

  defp resolve_holds(conf, {:name, name}) do
    wanted = String.downcase(name)

    matches =
      conf
      |> Conference.participants()
      |> Enum.filter(&(is_integer(&1.part_id) and name_matches?(&1.name, wanted)))

    case matches do
      [one] ->
        {:ok, one.part_id}

      [] ->
        {:error, :not_found}

      many ->
        ids = many |> Enum.map(& &1.part_id) |> Enum.sort() |> Enum.join(" and ")
        {:error, ~s(holds: "#{name}" matches participants #{ids} — use the part_id)}
    end
  end

  # A participant's name is its full AOR (`alice@phone_example_com`), which nobody wants
  # to type: the user part alone matches too, and two legs of the same user are a
  # refusal rather than a coin flip.
  defp name_matches?(nil, _wanted), do: false

  defp name_matches?(name, wanted) do
    name = String.downcase(name)
    name == wanted or hd(String.split(name, "@")) == wanted
  end

  # The mixer's logo, applied at create time and on every `logo` update. Its own RPC
  # rather than a field of another: `SetParticipantBackground` with a non-positive
  # participant id is what loads it (§8.3.8).
  defp set_logo(mcu, conf, logo, dir) do
    with :ok <- valid_basename(logo, "logo"),
         {:ok, path} <- image_path(dir, logo),
         {:ok, _} <-
           rpc(mcu, "SetParticipantBackground", [conf.conf_id, @mixer_logo_part_id, path]) do
      :ok
    end
  end

  defp image_path(nil, _logo),
    do: {:error, "image_dir is not set in [module.mcu]: there is nowhere to read a logo from"}

  defp image_path(dir, logo), do: {:ok, Path.join(dir, logo)}

  # ── delete ───────────────────────────────────────────────────────────────────

  defp do_delete(state, uid, force) do
    with {:ok, conf} <- found(conference(uid)) do
      cond do
        Conference.count(conf) > 0 and not force ->
          {:error, :not_empty}

        true ->
          disconnected = disconnect_participants(state, conf)
          reason = if force and disconnected > 0, do: :api_force, else: :api
          {{:ok, %{uid: uid, disconnected: disconnected}}, destroy(state, conf, reason)}
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

  # Drop a conference: MCU side first (that is the resource that leaks), then the
  # local rows, then the creator's monitor — a conference destroyed by any other path
  # must stop being watched, or its creator's later death would look for a row that
  # is no longer there (§17.3). Returns the state, since that monitor lives in it.
  defp destroy(state, %Conference{} = conf, reason) do
    Event.emit(:"conference.destroyed", conf.uid, %{
      reason: reason,
      participants_at_end: Conference.count(conf)
    })

    # `DeleteConference` closes the recorder with the conference, so the file ends
    # here whether or not anyone called `recording.stop` — a consumer that only saw
    # `recording_started` would otherwise believe it is still being written (§8.3.8).
    if conf.recording, do: emit_recording_stopped(conf, conf.recording, :destroyed)

    case mediaserver(conf.mcu) do
      {:ok, mcu} -> rpc(mcu, "DeleteConference", [conf.conf_id])
      :error -> :ok
    end

    :ets.delete(@did_table, {conf.domain, conf.did})
    :ets.delete(@conf_table, conf.uid)
    disown_conference(state, conf.uid)
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
