defmodule Kelix.Mod.Mcu.Supervisor do
  @moduledoc """
  What `Kelix.Mod.Mcu.child_spec/2` returns (design `docs/design/mcu_module.md`
  §4.1): the conference registry plus one `{Client, EventQueue}` pair per media
  server — the `[mediaserver.pool.<name>]` entries `Kelix.Mod.Mcu`
  `mediaservers_from_pool/0` selected, passed in as `:mediaservers` so tests can
  inject a list without a config file.

  Strategy `:rest_for_one`, not `:one_for_one`: the registry (`Kelix.Mod.Mcu`, the
  first child) **owns the ETS tables** the clients and the adapter read, and holds
  the client pids. If it were restarted alone, its tables would be gone and the
  surviving clients would be talking to a registry that no longer knows them. Every
  child after it therefore restarts with it, in order, and the clients re-announce
  themselves — which is also how they come back marked `up`.

  An MCU that is unreachable at boot does not prevent the module from starting: its
  client is up but marked `down` (§4.1, §9.4).
  """
  use Supervisor

  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Config, EventQueue}

  @spec start_link(keyword) :: Supervisor.on_start()
  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    config = Keyword.fetch!(opts, :config)
    module_name = Keyword.get(opts, :module_name, "mcu")
    mcus = Keyword.get(opts, :mediaservers, [])

    children =
      [{Mcu, config: config, module_name: module_name, mediaservers: mcus}] ++
        Enum.flat_map(mcus, &mcu_children(&1, config))

    Supervisor.init(children, strategy: :rest_for_one)
  end

  # One control channel and one event stream per media server. The event queue
  # reads its queueId from the client rather than creating its own: the id must be
  # the one every CreateConference on that MCU was given, or the events come back
  # on a queue nobody reads.
  defp mcu_children(mcu, %Config{} = config) do
    [
      Supervisor.child_spec(
        {Client,
         name: mcu.name,
         base_url: mcu.url,
         timeout_ms: config.xmlrpc_timeout_ms,
         register: {Mcu, mcu.name},
         server_name: client_name(mcu.name)},
        id: {Client, mcu.name}
      ),
      Supervisor.child_spec(
        {EventQueue,
         name: mcu.name,
         base_url: mcu.url,
         client: client_name(mcu.name),
         sink: Mcu,
         server_name: queue_name(mcu.name)},
        id: {EventQueue, mcu.name}
      )
    ]
  end

  @doc """
  The registered name of an MCU's control channel.

  Derived from the entry name, which comes from `config.toml` — a bounded set, so
  the atoms it creates are bounded too.
  """
  @spec client_name(String.t()) :: atom
  def client_name(mcu_name), do: :"kelix_mcu_client_#{mcu_name}"

  @doc "The registered name of an MCU's event stream."
  @spec queue_name(String.t()) :: atom
  def queue_name(mcu_name), do: :"kelix_mcu_events_#{mcu_name}"
end
