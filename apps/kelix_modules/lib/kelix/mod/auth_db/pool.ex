defmodule Kelix.Mod.AuthDb.Pool do
  @moduledoc """
  The subscriber-DB link of `Kelix.Mod.AuthDb`: a `Kelix.DB.Pool` registered as
  `Kelix.Mod.AuthDb.Conn`, supervised by `Kelix.ModuleSupervisor`, and what
  `kelictl auth_db show` reports about it.

  How the link is opened — the driver, TLS first, the cleartext fallback gated by
  `allow_insecure_db_connection`, the probe, the backoff — is `Kelix.DB.Pool`'s,
  shared with every module that keeps data in SQL. What is `auth_db`'s is only
  its name, its descriptor's `table`, and the block it reads, `[module.auth_db]`
  over the `[database]` defaults.
  """

  # The pool's registered name — the one `Kelix.Mod.AuthDb.lookup_ha1/2` queries.
  @conn Kelix.Mod.AuthDb.Conn

  @label "auth_db"

  @typedoc "See `t:Kelix.DB.Pool.verdict/0`."
  @type verdict :: Kelix.DB.Pool.verdict()

  @doc "The pool's registered name."
  @spec conn() :: atom
  def conn(), do: @conn

  @doc "Which SQL driver `[module.auth_db]` asks for: `:mysql` (default) or `:postgres`."
  defdelegate driver(config), to: Kelix.DB.Pool

  @doc "The driver module `driver/1`'s result resolves to."
  defdelegate driver_module(driver), to: Kelix.DB.Pool

  @doc "Does `[module.auth_db]` allow a cleartext link to the subscriber DB?"
  defdelegate insecure_allowed?(config), to: Kelix.DB.Pool

  @doc """
  Negotiate the transport, publish the descriptor `show` reads, and start the pool.
  `Kelix.Mod.AuthDb.child_spec/2`'s start MFA; see `Kelix.DB.Pool.start_link/2`.
  """
  @spec start_link(map) :: {:ok, pid} | {:error, term}
  def start_link(config) do
    Kelix.DB.Pool.start_link(config,
      name: @conn,
      label: @label,
      publish_as: __MODULE__,
      descriptor: &descriptor/2
    )
  end

  @doc "Which transport to open the pool on — `Kelix.DB.Pool.negotiate/2`."
  @spec negotiate(map, keyword) :: {verdict, keyword}
  def negotiate(config, opts \\ []),
    do: Kelix.DB.Pool.negotiate(config, Keyword.put_new(opts, :label, @label))

  @doc """
  What the link IS, as `show` reports it: `Kelix.DB.Pool.descriptor/2` and the
  subscriber table. Never the password.
  """
  @spec descriptor(map, verdict) :: map
  def descriptor(config, verdict) do
    config
    |> Kelix.DB.Pool.descriptor(verdict)
    |> Map.put(:table, config["table"] || "subscriber")
  end

  @doc """
  The running link: where it points, whether it is encrypted, and whether it
  answers **right now** (`kelictl auth_db show`) — `Kelix.DB.Pool.describe/3`.
  """
  @spec describe() :: map
  def describe(), do: Kelix.DB.Pool.describe(__MODULE__, @conn, @label)
end
