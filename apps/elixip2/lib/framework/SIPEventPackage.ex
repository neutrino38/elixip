# The event package behaviour and the node's name -> module table.
# RFC 6665 §4.4, §8.2.2. See docs/design/DESIGN-PRESENCE.md, "An event package is
# a behaviour".

defmodule SIP.EventPackage do
  @moduledoc """
  What a SIP event package is, and the table that maps a package **name** to the
  module implementing it.

  The subscription layer knows nothing of PIDF, of a dialog document or of a
  message-waiting summary: it reads `Event`, `Accept` and `Expires` off the
  message (`SIP.Msg.Ops`) and asks the package what it can produce. A package,
  symmetrically, never reads a SIP message — it answers about names, bounds,
  content types and bodies, and that is the whole contract.

  ## The table

  Three different questions hide behind "registering a package": whether the
  **code is loaded**, whether the **node knows** the package — this table, which
  is what answers **489 Bad Event** and composes `Allow-Events` — and whether a
  **domain enables** it, which `domains.toml` already answers. Only the second one
  lives here.

  The provided packages are compiled into this library and register themselves at
  boot. `register/2` is exposed for a **third party**: a kelixip module, or an
  operator with a document format of their own, declaring itself as a package when
  it starts.

  Four rules, and they are the reason this module exists rather than a hardcoded
  `case`:

  1. **`:persistent_term` holds the table.** It is read on the path of every
     SUBSCRIBE, PUBLISH and NOTIFY, and written once at boot plus once per module
     reload — that profile exactly. Not an ETS table with a process of its own to
     supervise. Writes are serialised by their callers, each of them a single
     process (the boot path, `Kelix.ModuleSupervisor`), which is why a
     read-modify-write of one key is safe here and would not be in general.
  2. **Start order stays out of the contract.** A domain naming a package whose
     module has not started yet cannot be validated at boot: that is a warning,
     never a refusal, and a **489** at run time if the package is still absent.
  3. **`register/2` is idempotent and paired with `unregister/1`.** A kelixip
     module reloads hot — a reload replaces the entry, a module removed drops it.
     An entry left pointing at an unloaded module kills the next SUBSCRIBE.
  4. **Collisions are decided at registration, never at use.** A third party
     *overriding* a provided package is legitimate, allowed, and logged at warning
     naming both modules. A second third party claiming one name is **refused**.
     Otherwise module start order silently decides SIP behaviour.

  Package names are matched case-insensitively (RFC 6665 §8.2.1) and held folded
  to lower case, which is the form `SIP.Msg.Ops.event_package/1` returns.
  """

  require Logger

  @typedoc "Where an entry came from: this library, or someone else."
  @type origin :: :builtin | :third_party

  @doc "The package name, as it appears in `Event` — `\"presence\"`, `\"dialog\"`."
  @callback name() :: binary()

  @doc """
  The lifetime a subscription gets when the SUBSCRIBE asks for none (RFC 6665
  §4.4.1). It belongs to the package — 3600 s for presence — never to the
  framework.
  """
  @callback default_expires() :: pos_integer()

  @doc "Below this, the notifier answers **423 Interval Too Brief**."
  @callback min_expires() :: pos_integer()

  @doc "Above this, the notifier grants this instead. It never refuses for being too long."
  @callback max_expires() :: pos_integer()

  @doc """
  The content types this package can produce, **in the package's own preference
  order**. The notifier intersects them with the SUBSCRIBE's `Accept` and answers
  **406 Not Acceptable** on an empty intersection; an absent `Accept` means the
  first of this list.
  """
  @callback content_types() :: [binary()]

  @doc "Read a body of one of `content_types/0` into whatever the package models."
  @callback parse(content_type :: binary(), body :: binary()) :: {:ok, term()} | {:error, term()}

  @doc "Write that model back out as one of `content_types/0`."
  @callback serialize(content_type :: binary(), state :: term()) ::
              {:ok, binary()} | {:error, term()}

  @callbacks [
    name: 0,
    default_expires: 0,
    min_expires: 0,
    max_expires: 0,
    content_types: 0,
    parse: 2,
    serialize: 2
  ]

  @table __MODULE__

  # The packages compiled into this library (design, *Scope for v1*). A kelixip
  # module does not register itself: it would be consuming an API meant for
  # third parties.
  @builtins [SIP.EventPackage.Presence, SIP.EventPackage.Dialog]

  @doc """
  One line saying what a document of a builtin package states, for a log.
  `nil` — no state — is said as such; a document no builtin models is named by
  its size or its type, never dumped.
  """
  @spec summary(term) :: binary()
  def summary(nil), do: "no state"
  def summary(%SIP.Presence.Doc{} = doc), do: SIP.Presence.Doc.summary(doc)
  def summary(%SIP.DialogInfo.Doc{} = doc), do: SIP.DialogInfo.Doc.summary(doc)
  def summary(body) when is_binary(body), do: "#{byte_size(body)}-byte body"
  def summary(%module{}), do: "a #{inspect(module)}"
  def summary(_other), do: "a document"

  @doc """
  Add `module` to the table under the name it answers to `name/0`.

  `opts[:origin]` is `:third_party` by default — the case this function is
  exposed for. The provided packages pass `origin: :builtin` from the boot path.

  Answers `:ok` when the table now names `module`, and
  `{:error, {:already_registered, other}}` when it does not, `other` being the
  module that keeps the name. Registering the same module twice is a no-op, so a
  caller may do it on every start without checking.
  """
  @spec register(module(), keyword()) ::
          :ok | {:error, {:already_registered, module()} | {:not_an_event_package, module()}}
  def register(module, opts \\ []) when is_atom(module) do
    origin = Keyword.get(opts, :origin, :third_party)

    with :ok <- implements_behaviour(module) do
      name = String.downcase(module.name())
      decide(name, module, origin, Map.get(table(), name))
    end
  end

  defp decide(name, module, origin, nil), do: put(name, module, origin)

  # Idempotent: the same module registering again refreshes nothing but its origin.
  defp decide(name, module, origin, %{module: module}), do: put(name, module, origin)

  defp decide(name, module, :third_party, %{module: provided, origin: :builtin}) do
    Logger.warning(
      "SIP.EventPackage: #{inspect(module)} overrides the provided package " <>
        "#{inspect(provided)} for event '#{name}'"
    )

    put(name, module, :third_party)
  end

  defp decide(name, module, _origin, %{module: incumbent}) do
    Logger.warning(
      "SIP.EventPackage: #{inspect(module)} refused for event '#{name}': " <>
        "#{inspect(incumbent)} already claims it"
    )

    {:error, {:already_registered, incumbent}}
  end

  defp put(name, module, origin) do
    :persistent_term.put(@table, Map.put(table(), name, %{module: module, origin: origin}))
    :ok
  end

  @doc """
  Register the packages this library provides.

  Called from the boot path — `SIP.FSL.Host.bootstrap/0` for a standalone run,
  `Kelix.Application` for a node — and idempotent, so calling it twice is what
  happens on a second run in one VM, not a bug.

  They go in as `:builtin`, which is what makes a third party allowed to override
  one (rule 4) instead of being refused.
  """
  @spec register_builtins() :: :ok
  def register_builtins do
    Enum.each(@builtins, &register(&1, origin: :builtin))
  end

  @doc """
  Drop the entry for a package name — or for a module, which answers its own name.

  Idempotent: dropping a name nobody claims is `:ok`. A module that unregisters on
  shutdown and a name the operator removed from the configuration both land here.
  """
  @spec unregister(binary() | module()) :: :ok
  def unregister(name) when is_binary(name) do
    :persistent_term.put(@table, Map.delete(table(), String.downcase(name)))
    :ok
  end

  def unregister(module) when is_atom(module) do
    case implements_behaviour(module) do
      :ok -> unregister(module.name())
      _not_a_package -> :ok
    end
  end

  @doc """
  The module implementing `name`, or `:error` when the node knows no such package
  — which the caller turns into a **489 Bad Event**, never into a crash.

  The name is matched case-insensitively.
  """
  @spec lookup(binary()) :: {:ok, module()} | :error
  def lookup(name) when is_binary(name) do
    case Map.fetch(table(), String.downcase(name)) do
      {:ok, %{module: module}} -> {:ok, module}
      :error -> :error
    end
  end

  @doc """
  Every package name the node knows, sorted.

  This is **not** what goes into `Allow-Events`: that header states what a *domain*
  enables, and two domains on one node may offer different packages
  (docs/design/presence-basic-plan.md, decision 3).
  """
  @spec names() :: [binary()]
  def names, do: table() |> Map.keys() |> Enum.sort()

  @doc """
  The whole table, `name => %{module: module, origin: origin}` — for `kelictl` and
  for a test that wants to put back what it found.
  """
  @spec registered() :: %{binary() => %{module: module(), origin: origin()}}
  def registered, do: table()

  defp table, do: :persistent_term.get(@table, %{})

  defp implements_behaviour(module) do
    Code.ensure_loaded(module)

    missing =
      Enum.reject(@callbacks, fn {fun, arity} -> function_exported?(module, fun, arity) end)

    if missing == [] do
      :ok
    else
      {:error, {:not_an_event_package, module}}
    end
  end
end
