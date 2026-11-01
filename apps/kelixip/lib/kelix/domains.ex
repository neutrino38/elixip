defmodule Kelix.Domains do
  @moduledoc """
  Holds the current `domains.toml` snapshot and swaps it **atomically** on reload
  (design `docs/design/DESIGN-KELIXIP.md`).

  The whole file is parsed and validated into a fresh `%Kelix.Domains{}` *off to
  the side* — including compiling every dial-plan pattern and, on the operator's
  reload, running the §5.3 load-time contract check on every **referenced script**
  (`check_scripts/1`); only if everything validates is it swapped in. One bad
  element ⇒ the reload is rejected and the current config stays intact — never a
  half-applied config. Reads (`current/0`) always see one consistent version.

  This module is both the supervised GenServer and the snapshot struct it holds:
    * `version`  — bumped on each successful reload
    * `domains`  — ordered `[%Kelix.Domain{}]`
    * `index`    — `name` + each literal alias (lower-cased) → `%Kelix.Domain{}` for O(1) lookup
    * `suffixes` — each wildcard alias (`*.gw.out`) as `{".gw.out", domain}`, longest first
    * `modules`  — raw `[module.*]` blocks (carried for the module system, P5)
    * `source`   — the decoded map of the whole file, what a write edits
    * `source_hash` — SHA-256 of the text the snapshot was parsed from
  """
  use GenServer
  require Logger

  alias Kelix.{Domain, DialRule, DialPlan, PresenceBlock}

  @type t :: %__MODULE__{
          version: non_neg_integer,
          domains: [Domain.t()],
          index: %{optional(String.t()) => Domain.t()},
          suffixes: [{String.t(), Domain.t()}],
          modules: %{optional(String.t()) => map},
          source: map,
          source_hash: binary | nil
        }

  defstruct version: 0,
            domains: [],
            index: %{},
            suffixes: [],
            modules: %{},
            source: %{},
            source_hash: nil

  @allowed_top_keys ~w(domain module)
  @registrar_keys %{
    "script" => :string,
    "default_expires" => :pos_integer,
    "min_expires" => :pos_integer,
    "keepalive_period" => :pos_integer
  }
  @presence_keys ~w(event-package subscribe publish)

  # ── GenServer API ────────────────────────────────────────────────────────────

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "The current snapshot (`%Kelix.Domains{}`)."
  @spec current() :: t
  def current(), do: GenServer.call(__MODULE__, :current)

  @doc """
  Atomically reload `domains.toml` from `path`. Returns `:ok` on success (the new
  version is swapped in) or `{:error, reason}` (current version kept intact).

  With `check_scripts: true` — what the operator command (`Kelix.Control.reload_domains/0`)
  passes — every script the file refers to must also pass the §5.3 load-time
  contract (`check_scripts/1`) before the swap: a config whose scripts are missing,
  uncompilable or not shutdown-aware is *not* servable, and is rejected here rather
  than discovered on the first call routed to it. Off by default, for the callers
  that only swap a snapshot without serving traffic from it (the test suite).

  Parsing, and the script check with it, run in the **caller's** process; the
  GenServer call is the swap alone. `current/0` is on the path of every inbound
  request — a reload compiling a handful of scenarios must not block it.
  """
  @spec reload(Path.t(), keyword) :: :ok | {:error, term}
  def reload(path, opts \\ []) do
    case load(path, Keyword.get(opts, :check_scripts, false)) do
      {:ok, snapshot} ->
        GenServer.call(__MODULE__, {:swap, snapshot})

      {:error, reason} = err ->
        Logger.error(
          module: __MODULE__,
          message: "domains.toml reload rejected: #{reason} — current version kept"
        )

        err
    end
  end

  @doc """
  Create or replace one domain, and write the result to `domains.toml`
  (`docs/design/dynamic-domains-plan.md`, §4).

  `doc` is one `[[domain]]` table as the file holds it — string keys, the same
  nesting. It replaces the domain of the same name, case-insensitively, in its
  place; a new name goes at the end. Nothing else in the file changes.

  The new file is encoded, parsed back and, unless `check_scripts: false`, its
  scripts checked, all in the caller's process. Then, in one GenServer call: the
  snapshot must still be at `:version` when one is given (`:conflict`), the file
  on disk must still be the text the snapshot was read from (`:file_changed`),
  and the node must be able to write it (`{:read_only, info}`). Only then is it
  written, through a sibling `.tmp` and a rename, and the snapshot swapped.

  Options: `:path` (required), `:version`, `:check_scripts` (default `true`).
  Returns the new snapshot, or `{:error, reason}` with nothing applied.
  """
  @spec put_domain(map, keyword) :: {:ok, t} | {:error, term}
  def put_domain(doc, opts) when is_map(doc) do
    with {:ok, name} <- doc_name(doc) do
      write(opts, fn domains ->
        case Enum.find_index(domains, &same_name?(&1, name)) do
          nil -> {:ok, domains ++ [doc]}
          i -> {:ok, List.replace_at(domains, i, doc)}
        end
      end)
    end
  end

  @doc """
  Remove the domain called `name` (its canonical name, case-insensitively, never an
  alias) and write the result to `domains.toml`. Same checks and options as
  `put_domain/2`; `{:error, :not_found}` when the file has no such domain.
  """
  @spec delete_domain(String.t(), keyword) :: {:ok, t} | {:error, term}
  def delete_domain(name, opts) when is_binary(name) do
    write(opts, fn domains ->
      case Enum.split_with(domains, &same_name?(&1, name)) do
        {[], _} -> {:error, :not_found}
        {_gone, kept} -> {:ok, kept}
      end
    end)
  end

  @doc """
  Whether the node can write `path` the way a write does: the file itself, and a
  `.tmp` created next to it. `:ok`, or `{:error, {:read_only, info}}` where `info`
  names the path, the system reason and the user the node runs as.
  """
  @spec writable(Path.t()) :: :ok | {:error, {:read_only, map}}
  def writable(path) do
    # its own name: `kelictl status` probes while a write may hold `path.tmp`
    tmp = "#{path}.#{System.unique_integer([:positive])}.tmp"

    with :ok <- check_write(path, if(File.exists?(path), do: :ok, else: {:error, :enoent})),
         :ok <- check_write(path, File.open(path, [:read, :write])),
         :ok <- check_write(tmp, File.write(tmp, "")) do
      File.rm(tmp)
      :ok
    end
  end

  @doc """
  Whether the file at `path` is no longer the text `snapshot` was read from: it was
  edited by hand and not reloaded, or it is gone. A write is then refused with
  `:file_changed`, so that it does not erase the edit.
  """
  @spec file_changed?(t, Path.t()) :: boolean
  def file_changed?(%__MODULE__{source_hash: hash}, path) do
    case File.read(path) do
      {:ok, text} -> :crypto.hash(:sha256, text) != hash
      {:error, _} -> true
    end
  end

  defp check_write(_path, {:ok, io}) when is_pid(io), do: File.close(io)
  defp check_write(_path, :ok), do: :ok

  defp check_write(path, {:error, reason}),
    do: {:error, {:read_only, %{path: path, reason: reason, user: os_user()}}}

  defp os_user() do
    case System.cmd("id", ["-un"], stderr_to_stdout: true) do
      {user, 0} -> String.trim(user)
      _ -> System.get_env("USER", "unknown")
    end
  rescue
    _ -> System.get_env("USER", "unknown")
  end

  defp doc_name(%{"name" => name}) when is_binary(name) and name != "", do: {:ok, name}
  defp doc_name(_), do: {:error, {:invalid, "the domain needs a non-empty `name`"}}

  defp same_name?(%{"name" => n}, name) when is_binary(n),
    do: String.downcase(n) == String.downcase(name)

  defp same_name?(_entry, _name), do: false

  defp write(opts, edit) do
    path = Keyword.fetch!(opts, :path)
    current = current()
    domains = Map.get(current.source, "domain", [])

    with {:ok, domains} <- edit.(domains),
         source = Map.put(current.source, "domain", domains),
         {:ok, text} <- tag(Kelix.Domains.Toml.encode(source), :invalid),
         {:ok, snapshot} <- tag(parse(text), :invalid),
         :ok <-
           if(Keyword.get(opts, :check_scripts, true),
             do: tag(check_scripts(snapshot), :scripts),
             else: :ok
           ) do
      GenServer.call(__MODULE__, {:write, snapshot, text, path, Keyword.get(opts, :version)})
    end
  end

  defp tag({:error, message}, tag) when is_binary(message), do: {:error, {tag, message}}
  defp tag(ok, _tag), do: ok

  @doc """
  The event packages a domain serves, in declaration order — what a notifier
  script puts in `Allow-Events`.

  Takes the domain by name (what a scenario carries in its context) or the struct
  itself. An unknown domain, or one serving none, answers `[]`.
  """
  @spec event_packages(String.t() | Domain.t()) :: [String.t()]
  def event_packages(%Domain{presence: blocks}), do: Enum.map(blocks, & &1.event_package)

  def event_packages(name) when is_binary(name) do
    case Process.whereis(__MODULE__) && lookup(current(), name) do
      %Domain{} = domain -> event_packages(domain)
      _ -> []
    end
  end

  @doc """
  Resolve a host (R-URI/To host) to its domain, or nil. `name` + aliases,
  case-insensitive.

  A literal name or alias always wins over a wildcard alias, and among wildcards
  the longest suffix wins — so declaring `a.gw.out` alongside a `*.gw.out` domain
  routes `a.gw.out` to the specific one, not to the catch-all.
  """
  @spec lookup(t, String.t()) :: Domain.t() | nil
  def lookup(%__MODULE__{index: index, suffixes: suffixes}, host) when is_binary(host) do
    host = String.downcase(host)

    case Map.get(index, host) do
      nil -> Enum.find_value(suffixes, fn {sfx, d} -> String.ends_with?(host, sfx) && d end)
      %Domain{} = d -> d
    end
  end

  @doc """
  The nominal name of the domain `host` belongs to — an alias folds to it — or
  `host` itself when no domain claims it, or when the table is not running (a
  unit test). What a module keys per-domain state on, so an alias and the name
  it stands for share one store.
  """
  @spec nominal(String.t() | nil) :: String.t() | nil
  def nominal(nil), do: nil

  def nominal(host) when is_binary(host) do
    with pid when not is_nil(pid) <- Process.whereis(__MODULE__),
         %Domain{name: name} <- lookup(current(), host) do
      name
    else
      _ -> host
    end
  end

  # ── GenServer callbacks ──────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    case Keyword.get(opts, :path) do
      nil ->
        # No path (elixipp, tests, a bare release): boot with an empty snapshot.
        {:ok, %__MODULE__{}}

      path ->
        # No script check here, deliberately: the `[module.*]` blocks live in this
        # very file, so `Kelix.ModuleSupervisor` can only start the modules once the
        # snapshot exists — and a script's `uses_modules` can only be resolved once
        # those modules are loaded. The boot check is therefore a later child in the
        # tree (`Kelix.ScriptPreflight`), which aborts the boot on a bad script.
        case load(path, false) do
          {:ok, snapshot} ->
            warn_unwritable(path)
            {:ok, %{snapshot | version: 1}}

          {:error, reason} ->
            # A release dying during boot flushes no Logger output, so state the
            # reason on stderr for journald (same as Kelix.Config).
            IO.puts(:stderr, "kelixip: invalid domains in #{path}: #{reason}")
            {:stop, {:invalid_domains, reason}}
        end
    end
  end

  # The node serves the file either way; only the writes through the frontals
  # need it, and each of them answers `read_only` on its own.
  defp warn_unwritable(path) do
    with {:error, {:read_only, %{reason: reason, user: user}}} <- writable(path) do
      Logger.warning(
        module: __MODULE__,
        message:
          "#{path} is not writable by #{user} (#{reason}): domain edits will be " <>
            "refused until the file and its directory belong to #{user}"
      )
    end
  end

  @impl true
  def handle_call(:current, _from, state), do: {:reply, state, state}

  # The swap itself: the snapshot arrives fully parsed and validated (reload/2), so
  # this cannot fail — it only stamps the next version and replaces the state.
  def handle_call({:swap, snapshot}, _from, state) do
    snapshot = %{snapshot | version: state.version + 1}

    Logger.info(
      module: __MODULE__,
      message: "domains.toml reloaded (v#{snapshot.version}, #{length(snapshot.domains)} domains)"
    )

    {:reply, :ok, snapshot}
  end

  def handle_call({:write, snapshot, text, path, expected}, _from, state) do
    with :ok <- same_version(state, expected),
         :ok <- same_file(state, path),
         :ok <- writable(path),
         :ok <- write_file(path, text) do
      snapshot = %{snapshot | version: state.version + 1}

      Logger.info(
        module: __MODULE__,
        message:
          "domains.toml written (v#{snapshot.version}, #{length(snapshot.domains)} domains)"
      )

      {:reply, {:ok, snapshot}, snapshot}
    else
      err -> {:reply, err, state}
    end
  end

  defp same_version(_state, nil), do: :ok
  defp same_version(%{version: v}, v), do: :ok
  defp same_version(_state, _expected), do: {:error, :conflict}

  # A hand edit not reloaded yet is the operator's, and a write would erase it.
  defp same_file(state, path),
    do: if(file_changed?(state, path), do: {:error, :file_changed}, else: :ok)

  defp write_file(path, text) do
    tmp = path <> ".tmp"
    mode = with {:ok, %File.Stat{mode: m}} <- File.stat(path), do: Bitwise.band(m, 0o777)

    with :ok <- File.write(tmp, text),
         :ok <- if(is_integer(mode), do: File.chmod(tmp, mode), else: :ok),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, reason} ->
        File.rm(tmp)
        {:error, {:write_failed, %{path: path, reason: reason}}}
    end
  end

  defp load(path, check_scripts?) do
    with {:ok, content} <- read_file(path),
         {:ok, snapshot} <- parse(content),
         :ok <- if(check_scripts?, do: check_scripts(snapshot), else: :ok) do
      {:ok, snapshot}
    end
  end

  defp read_file(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, reason} -> {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  # ── referenced scripts: enumeration + load-time contract check ───────────────

  @doc """
  Every script a snapshot refers to — the `registrar`/`presence` block's `script`
  and each dial-plan, chat and options rule's — as `[{name, context}]`, deduped by name (first
  reference wins). `context` says *where* the reference comes from, so an error
  message can name the domain and the rule an operator has to go and fix.
  """
  @spec script_refs(t) :: [{String.t(), String.t()}]
  def script_refs(%__MODULE__{domains: domains}) do
    domains
    |> Enum.flat_map(&domain_script_refs/1)
    |> Enum.uniq_by(&elem(&1, 0))
  end

  defp domain_script_refs(%Domain{} = d) do
    registrar_refs =
      for block <- List.wrap(d.registrar),
          do: {block.script, "domain #{d.name} [domain.registrar]"}

    # Every script of every block: a node whose `publish` script is missing serves
    # SUBSCRIBE and dies on the first PUBLISH, which is exactly what the load-time
    # contract exists to catch.
    presence_refs =
      for block <- d.presence,
          {key, script} <-
            Enum.map(block.subscribe, &{"subscribe rule #{rule_label(&1)}", &1.script}) ++
              [{"publish", block.publish}],
          is_binary(script),
          do:
            {script,
             "domain #{d.name} [[domain.presence]] #{key} " <>
               "(event-package #{block.event_package})"}

    call_refs =
      for rule <- d.dial_plan,
          do: {rule.script, "domain #{d.name} call rule #{rule_label(rule)}"}

    chat_refs =
      for rule <- d.chat,
          do: {rule.script, "domain #{d.name} chat rule #{rule_label(rule)}"}

    options_refs =
      for script <- List.wrap(d.options_keepalive),
          do: {script, "domain #{d.name} options rule keepalive = true"}

    options_refs =
      options_refs ++
        for rule <- d.options,
            do: {rule.script, "domain #{d.name} options rule #{rule_label(rule)}"}

    registrar_refs ++ presence_refs ++ call_refs ++ chat_refs ++ options_refs
  end

  defp rule_label(%DialRule{default?: true}), do: "default = true"
  defp rule_label(%DialRule{raw: raw}), do: inspect(raw)

  @doc """
  Run the §5.3 load-time contract check on every script a snapshot refers to,
  through `Kelix.ScriptRegistry.validate/1` — the one place that knows what a
  servable script is (present, compiling, a scenario, shutdown-aware, its declared
  `uses_modules` loaded). `:ok`, or `{:error, message}` listing each offender with
  the domain and rule that names it.

  Called on the operator's reload (`reload/2` with `check_scripts: true`) and at
  boot (`Kelix.ScriptPreflight`) — not from `init/1`, see the comment there.
  """
  @spec check_scripts(t) :: :ok | {:error, String.t()}
  def check_scripts(%__MODULE__{} = snapshot) do
    refs = script_refs(snapshot)

    cond do
      refs == [] ->
        :ok

      is_nil(Process.whereis(Kelix.ScriptRegistry)) ->
        {:error,
         "cannot check the #{length(refs)} referenced script(s): Kelix.ScriptRegistry is not running"}

      true ->
        case Kelix.ScriptRegistry.validate(Enum.map(refs, &elem(&1, 0))) do
          :ok -> :ok
          {:error, failures} -> {:error, format_failures(refs, failures)}
        end
    end
  end

  defp format_failures(refs, failures) do
    contexts = Map.new(refs)

    "#{length(failures)} script(s) rejected:" <>
      Enum.map_join(failures, "", fn {name, reason} ->
        "\n  - #{Map.get(contexts, name, name)}: #{describe(reason)}"
      end)
  end

  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason), do: inspect(reason)

  # ── Pure parse + validation (testable without the GenServer) ─────────────────

  @doc """
  Parse + validate a `domains.toml` string into a `%Kelix.Domains{}` (version 0).
  Returns `{:ok, snapshot}` or `{:error, message}` with a clear reason.
  """
  @spec parse(String.t()) :: {:ok, t} | {:error, String.t()}
  def parse(content) when is_binary(content) do
    with {:ok, map} <- decode(content),
         :ok <- check_top_keys(map),
         {:ok, domains} <- parse_domains(Map.get(map, "domain", [])),
         {:ok, {index, suffixes}} <- build_index(domains) do
      {:ok,
       %__MODULE__{
         version: 0,
         domains: domains,
         index: index,
         suffixes: suffixes,
         modules: Map.get(map, "module", %{}),
         source: map,
         source_hash: :crypto.hash(:sha256, content)
       }}
    end
  end

  defp decode(content) do
    case Toml.decode(content) do
      {:ok, map} -> {:ok, map}
      {:error, reason} -> {:error, "invalid TOML: #{inspect(reason)}"}
    end
  end

  defp check_top_keys(map) do
    case Map.keys(map) -- @allowed_top_keys do
      [] -> :ok
      extra -> {:error, "unknown top-level key(s): #{Enum.join(extra, ", ")}"}
    end
  end

  defp parse_domains(list) when is_list(list) do
    reduce_while_ok(list, fn dm -> parse_domain(dm) end)
  end

  defp parse_domains(_), do: {:error, "`domain` must be an array of tables ([[domain]])"}

  defp parse_domain(%{} = dm) do
    with {:ok, name} <- req_string(dm, "name", "domain"),
         {:ok, aliases} <- opt_string_list(dm, "aliases", name),
         :ok <- check_aliases(aliases, name),
         {:ok, max_calls} <- opt_pos_integer(dm, "max_calls", name),
         {:ok, registrar} <- opt_fn_block(dm, "registrar", @registrar_keys, name),
         {:ok, presence} <- parse_presence(Map.get(dm, "presence", []), name),
         {:ok, dial_plan} <- parse_dial_plan(Map.get(dm, "call", []), name),
         {:ok, chat} <- parse_dial_plan(Map.get(dm, "chat", []), name, "chat"),
         {:ok, {keepalive, options}} <- parse_options(Map.get(dm, "options", []), name),
         :ok <- check_domain_keys(dm, name) do
      {:ok,
       %Domain{
         name: name,
         aliases: aliases,
         max_calls: max_calls,
         registrar: registrar,
         presence: presence,
         dial_plan: dial_plan,
         chat: chat,
         options: options,
         options_keepalive: keepalive
       }}
    end
  end

  defp parse_domain(_), do: {:error, "each [[domain]] must be a table"}

  @domain_keys ~w(name aliases max_calls registrar presence call chat options)
  defp check_domain_keys(dm, name) do
    case Map.keys(dm) -- @domain_keys do
      [] -> :ok
      extra -> {:error, "domain #{inspect(name)}: unknown key(s): #{Enum.join(extra, ", ")}"}
    end
  end

  # ── dial-plan (ordered; first-match-wins; one catch-all, last) ───────────────
  #
  # `[[domain.call]]` and `[[domain.chat]]` are the same list — a pattern on the
  # R-URI user part, first match wins, `default = true` last — so they are one
  # parser, and `key` is only what the messages call the block.

  defp parse_dial_plan(rules, domain, key \\ "call")

  defp parse_dial_plan(rules, domain, key) when is_list(rules) do
    with {:ok, parsed} <- reduce_while_ok(rules, fn r -> parse_rule(r, domain, key) end),
         :ok <- validate_catch_all(parsed, domain, key) do
      {:ok, parsed}
    end
  end

  defp parse_dial_plan(_, domain, key),
    do: {:error, "domain #{inspect(domain)}: `#{key}` must be an array of tables"}

  defp parse_rule(%{"default" => true} = r, domain, key) do
    what = "default #{key} rule (domain #{domain})"

    with {:ok, script} <- req_string(r, "script", "#{key} rule (domain #{domain})"),
         :ok <- reject_keys(r, ~w(default script) ++ rule_keys(key), what),
         {:ok, rule} <-
           parse_conversation(%DialRule{default?: true, script: script}, r, key, what) do
      {:ok, rule}
    end
  end

  defp parse_rule(%{"pattern" => pattern} = r, domain, key) when is_binary(pattern) do
    what = "#{key} rule (domain #{domain})"

    with {:ok, script} <- req_string(r, "script", what),
         :ok <- reject_keys(r, ~w(pattern script) ++ rule_keys(key), what),
         {:ok, matcher} <- compile_pattern(pattern, domain),
         rule = %DialRule{matcher: matcher, raw: pattern, script: script},
         {:ok, rule} <- parse_conversation(rule, r, key, what) do
      {:ok, rule}
    end
  end

  defp parse_rule(_, domain, "options"),
    do:
      {:error,
       "domain #{inspect(domain)}: each [[domain.options]] needs `keepalive = true`, " <>
         "`pattern = \"...\"` or `default = true`"}

  defp parse_rule(_, domain, key),
    do:
      {:error,
       "domain #{inspect(domain)}: each [[domain.#{key}]] needs `pattern = \"...\"` or `default = true`"}

  # A chat rule says how long one of its conversations lasts silent
  # (chat-basic-plan, C3b). A call rule has no such thing: a call is its dialog.
  defp rule_keys("chat"), do: ~w(idle_timeout)
  defp rule_keys(_key), do: []

  @default_idle_timeout 300

  defp parse_conversation(rule, r, "chat", what) do
    with {:ok, idle} <- idle_timeout(Map.get(r, "idle_timeout", @default_idle_timeout), what) do
      {:ok, %DialRule{rule | idle_timeout: idle}}
    end
  end

  defp parse_conversation(rule, _r, _key, _what), do: {:ok, rule}

  defp idle_timeout(value, _what) when is_integer(value) and value > 0, do: {:ok, value}

  defp idle_timeout(value, what),
    do:
      {:error,
       "#{what}: `idle_timeout` must be a positive integer (seconds), got #{inspect(value)}"}

  # ── OPTIONS (one keepalive rule for `sip:domain`, then a dial-plan) ───────────

  # The keepalive rule serves an R-URI with no user-part, which no pattern is ever
  # tried against, so its position among the others does not matter.
  defp parse_options(rules, domain) when is_list(rules) do
    {keepalives, others} = Enum.split_with(rules, &match?(%{"keepalive" => _}, &1))

    with {:ok, keepalive} <- parse_keepalive(keepalives, domain),
         {:ok, parsed} <- reduce_while_ok(others, &parse_rule(&1, domain, "options")),
         :ok <- validate_catch_all(parsed, domain, "options") do
      {:ok, {keepalive, parsed}}
    end
  end

  defp parse_options(_, domain),
    do: {:error, "domain #{inspect(domain)}: `options` must be an array of tables"}

  defp parse_keepalive([], _domain), do: {:ok, nil}

  defp parse_keepalive([%{"keepalive" => true} = r], domain) do
    ctx = "keepalive options rule (domain #{domain})"

    with {:ok, script} <- req_string(r, "script", ctx),
         :ok <- reject_keys(r, ~w(keepalive script), ctx) do
      {:ok, script}
    end
  end

  defp parse_keepalive([_], domain),
    do: {:error, "domain #{inspect(domain)}: `keepalive` must be `true` or absent"}

  defp parse_keepalive(_, domain),
    do:
      {:error,
       "domain #{inspect(domain)}: at most one [[domain.options]] rule has keepalive = true"}

  defp compile_pattern(pattern, domain) do
    case DialPlan.compile(pattern) do
      {:ok, matcher} ->
        {:ok, matcher}

      {:error, reason} ->
        {:error,
         "domain #{inspect(domain)}: bad pattern #{inspect(pattern)} (#{inspect(reason)})"}
    end
  end

  defp validate_catch_all(rules, domain, key) do
    case Enum.split_while(rules, &(not &1.default?)) do
      {_before, []} ->
        :ok

      {_before, [_default]} ->
        :ok

      {_before, [_default | _after]} ->
        {:error,
         "domain #{inspect(domain)}: the catch-all (default = true) must be the last #{key} rule"}
    end
  end

  # ── presence (one block per event package; the package is the key) ───────────

  defp parse_presence(blocks, domain) when is_list(blocks) do
    with {:ok, parsed} <- reduce_while_ok(blocks, &parse_presence_block(&1, domain)),
         :ok <- reject_duplicate_packages(parsed, domain) do
      {:ok, parsed}
    end
  end

  # A single `[domain.presence]` table is the shape this key had before it carried
  # the event package. Saying so beats "must be an array of tables": the operator
  # upgrading a node has the old form under their eyes, and the new one names a
  # package theirs did not have to.
  defp parse_presence(%{}, domain) do
    {:error,
     "domain #{inspect(domain)}: presence is an array of tables, one per event " <>
       "package — write [[domain.presence]] with event-package = \"presence\""}
  end

  defp parse_presence(_, domain),
    do: {:error, "domain #{inspect(domain)}: `presence` must be an array of tables"}

  defp parse_presence_block(%{} = block, domain) do
    ctx = "domain #{domain} [[domain.presence]]"

    with :ok <- reject_lists(block, ctx),
         :ok <- reject_keys(block, @presence_keys, ctx),
         {:ok, package} <- req_string(block, "event-package", ctx),
         {:ok, subscribe} <- parse_subscribe(Map.get(block, "subscribe"), domain, ctx),
         {:ok, publish} <- opt_script(block, "publish", ctx) do
      {:ok,
       %PresenceBlock{
         # The package name is matched against `Event`, which is case-insensitive
         # (RFC 6665 §8.2.1) — folded once here so nothing downcases at lookup.
         event_package: String.downcase(package),
         subscribe: subscribe,
         publish: publish
       }}
    end
  end

  defp parse_presence_block(_, domain),
    do: {:error, "domain #{inspect(domain)}: each [[domain.presence]] must be a table"}

  # Two blocks claiming one package: the second would be unreachable, and which of
  # the two serves a SUBSCRIBE would be decided by declaration order rather than by
  # the operator. Refused at parse time, like a domain name used twice.
  defp reject_duplicate_packages(blocks, domain) do
    case blocks
         |> Enum.frequencies_by(& &1.event_package)
         |> Enum.find(fn {_p, n} -> n > 1 end) do
      nil ->
        :ok

      {package, _n} ->
        {:error,
         "domain #{inspect(domain)}: event package #{inspect(package)} is served by " <>
           "more than one [[domain.presence]] block"}
    end
  end

  # The SUBSCRIBE rules are the dial-plan's reading, on the R-URI of a SUBSCRIBE:
  # a resource list, a conference room range and the domain's users are three
  # rules of one list. A plain string is the one-rule shorthand, a catch-all.
  defp parse_subscribe(script, _domain, _ctx) when is_binary(script) and script != "",
    do: {:ok, [%DialRule{default?: true, script: script}]}

  defp parse_subscribe([_ | _] = rules, domain, _ctx),
    do: parse_dial_plan(rules, domain, "presence.subscribe")

  defp parse_subscribe(_other, _domain, ctx),
    do:
      {:error,
       "#{ctx}: `subscribe` is required — a script, or [[domain.presence.subscribe]] " <>
         "rules (`pattern` or `default = true`, and `script`)"}

  # `lists` / `list-subscribe` routed a resource list before SUBSCRIBE had rules.
  # Named, rather than refused as two unknown keys, so the operator reads what
  # replaces them.
  defp reject_lists(block, ctx) do
    if Map.has_key?(block, "lists") or Map.has_key?(block, "list-subscribe") do
      {:error,
       "#{ctx}: `lists` / `list-subscribe` are gone — declare the list as a SUBSCRIBE " <>
         "rule: [[domain.presence.subscribe]] pattern = \"rls\" script = \"presence-rls.exs\""}
    else
      :ok
    end
  end

  defp opt_script(block, key, ctx) do
    case Map.get(block, key) do
      nil -> {:ok, nil}
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> {:error, "#{ctx}: `#{key}` must be a non-empty string"}
    end
  end

  # ── aliases: literal hosts, or `*.suffix` ────────────────────────────────────

  # `*.suffix` is the only wildcard shape, and it matches any host ending in
  # `.suffix`, at whatever depth. A `*` anywhere else is a typo, not a pattern:
  # accepting it silently would route traffic an operator never meant to serve.
  defp check_aliases(aliases, domain) do
    case Enum.find(aliases, &bad_alias?/1) do
      nil ->
        :ok

      bad ->
        {:error,
         "domain #{inspect(domain)}: bad alias #{inspect(bad)} — " <>
           "a wildcard alias is written `*.suffix`"}
    end
  end

  defp bad_alias?("*." <> rest), do: rest == "" or String.contains?(rest, "*")
  defp bad_alias?(alias_), do: String.contains?(alias_, "*")

  defp wildcard?("*." <> _), do: true
  defp wildcard?(_), do: false

  # `*.gw.out` -> `.gw.out`: the leading dot is kept, so the suffix never matches
  # a host that merely *ends* with the letters (`notgw.out`).
  defp wildcard_suffix("*" <> suffix), do: suffix

  # ── index (name + aliases -> domain; collisions rejected) ────────────────────

  defp build_index(domains) do
    result =
      Enum.reduce_while(domains, {:ok, {%{}, %{}}}, fn d, {:ok, {exact, wild}} ->
        {wildcards, literals} =
          d.aliases |> Enum.map(&String.downcase/1) |> Enum.split_with(&wildcard?/1)

        keys = [String.downcase(d.name) | literals]

        dup =
          Enum.find(keys, &Map.has_key?(exact, &1)) ||
            Enum.find(wildcards, &Map.has_key?(wild, wildcard_suffix(&1)))

        if dup do
          {:halt, {:error, "domain name/alias #{inspect(dup)} is used by more than one domain"}}
        else
          {:cont,
           {:ok,
            {Enum.reduce(keys, exact, &Map.put(&2, &1, d)),
             Enum.reduce(wildcards, wild, &Map.put(&2, wildcard_suffix(&1), d))}}}
        end
      end)

    with {:ok, {exact, wild}} <- result do
      {:ok, {exact, Enum.sort_by(Map.to_list(wild), fn {sfx, _} -> -byte_size(sfx) end)}}
    end
  end

  # ── small validators ─────────────────────────────────────────────────────────

  defp req_string(map, key, ctx) do
    case Map.get(map, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      nil -> {:error, "#{ctx}: missing required `#{key}`"}
      _ -> {:error, "#{ctx}: `#{key}` must be a non-empty string"}
    end
  end

  defp opt_string_list(map, key, ctx) do
    case Map.get(map, key) do
      nil ->
        {:ok, []}

      list when is_list(list) ->
        if Enum.all?(list, &is_binary/1),
          do: {:ok, list},
          else: {:error, "domain #{inspect(ctx)}: `#{key}` must be a list of strings"}

      _ ->
        {:error, "domain #{inspect(ctx)}: `#{key}` must be a list of strings"}
    end
  end

  defp opt_pos_integer(map, key, ctx) do
    case Map.get(map, key) do
      nil -> {:ok, nil}
      v when is_integer(v) and v > 0 -> {:ok, v}
      _ -> {:error, "domain #{inspect(ctx)}: `#{key}` must be a positive integer"}
    end
  end

  # a function block ([domain.registrar]): present = enabled
  defp opt_fn_block(map, key, allowed, domain) do
    case Map.get(map, key) do
      nil ->
        {:ok, nil}

      %{} = block ->
        ctx = "domain #{domain} [domain.#{key}]"

        with :ok <- reject_keys(block, Map.keys(allowed), ctx),
             {:ok, _} <- req_string(block, "script", ctx),
             {:ok, cfg} <- pick_typed(block, allowed, ctx) do
          {:ok, cfg}
        end

      _ ->
        {:error, "domain #{domain}: [domain.#{key}] must be a table"}
    end
  end

  # build an atom-keyed config map from a whitelist (no String.to_atom on input)
  defp pick_typed(block, allowed, ctx) do
    Enum.reduce_while(allowed, {:ok, %{}}, fn {key, type}, {:ok, acc} ->
      case Map.get(block, key) do
        nil ->
          {:cont, {:ok, acc}}

        v ->
          case check_type(v, type) do
            :ok -> {:cont, {:ok, Map.put(acc, known_atom(key), v)}}
            :error -> {:halt, {:error, "#{ctx}: `#{key}` must be #{type}"}}
          end
      end
    end)
  end

  defp check_type(v, :string) when is_binary(v), do: :ok
  defp check_type(v, :pos_integer) when is_integer(v) and v > 0, do: :ok
  defp check_type(_, _), do: :error

  # whitelist -> atom (compile-time-known keys only; never String.to_atom on input)
  defp known_atom("script"), do: :script
  defp known_atom("default_expires"), do: :default_expires
  defp known_atom("min_expires"), do: :min_expires
  defp known_atom("keepalive_period"), do: :keepalive_period

  defp reject_keys(map, allowed, ctx) do
    case Map.keys(map) -- allowed do
      [] -> :ok
      extra -> {:error, "#{ctx}: unknown key(s): #{Enum.join(extra, ", ")}"}
    end
  end

  # reduce a list, stopping at the first {:error, _}
  defp reduce_while_ok(list, fun) do
    result =
      Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
        case fun.(item) do
          {:ok, parsed} -> {:cont, {:ok, [parsed | acc]}}
          {:error, _} = err -> {:halt, err}
        end
      end)

    with {:ok, acc} <- result, do: {:ok, Enum.reverse(acc)}
  end
end
