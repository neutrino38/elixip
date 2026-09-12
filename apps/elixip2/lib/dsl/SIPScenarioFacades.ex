# The names the SIP side of Elixip knows the FSL engine by.
#
# The language and its engine live in `FSL.*` (extraction plan §2.1); these are
# the names three apps, a dozen tests, the `mix scenario` task and the kelixip
# server call them by. They are kept because a rename a compiler would catch
# here is a node that fails to start in the field: `.exs` scenarios and kelixip
# scripts are loaded at *run* time, from `/etc/kelixip/scripts` and from customer
# directories.
#
# Each module below delegates and adds nothing, with one exception noted on
# `SIP.Scenario.Monitor`: a **registered name** is the one thing a facade cannot
# forward.

defmodule SIP.Scenario.Runner do
  @moduledoc """
  `FSL.Runner` under the name Elixip calls it. See that module for the FSM loop.
  """

  @doc "See `FSL.Runner.run/2`."
  defdelegate run(module, start_stack?), to: FSL.Runner

  @doc "See `FSL.Runner.run_instance/2`."
  defdelegate run_instance(module, opts \\ []), to: FSL.Runner

  @doc "See `FSL.Runner.spawn_uas_instance/2`."
  defdelegate spawn_uas_instance(target, opts \\ []), to: FSL.Runner

  @doc """
  Start the SIP layers. `SIP.FSL.Host.bootstrap/0` is what they are.
  """
  defdelegate bootstrap_stack(), to: SIP.FSL.Host, as: :bootstrap

  @doc """
  Build a `%SIP.Context{}` from a `config` keyword list.
  `SIP.FSL.Host.build_context/1` is where the routing lives.
  """
  defdelegate build_context(config), to: SIP.FSL.Host

  @doc false
  defdelegate spawn_child(ctx, target, opts, parent_pid, base_dir \\ nil), to: FSL.Runner

  @doc false
  defdelegate run_sbb(ctx, module, opts \\ []), to: FSL.Runner

  @doc false
  defdelegate note_stay(module, ctx, desc, type), to: FSL.Runner

  @doc false
  defdelegate notify_child(ctx, name, payload), to: FSL.Runner

  @doc false
  defdelegate notify_parent(ctx, payload), to: FSL.Runner

  @doc false
  defdelegate sbb_data_get(ctx, module, key), to: FSL.Runner

  @doc false
  defdelegate sbb_data_set(ctx, module, key, value), to: FSL.Runner
end

defmodule SIP.Scenario.Loader do
  @moduledoc """
  `FSL.Loader` under the name Elixip calls it, plus the one thing that is SIP's:
  the default role of a scenario that declares none.
  """

  @doc "See `FSL.Loader.load_file!/1`."
  defdelegate load_file!(path), to: FSL.Loader

  @doc "See `FSL.Loader.load_module!/1`."
  defdelegate load_module!(name), to: FSL.Loader

  @doc """
  The role this scenario declared: `:uac`, `:uas_register`, `:uas_invite`.

  `:uac` is the default, and it is applied here rather than in `FSL.Loader`
  because it is a SIP role name — the language keeps the slot opaque and has no
  opinion on what a machine that declared nothing is (extraction plan §4.11).
  Scenarios compiled before the `uas` annotation existed have no
  `__scenario_type__/0` at all and land on the same default.
  """
  @spec scenario_type(module()) :: atom()
  def scenario_type(module), do: FSL.Loader.scenario_type(module) || :uac
end

defmodule SIP.Scenario.SequenceJournal do
  @moduledoc "`FSL.Journal` under the name Elixip calls it."

  @doc false
  defdelegate start(meta), to: FSL.Journal

  @doc false
  defdelegate record_command(type, name), to: FSL.Journal

  @doc false
  defdelegate record_transition(to, event, type), to: FSL.Journal

  @doc false
  defdelegate events(), to: FSL.Journal

  @doc false
  defdelegate enabled?(), to: FSL.Journal

  @doc false
  defdelegate meta(), to: FSL.Journal

  @doc false
  defdelegate flush(), to: FSL.Journal

  @doc false
  defdelegate clear(), to: FSL.Journal
end

defmodule SIP.Scenario.SequenceDiagram do
  @moduledoc "`FSL.Diagram.PlantUML` under the name Elixip calls it."

  @doc false
  defdelegate to_plantuml(events, meta), to: FSL.Diagram.PlantUML

  @doc false
  defdelegate filename(meta), to: FSL.Diagram.PlantUML

  @doc false
  defdelegate safe_pid(pid_string), to: FSL.Diagram.PlantUML
end

defmodule SIP.Scenario.Monitor do
  @moduledoc """
  `FSL.Monitor` under the name Elixip calls it — for everything except the one
  thing a facade cannot forward.

  **The registered name is `FSL.Monitor`.** `defdelegate` covers `calls/0` and
  every `note_*`; it does nothing for a `Process.whereis/1` or a supervision
  child spec. So the four places that name the process were changed together
  (extraction plan §4.7): `Kelix.Application`'s supervision tree, elixipp's
  `--monitor` bootstrap, `Kelix.InstancePool`'s subscription, and the runner's
  own `whereis`.

  **The push tag is `{:fsl_monitor, …}`.** That one is not compile-checked
  either: a missed `handle_info` clause is a message that falls through and a
  live view that silently stops updating, which is why the rename came with a
  test that subscribes, triggers a change and asserts the tuple, on both halves
  of the chain.
  """

  @doc false
  defdelegate start(opts \\ []), to: FSL.Monitor

  @doc false
  defdelegate start_link(opts \\ []), to: FSL.Monitor

  @doc false
  defdelegate child_spec(opts), to: FSL.Monitor

  @doc "See `FSL.Monitor.report/6`."
  defdelegate report(call_id, scenario, username, state, event, event_type \\ nil),
    to: FSL.Monitor

  @doc "See `FSL.Monitor.note/2`."
  defdelegate note(key, value), to: FSL.Monitor

  @doc false
  defdelegate note_account(username), to: FSL.Monitor

  @doc false
  defdelegate note_medias(kinds), to: FSL.Monitor

  @doc false
  defdelegate note_mediaserver(name), to: FSL.Monitor

  @doc false
  defdelegate note_outbound(uri), to: FSL.Monitor

  @doc false
  defdelegate note_command(type, command), to: FSL.Monitor

  @doc false
  defdelegate calls(), to: FSL.Monitor

  @doc false
  defdelegate clear(slot_id), to: FSL.Monitor

  @doc false
  defdelegate subscribe(pid), to: FSL.Monitor

  @doc false
  defdelegate unsubscribe(pid), to: FSL.Monitor
end

defmodule HTTP.Session do
  @moduledoc """
  `FSL.HTTP` under the name the example scenario uses. HTTP-as-events is the
  language's, not SIP's — the name is kept because
  `scenarios/http_get_example.exs` says `use HTTP.Session` and a scenario
  already written must keep running.
  """

  defmacro __using__(_opts) do
    quote do
      use FSL.HTTP
    end
  end

  @doc false
  defdelegate get_async(url, timeout, tag, req_opts \\ []), to: FSL.HTTP
end
