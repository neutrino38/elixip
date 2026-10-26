defmodule Kelix.Mod.Captioning do
  @moduledoc """
  The correction service of a captioned call (call-captioning spec §6, phase 2):
  answer the client's captioning INFO, and hand it a single-use `wss://` URL to
  the speech-server's `comp` function when it asks for one.

  The client sends, once the call is up, an in-dialog INFO of type
  `application/captioning+xml` (`Kelix.Mod.Captioning.Body`). Captions are on from
  the answer whatever it says — `call-captioning.exs` starts the transcription
  with the call — so the INFO only confirms them, and asks, with `comp="true"`,
  for the correction of what the user types. For that this module mints a token
  on the speech-server's control API (`Kelix.Mod.Captioning.Token`) and builds
  the URL the client opens:

      <public_url>/streaming/comp/<token>[?lang=<lang>]

  What it decides, per domain of the authenticated caller:

    * whether the correction is part of the service at all (`correction`) — a
      domain without it answers `403` to `comp="true"`;
    * how often a call may ask: `max_per_call` renewals after the first token, at
      least `min_interval` seconds apart (spec §7.4) — past that, `503` with
      `Retry-After`, which a client takes as "stop for this call";
    * the `account` the speech-server bills the token to: the domain's name.

  A speech-server that is down, slow (`timeout_ms`) or refuses the token is a
  `503` with `Retry-After`, never a failed call: the correction helps, it never
  blocks (spec §2, principle 3).

  The token is a bearer credential. It is never logged: what this module writes
  goes through `mask/1` (its first six characters, as the speech-server logs
  it), and its start registers `mask/1` as the redactor of the body type with
  `SIPMsg.register_redactor/2`, so the journal, `kelictl debug` and the SIP debug
  logs show the `200 OK` masked too.
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  alias Kelix.Mod.Captioning.{Body, Token}

  @defaults %{
    ttl: 60,
    timeout_ms: 2_000,
    max_per_call: 5,
    min_interval: 10,
    retry_after: 30
  }

  @config_keys ~w(module call_timeout_ms control_url public_url ttl timeout_ms
                  max_per_call min_interval retry_after domain)
  @domain_keys ~w(name correction lang)

  # The speech-server's rule for `account` (1 to 64 of [A-Za-z0-9._-]).
  @account ~r/\A[A-Za-z0-9._-]{1,64}\z/
  @lang ~r/\A[a-z]{2,3}(-[A-Za-z0-9]{1,8})*\z/

  # A call that ends without `release/1` (an instance killed) is forgotten after
  # this long — past the bridge's own default bound on a call.
  @sweep_ms 600_000
  @call_lifetime_ms 5 * 3_600_000

  defstruct cfg: nil,
            calls: %{},
            stats: %{requested: 0, obtained: 0, refused: %{}, latency: nil}

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, config) do
    {:ok, cfg} = parse_config(config)
    %{id: __MODULE__, start: {__MODULE__, :start_link, [[cfg: cfg]]}}
  end

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    case parse_config(config) do
      {:ok, _cfg} -> :ok
      error -> error
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def reload(_name, config) do
    with {:ok, cfg} <- parse_config(config), do: GenServer.call(__MODULE__, {:reload, cfg})
  end

  @impl Kelix.Module
  def describe() do
    %{
      version: "1.0",
      exports: [answer: 2, parse_request: 1, activate: 3, response_body: 1, release: 1, mask: 1]
    }
  end

  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "status",
        rest: {:get, "/status"},
        rw: :r,
        args: [],
        render: %{
          kind: :detail,
          fields: ~w(control_url public_url ttl timeout_ms max_per_call min_interval
                     retry_after domains active_calls requested obtained refused latency_ms)
        },
        help: "Effective configuration, tokens requested / obtained / refused, active calls"
      }
    ]
  end

  @impl Kelix.Module
  def handle_control("status", _args), do: wrap(Kelix.Module.safe_call(__MODULE__, :status))
  def handle_control(command, _args), do: {:error, {:unknown_command, command}}

  defp wrap({:error, _} = error), do: error
  defp wrap(status), do: {:ok, status}

  # ── Facades ──────────────────────────────────────────────────────────────────

  @doc """
  Answer a captioning INFO from a caller of `domain`, as `b2bua_reply_on/5` takes
  it: `{code, reason, upd_fields}`.

  | Situation | Answer |
  |---|---|
  | no `comp`, or `comp="false"` | `200`, `comp="false"`, no `uri` |
  | `comp="true"`, token obtained | `200`, `comp="true" uri="wss://…"` |
  | `comp="true"`, domain without the correction | `403` |
  | not a captioning document | `400` |
  | renewals past the bounds | `503` + `Retry-After` |
  | speech-server down, slow, refusing | `503` + `Retry-After` |

  Every case answers and none touches the call (spec §6.3). A script calls it
  through `Kelix.ModuleRegistry.facade/4`, so a node without this module answers
  its own default instead.
  """
  @spec answer(map, String.t()) :: {pos_integer, String.t(), keyword}
  def answer(req, domain) when is_map(req) and is_binary(domain) do
    call_id = Map.get(req, :callid)

    with {:ok, request} <- parse_request(req),
         {:ok, granted} <- activate(call_id, domain, request) do
      if granted.comp,
        do:
          Logger.info(
            module: __MODULE__,
            message: "#{call_id}: correction granted, #{mask(granted.uri)}"
          )

      {200, "OK", body: [response_body(granted)]}
    else
      {:error, :malformed} ->
        {400, "Bad Request", []}

      {:error, :forbidden} ->
        Logger.info(
          module: __MODULE__,
          message: "#{call_id}: correction refused, #{domain} not entitled"
        )

        {403, "Forbidden", []}

      {:error, {:busy, retry_after}} ->
        Logger.info(
          module: __MODULE__,
          message: "#{call_id}: correction refused, renewals exhausted"
        )

        unavailable(retry_after)

      {:error, {:unavailable, _reason, retry_after}} ->
        unavailable(retry_after)

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message: "#{call_id}: captioning module unavailable (#{inspect(reason)})"
        )

        unavailable(@defaults.retry_after)
    end
  end

  defp unavailable(retry_after),
    do: {503, "Service Unavailable", [{"Retry-After", Integer.to_string(retry_after)}]}

  @doc """
  Read the INFO: whether it asks for the captions (`stt`) and for the correction
  (`comp`). `{:error, :malformed}` for a body that is absent, not XML, or not a
  `<captioning>` document.
  """
  @spec parse_request(map) :: {:ok, %{stt: boolean, comp: boolean}} | {:error, :malformed}
  def parse_request(req) when is_map(req) do
    case Body.parse(SIP.Msg.Ops.body_string(req)) do
      {:ok, request} -> {:ok, request}
      {:error, _reason} -> {:error, :malformed}
    end
  end

  @doc """
  Grant what the INFO asked for, for the call `call_id` of a caller of `domain`.

  `{:ok, %{comp: false}}` when the correction was not asked for — nothing is
  minted. Otherwise `{:ok, %{comp: true, uri: uri}}`, or:

    * `{:error, :forbidden}` — the domain does not have the correction;
    * `{:error, {:busy, retry_after}}` — renewals past the bounds;
    * `{:error, {:unavailable, reason, retry_after}}` — the speech-server did not
      give a token: `:down`, `:timeout`, `:invalid_response` or
      `{:speech, status, reason}`;
    * `{:error, :down | :timeout}` — this module itself is not answering.
  """
  @spec activate(String.t() | nil, String.t(), %{comp: boolean}) ::
          {:ok, %{comp: false} | %{comp: true, uri: String.t()}} | {:error, term}
  def activate(_call_id, _domain, %{comp: false}), do: {:ok, %{comp: false}}

  def activate(call_id, domain, %{comp: true}) do
    case Kelix.Module.safe_call(__MODULE__, {:reserve, call_id, domain_name(domain)}) do
      {:ok, grant} ->
        started = System.monotonic_time()
        result = Token.request(grant.cfg, grant.account)
        elapsed = System.monotonic_time() - started
        GenServer.cast(__MODULE__, {:token, outcome(result), elapsed})

        case result do
          {:ok, token} ->
            {:ok, %{comp: true, uri: stream_uri(grant, token)}}

          {:error, reason} ->
            log_refusal(call_id, reason)
            {:error, {:unavailable, reason, grant.cfg.retry_after}}
        end

      other ->
        other
    end
  end

  @doc "The body part of a `200 OK`, as `upd_fields`' `body:` takes it."
  @spec response_body(%{comp: boolean}) :: %{contenttype: String.t(), data: binary}
  def response_body(granted), do: %{contenttype: Body.content_type(), data: Body.render(granted)}

  @doc """
  The call is over: forget its renewal count. Takes the Call-ID, or any request
  of the call — what a script has at hand when it ends.
  """
  @spec release(String.t() | map | nil) :: :ok
  def release(%{} = req), do: release(Map.get(req, :callid))

  def release(call_id) do
    if is_binary(call_id) and Process.whereis(__MODULE__),
      do: GenServer.cast(__MODULE__, {:release, call_id})

    :ok
  end

  @doc """
  `text` with every correction token in it cut to its first six characters —
  `…/streaming/comp/AbCdEf…` — the form the speech-server logs it in, so the two
  journals can be matched without either showing the credential.
  """
  @spec mask(binary) :: binary
  def mask(text) when is_binary(text),
    do: Regex.replace(~r"(/streaming/comp/)([A-Za-z0-9_-]{0,6})[A-Za-z0-9_-]*", text, "\\1\\2…")

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    SIPMsg.register_redactor(Body.content_type(), &__MODULE__.mask/1)
    Process.send_after(self(), :sweep, @sweep_ms)
    {:ok, %__MODULE__{cfg: Keyword.fetch!(opts, :cfg)}}
  end

  @impl true
  def handle_call({:reserve, call_id, domain}, _from, state) do
    now = System.monotonic_time(:millisecond)
    state = update_in(state.stats.requested, &(&1 + 1))

    case Map.get(state.cfg.domains, domain) do
      %{correction: true} = dom ->
        case Map.get(state.calls, call_id) do
          %{count: count} when count > state.cfg.max_per_call ->
            {:reply, {:error, {:busy, state.cfg.retry_after}}, refuse(state, :busy)}

          %{last: last} when now - last < state.cfg.min_interval * 1_000 ->
            {:reply, {:error, {:busy, state.cfg.retry_after}}, refuse(state, :busy)}

          entry ->
            entry = %{
              count: ((entry && entry.count) || 0) + 1,
              last: now,
              since: (entry && entry.since) || now
            }

            grant = %{cfg: state.cfg, account: dom.name, lang: dom.lang}
            {:reply, {:ok, grant}, %{state | calls: Map.put(state.calls, call_id, entry)}}
        end

      _not_entitled ->
        {:reply, {:error, :forbidden}, refuse(state, :forbidden)}
    end
  end

  def handle_call(:status, _from, state), do: {:reply, status(state), state}

  def handle_call({:reload, cfg}, _from, state), do: {:reply, :ok, %{state | cfg: cfg}}

  @impl true
  def handle_cast({:token, :obtained, elapsed}, state) do
    Kelix.Metrics.Emit.captioning_token(:obtained, elapsed)
    state = update_in(state.stats.obtained, &(&1 + 1))
    {:noreply, note_latency(state, elapsed)}
  end

  def handle_cast({:token, cause, elapsed}, state) do
    Kelix.Metrics.Emit.captioning_token(cause, elapsed)
    {:noreply, state |> refuse(cause) |> note_latency(elapsed)}
  end

  def handle_cast({:release, call_id}, state),
    do: {:noreply, %{state | calls: Map.delete(state.calls, call_id)}}

  @impl true
  def handle_info(:sweep, state) do
    Process.send_after(self(), :sweep, @sweep_ms)
    oldest = System.monotonic_time(:millisecond) - @call_lifetime_ms
    {:noreply, %{state | calls: Map.reject(state.calls, fn {_id, e} -> e.since < oldest end)}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp refuse(state, cause) do
    if cause in [:forbidden, :busy], do: Kelix.Metrics.Emit.captioning_token(cause, nil)
    update_in(state.stats.refused, &Map.update(&1, cause, 1, fn n -> n + 1 end))
  end

  defp note_latency(state, elapsed) do
    ms = System.convert_time_unit(elapsed, :native, :millisecond)

    latency =
      case state.stats.latency do
        nil -> %{last: ms, max: ms, sum: ms, count: 1}
        l -> %{last: ms, max: max(l.max, ms), sum: l.sum + ms, count: l.count + 1}
      end

    put_in(state.stats.latency, latency)
  end

  defp status(%{cfg: cfg, stats: stats} = state) do
    %{
      control_url: cfg.control_url,
      public_url: cfg.public_url,
      ttl: cfg.ttl,
      timeout_ms: cfg.timeout_ms,
      max_per_call: cfg.max_per_call,
      min_interval: cfg.min_interval,
      retry_after: cfg.retry_after,
      domains:
        cfg.domains
        |> Map.values()
        |> Enum.sort_by(& &1.name)
        |> Enum.map(&%{name: &1.name, correction: &1.correction, lang: &1.lang}),
      active_calls: map_size(state.calls),
      requested: stats.requested,
      obtained: stats.obtained,
      refused: Map.new(stats.refused, fn {cause, n} -> {to_string(cause), n} end),
      latency_ms:
        case stats.latency do
          nil -> nil
          l -> %{last: l.last, max: l.max, mean: div(l.sum, l.count)}
        end
    }
  end

  # ── Tokens ───────────────────────────────────────────────────────────────────

  defp stream_uri(grant, token) do
    base = String.trim_trailing(grant.cfg.public_url, "/") <> "/streaming/comp/" <> token
    if grant.lang, do: base <> "?lang=" <> grant.lang, else: base
  end

  # A bounded label: the reason a server gives goes to the log, not to a metric.
  defp outcome({:ok, _token}), do: :obtained
  defp outcome({:error, {:speech, status, _reason}}), do: :"speech_#{status}"
  defp outcome({:error, reason}) when is_atom(reason), do: reason

  # A 400 / 403 / 413 / 415 is ours to fix — our request, or the deployment
  # (`control.allow`) — so an error; anything else is the speech-server away.
  defp log_refusal(call_id, {:speech, status, reason}) when status in [400, 403, 413, 415] do
    Logger.error(
      module: __MODULE__,
      message:
        "#{call_id}: the speech-server refused the token request: #{status} #{reason || ""}" <>
          if(status == 403, do: " (is this node in its control.allow?)", else: "")
    )
  end

  defp log_refusal(call_id, reason) do
    Logger.warning(
      module: __MODULE__,
      message:
        "#{call_id}: no correction token, speech-server unavailable: #{describe_reason(reason)}"
    )
  end

  defp describe_reason({:speech, status, reason}), do: "#{status} #{reason || ""}"
  defp describe_reason(reason), do: to_string(reason)

  # ── Configuration ────────────────────────────────────────────────────────────

  @doc false
  @spec parse_config(map) :: {:ok, map} | {:error, String.t()}
  def parse_config(config) when is_map(config) do
    with :ok <- reject_unknown(config, @config_keys, ""),
         {:ok, control_url} <- url(config, "control_url", ["http", "https"]),
         {:ok, public_url} <- url(config, "public_url", ["wss"]),
         {:ok, ttl} <- integer(config, "ttl", 1..3600),
         {:ok, timeout_ms} <- integer(config, "timeout_ms", 100..30_000),
         {:ok, max_per_call} <- integer(config, "max_per_call", 0..100),
         {:ok, min_interval} <- integer(config, "min_interval", 0..3600),
         {:ok, retry_after} <- integer(config, "retry_after", 1..3600),
         {:ok, domains} <- domains(Map.get(config, "domain", [])) do
      {:ok,
       %{
         control_url: control_url,
         public_url: public_url,
         ttl: ttl,
         timeout_ms: timeout_ms,
         max_per_call: max_per_call,
         min_interval: min_interval,
         retry_after: retry_after,
         domains: domains
       }}
    end
  end

  def parse_config(_), do: {:error, "block must be a table"}

  defp reject_unknown(map, keys, where) do
    case Map.keys(map) -- keys do
      [] -> :ok
      extra -> {:error, "#{where}unknown key(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  # `public_url` is what a browser opens: `wss://` only, never `ws://` (spec §6.5).
  defp url(config, key, schemes) do
    with value when is_binary(value) <- Map.get(config, key),
         %URI{scheme: scheme, host: host} when is_binary(host) and host != "" <- URI.parse(value),
         true <- scheme in schemes do
      {:ok, value}
    else
      nil -> {:error, "#{key} is required"}
      _ -> {:error, "#{key} must be a #{Enum.map_join(schemes, " or ", &"#{&1}://")} URL"}
    end
  end

  defp integer(config, key, range) do
    case Map.get(config, key, Map.fetch!(@defaults, String.to_existing_atom(key))) do
      n when is_integer(n) ->
        if n in range,
          do: {:ok, n},
          else: {:error, "#{key} must be between #{range.first} and #{range.last}"}

      _ ->
        {:error, "#{key} must be an integer"}
    end
  end

  defp domains(list) when is_list(list) do
    Enum.reduce_while(list, {:ok, %{}}, fn entry, {:ok, acc} ->
      case domain(entry) do
        {:ok, dom} -> {:cont, {:ok, Map.put(acc, String.downcase(dom.name), dom)}}
        error -> {:halt, error}
      end
    end)
  end

  defp domains(_), do: {:error, "domain must be a list of [[module.captioning.domain]] tables"}

  # The domain's name is the token's `account`: it must pass the speech-server's
  # rule, so an IDN goes in as its punycode.
  defp domain(entry) when is_map(entry) do
    name = Map.get(entry, "name")

    cond do
      (error = reject_unknown(entry, @domain_keys, "domain: ")) != :ok ->
        error

      not (is_binary(name) and name =~ @account) ->
        {:error,
         "domain name #{inspect(name)} must be 1 to 64 of [A-Za-z0-9._-] (punycode for an IDN)"}

      not is_boolean(Map.get(entry, "correction", false)) ->
        {:error, "domain #{name}: correction must be true or false"}

      not (is_nil(Map.get(entry, "lang")) or Map.get(entry, "lang") =~ @lang) ->
        {:error, "domain #{name}: lang must be a short language code (fr, en, pt-BR…)"}

      true ->
        {:ok,
         %{
           name: name,
           correction: Map.get(entry, "correction", false),
           lang: Map.get(entry, "lang")
         }}
    end
  end

  defp domain(_), do: {:error, "domain must be a list of [[module.captioning.domain]] tables"}

  # A served domain's canonical name, an alias folded into it; the name as given
  # when this node does not serve it, or when there is no configuration to ask.
  defp domain_name(domain) do
    folded =
      with pid when is_pid(pid) <- Process.whereis(Kelix.Domains),
           %Kelix.Domain{name: name} <- Kelix.Domains.lookup(Kelix.Domains.current(), domain) do
        name
      else
        _ -> domain
      end

    String.downcase(folded)
  end
end
