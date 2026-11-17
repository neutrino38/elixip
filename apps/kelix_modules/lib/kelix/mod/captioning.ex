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

  A node that loads this module offers the correction to every call of the
  script. What it decides is how often a call may ask: `max_per_call` renewals
  after the first token, at least `min_interval` seconds apart (spec §7.4) — past
  that, `503` with `Retry-After`, which a client takes as "stop for this call".
  The `account` the speech-server bills the token to and the `lang` of the
  correction are the script's, passed to `answer/2`.

  A token is asked of the speech-server, then of the backup one when it is
  configured and the first did not answer: a token is only valid on the server
  that minted it, so the URL handed out is that server's `public_url`. A refusal
  (4xx) is not retried elsewhere, the request itself being at fault.

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

  @config_keys ~w(module call_timeout_ms control_url public_url backup_control_url
                  backup_public_url ttl timeout_ms max_per_call min_interval retry_after)

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
          fields: ~w(control_url public_url backup_control_url backup_public_url ttl
                     timeout_ms max_per_call min_interval retry_after active_calls
                     requested obtained refused latency_ms)
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
  Answer a captioning INFO, as `b2bua_reply_on/5` takes it: `{code, reason,
  upd_fields}`. `opts`: `account:` the label the speech-server bills the token
  to, `lang:` the language of the correction, added to the URL; both absent by
  default. A bare string is taken as the `account`.

  | Situation | Answer |
  |---|---|
  | no `comp`, or `comp="false"` | `200`, `comp="false"`, no `uri` |
  | `comp="true"`, token obtained | `200`, `comp="true" uri="wss://…"` |
  | not a captioning document | `400` |
  | `account` or `lang` invalid | `500` |
  | renewals past the bounds | `503` + `Retry-After` |
  | speech-server down, slow, refusing | `503` + `Retry-After` |

  Every case answers and none touches the call (spec §6.3). A script calls it
  through `Kelix.ModuleRegistry.facade/4`, so a node without this module answers
  its own default instead.
  """
  @spec answer(map, keyword | String.t()) :: {pos_integer, String.t(), keyword}
  def answer(req, account) when is_binary(account), do: answer(req, account: account)

  def answer(req, opts) when is_map(req) and is_list(opts) do
    call_id = Map.get(req, :callid)

    with {:ok, request} <- parse_request(req),
         {:ok, granted} <- activate(call_id, request, opts) do
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

      {:error, {:bad_option, key, value}} ->
        Logger.error(
          module: __MODULE__,
          message: "#{call_id}: the script passed an invalid #{key}: #{inspect(value)}"
        )

        {500, "Server Internal Error", []}

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
  Grant what the INFO asked for, for the call `call_id`. `opts` as `answer/2`.

  `{:ok, %{comp: false}}` when the correction was not asked for — nothing is
  minted. Otherwise `{:ok, %{comp: true, uri: uri}}`, or:

    * `{:error, {:bad_option, key, value}}` — `account` or `lang` is invalid;
    * `{:error, {:busy, retry_after}}` — renewals past the bounds;
    * `{:error, {:unavailable, reason, retry_after}}` — the speech-server did not
      give a token: `:down`, `:timeout`, `:invalid_response` or
      `{:speech, status, reason}`;
    * `{:error, :down | :timeout}` — this module itself is not answering.
  """
  @spec activate(String.t() | nil, %{comp: boolean}, keyword) ::
          {:ok, %{comp: false} | %{comp: true, uri: String.t()}} | {:error, term}
  def activate(_call_id, %{comp: false}, _opts), do: {:ok, %{comp: false}}

  def activate(call_id, %{comp: true}, opts) do
    with {:ok, account} <- option(opts, :account, @account),
         {:ok, lang} <- option(opts, :lang, @lang),
         {:ok, cfg} <- Kelix.Module.safe_call(__MODULE__, {:reserve, call_id}) do
      started = System.monotonic_time()
      result = request_token(cfg, call_id, account)
      elapsed = System.monotonic_time() - started
      GenServer.cast(__MODULE__, {:token, outcome(result), elapsed})

      case result do
        {:ok, server, token} ->
          {:ok, %{comp: true, uri: stream_uri(server.public_url, token, lang)}}

        {:error, reason} ->
          {:error, {:unavailable, reason, cfg.retry_after}}
      end
    end
  end

  defp option(opts, key, format) do
    case Keyword.get(opts, key) do
      nil -> {:ok, nil}
      value when is_binary(value) -> if value =~ format, do: {:ok, value}, else: bad(key, value)
      value -> bad(key, value)
    end
  end

  defp bad(key, value), do: {:error, {:bad_option, key, value}}

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
  def handle_call({:reserve, call_id}, _from, state) do
    now = System.monotonic_time(:millisecond)
    state = update_in(state.stats.requested, &(&1 + 1))

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

        {:reply, {:ok, state.cfg}, %{state | calls: Map.put(state.calls, call_id, entry)}}
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
    if cause == :busy, do: Kelix.Metrics.Emit.captioning_token(cause, nil)
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
      backup_control_url: cfg.backup_control_url,
      backup_public_url: cfg.backup_public_url,
      ttl: cfg.ttl,
      timeout_ms: cfg.timeout_ms,
      max_per_call: cfg.max_per_call,
      min_interval: cfg.min_interval,
      retry_after: cfg.retry_after,
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

  # The servers in the order they are asked: the main one, then the backup.
  defp servers(%{backup_control_url: nil} = cfg),
    do: [%{control_url: cfg.control_url, public_url: cfg.public_url}]

  defp servers(cfg) do
    [
      %{control_url: cfg.control_url, public_url: cfg.public_url},
      %{control_url: cfg.backup_control_url, public_url: cfg.backup_public_url}
    ]
  end

  defp request_token(cfg, call_id, account) do
    Enum.reduce_while(servers(cfg), nil, fn server, _last ->
      case Token.request(server.control_url, cfg, account) do
        {:ok, token} ->
          {:halt, {:ok, server, token}}

        {:error, reason} = error ->
          log_refusal(call_id, server.control_url, reason)
          if refused?(reason), do: {:halt, error}, else: {:cont, error}
      end
    end)
  end

  defp refused?({:speech, status, _reason}), do: status in 400..499
  defp refused?(_reason), do: false

  defp stream_uri(public_url, token, lang) do
    base = String.trim_trailing(public_url, "/") <> "/streaming/comp/" <> token
    if lang, do: base <> "?lang=" <> lang, else: base
  end

  # A bounded label: the reason a server gives goes to the log, not to a metric.
  defp outcome({:ok, _server, _token}), do: :obtained
  defp outcome({:error, {:speech, status, _reason}}), do: :"speech_#{status}"
  defp outcome({:error, reason}) when is_atom(reason), do: reason

  # A 400 / 403 / 413 / 415 is ours to fix — our request, or the deployment
  # (`control.allow`) — so an error; anything else is the speech-server away.
  defp log_refusal(call_id, url, {:speech, status, reason})
       when status in [400, 403, 413, 415] do
    Logger.error(
      module: __MODULE__,
      message:
        "#{call_id}: the speech-server #{url} refused the token request: " <>
          "#{status} #{reason || ""}" <>
          if(status == 403, do: " (is this node in its control.allow?)", else: "")
    )
  end

  defp log_refusal(call_id, url, reason) do
    Logger.warning(
      module: __MODULE__,
      message:
        "#{call_id}: no correction token, speech-server #{url} unavailable: " <>
          describe_reason(reason)
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
         {:ok, backup_control_url, backup_public_url} <- backup(config) do
      {:ok,
       %{
         control_url: control_url,
         public_url: public_url,
         backup_control_url: backup_control_url,
         backup_public_url: backup_public_url,
         ttl: ttl,
         timeout_ms: timeout_ms,
         max_per_call: max_per_call,
         min_interval: min_interval,
         retry_after: retry_after
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

  # The backup server is a pair: a token is only valid on the server that minted
  # it, so the URL a client opens must be the one of the server that answered.
  defp backup(config) do
    case {Map.has_key?(config, "backup_control_url"), Map.has_key?(config, "backup_public_url")} do
      {false, false} ->
        {:ok, nil, nil}

      {true, true} ->
        with {:ok, control_url} <- url(config, "backup_control_url", ["http", "https"]),
             {:ok, public_url} <- url(config, "backup_public_url", ["wss"]),
             do: {:ok, control_url, public_url}

      _ ->
        {:error, "backup_control_url and backup_public_url go together"}
    end
  end
end
