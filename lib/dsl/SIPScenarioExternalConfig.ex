defmodule SIP.Scenario.ExternalConfig do
  @moduledoc """
  Load and validate an external JSON file parameterizing a scenario.

  The file holds a header (global / per-session defaults) and a list of N
  accounts:

      {
        "domain": "visioassistance.net",
        "proxyuri": "sip:sip.djanah.com:5060",
        "proxyusesrv": false,
        "optionkeepaliveperiod": 5,
        "accounts": [
          { "username": "33970262546", "password": "TestKam1" },
          { "username": "33970262547", "password": "TestKam2", "domain": "autre.net" }
        ]
      }

  ## Merge model

  The external config *overrides* the scenario `config` block (which becomes a
  set of defaults). The runner merges, in increasing precedence:

      scenario config block  <  JSON header  <  JSON account

  `overrides_for/2` produces, for a given instance index, the keyword list of
  overrides (header merged with the selected account) to hand to
  `SIP.Scenario.Runner.run_instance/2` via the `:config_overrides` option.

  ## Key routing

  The header `:proxyuri` / `:proxyusesrv` / `:optionkeepaliveperiod` are global
  keys: the runner routes them to the `:elixip2` application env, not the
  per-session `%SIP.Context{}`. `:domain` and the account fields are per-session
  context keys. The mapping is applied by `SIP.Scenario.Runner.build_context/1`,
  so this module only normalizes and validates.

  Validation is strict: any unknown key (header or account), missing required
  account field, unresolved domain or type mismatch raises with a clear message.
  """

  defstruct header: [], accounts: []

  @type t :: %__MODULE__{header: keyword(), accounts: [keyword()]}

  # Whitelisted JSON keys. Conversion string -> atom is restricted to these, so
  # a malformed file cannot exhaust the atom table.
  @header_keys ~w(domain proxyuri proxyusesrv optionkeepaliveperiod)
  @account_keys ~w(username password authusername displayname domain)

  @doc """
  Read, parse and validate the JSON file at `path`. Raises on any error
  (missing file, invalid JSON, unknown key, missing/ill-typed field).
  """
  @spec load!(Path.t()) :: t()
  def load!(path) do
    unless File.exists?(path) do
      raise ArgumentError, "Fichier de configuration introuvable : #{path}"
    end

    json =
      case path |> File.read!() |> Jason.decode() do
        {:ok, decoded} ->
          decoded

        {:error, err} ->
          raise ArgumentError, "JSON invalide dans #{path} : #{Exception.message(err)}"
      end

    parse!(json)
  end

  @doc """
  Validate an already-decoded JSON term (a map). Same rules as `load!/1` but
  without the file I/O — convenient for tests.
  """
  @spec parse!(map()) :: t()
  def parse!(json) when is_map(json) do
    {accounts_raw, header_raw} = Map.pop(json, "accounts")
    header = parse_header!(header_raw)
    accounts = parse_accounts!(accounts_raw, header)
    %__MODULE__{header: header, accounts: accounts}
  end

  def parse!(_other) do
    raise ArgumentError, "La racine du fichier de configuration doit être un objet JSON"
  end

  @doc """
  Build the `:config_overrides` keyword list for the instance at `index`
  (0-based). The account is selected round-robin: `accounts[rem(index, N)]`, so
  recycling slots (or running several in parallel) cycles through every account.

  Returns `[]` when `config` is `nil`, so callers can pass the result
  unconditionally and keep the no-config behavior identical to before.
  """
  @spec overrides_for(t() | nil, non_neg_integer()) :: keyword()
  def overrides_for(nil, _index), do: []

  def overrides_for(%__MODULE__{header: header, accounts: accounts}, index) do
    account = Enum.at(accounts, rem(index, length(accounts)))
    Keyword.merge(header, account)
  end

  @doc "Number of accounts declared in the config (0 for `nil`)."
  @spec account_count(t() | nil) :: non_neg_integer()
  def account_count(nil), do: 0
  def account_count(%__MODULE__{accounts: accounts}), do: length(accounts)

  # ── Header ──────────────────────────────────────────────────────────────

  defp parse_header!(nil), do: []

  defp parse_header!(header) when is_map(header) do
    Enum.map(header, fn {key, value} ->
      unless key in @header_keys do
        raise ArgumentError,
              "Clé d'entête inconnue : #{inspect(key)}. Clés attendues : #{Enum.join(@header_keys, ", ")}"
      end

      header_pair!(key, value)
    end)
  end

  defp parse_header!(_), do: raise(ArgumentError, "L'entête doit être un objet JSON")

  defp header_pair!("domain", value) when is_binary(value), do: {:domain, value}

  defp header_pair!("proxyuri", value) when is_binary(value) do
    case SIP.Uri.parse(value) do
      {:ok, uri} -> {:proxyuri, uri}
      {err, _} -> raise ArgumentError, "proxyuri invalide #{inspect(value)} : #{inspect(err)}"
    end
  end

  defp header_pair!("proxyusesrv", value) when is_boolean(value), do: {:proxyusesrv, value}

  defp header_pair!("optionkeepaliveperiod", value) when is_integer(value),
    do: {:optionkeepaliveperiod, value}

  defp header_pair!(key, value),
    do:
      raise(
        ArgumentError,
        "Valeur invalide pour la clé d'entête #{inspect(key)} : #{inspect(value)}"
      )

  # ── Accounts ────────────────────────────────────────────────────────────

  defp parse_accounts!(nil, _header),
    do: raise(ArgumentError, "Le fichier de configuration doit contenir une liste \"accounts\"")

  defp parse_accounts!([], _header),
    do: raise(ArgumentError, "La liste \"accounts\" ne doit pas être vide")

  defp parse_accounts!(accounts, header) when is_list(accounts) do
    Enum.map(accounts, &parse_account!(&1, header))
  end

  defp parse_accounts!(_other, _header),
    do: raise(ArgumentError, "\"accounts\" doit être une liste d'objets JSON")

  defp parse_account!(account, header) when is_map(account) do
    Enum.each(Map.keys(account), fn key ->
      unless key in @account_keys do
        raise ArgumentError,
              "Clé de compte inconnue : #{inspect(key)}. Clés attendues : #{Enum.join(@account_keys, ", ")}"
      end
    end)

    username = required_string!(account, "username")
    password = required_string!(account, "password")
    authusername = optional_string!(account, "authusername") || username
    domain = optional_string!(account, "domain") || Keyword.get(header, :domain)

    unless is_binary(domain) do
      raise ArgumentError,
            "Le compte #{inspect(username)} n'a pas de domaine (absent du compte et de l'entête)"
    end

    base = [username: username, authusername: authusername, domain: domain, passwd: password]

    case optional_string!(account, "displayname") do
      nil -> base
      displayname -> base ++ [displayname: displayname]
    end
  end

  defp parse_account!(_other, _header),
    do: raise(ArgumentError, "Chaque entrée de \"accounts\" doit être un objet JSON")

  defp required_string!(map, key) do
    case Map.get(map, key) do
      value when is_binary(value) ->
        value

      nil ->
        raise ArgumentError, "Champ de compte requis manquant : #{inspect(key)}"

      other ->
        raise ArgumentError,
              "Le champ de compte #{inspect(key)} doit être une chaîne, reçu #{inspect(other)}"
    end
  end

  defp optional_string!(map, key) do
    case Map.get(map, key) do
      nil ->
        nil

      value when is_binary(value) ->
        value

      other ->
        raise ArgumentError,
              "Le champ de compte #{inspect(key)} doit être une chaîne, reçu #{inspect(other)}"
    end
  end
end
