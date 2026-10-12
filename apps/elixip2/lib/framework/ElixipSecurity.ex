defmodule Elixip.Security do
  @moduledoc """
  The one function the whole stack calls to say "someone is knocking".

  A transport, a router or a module builds an `Elixip.Security.Incident` and hands
  it to `report/1`. The library keeps no sink of its own: the embedding product
  names one in the `:elixip2` application env, `security_sink: {module, fun}`, and
  `report/1` applies it when present and does nothing when absent. kelixip's sink
  is `Kelix.Security.IncidentReporter`, which writes the line fail2ban reads
  (`docs/design/fail2ban-plan.md`).
  """

  defmodule Incident do
    @moduledoc """
    One security incident, rendered as one line of `key=value` pairs in a fixed
    order, `type` first and `src` second:

        auth-failure src=192.0.2.5 port=5060 proto=UDP method=REGISTER realm=example.com user="alice" reason=bad_password

    Every field defaults to `nil`, and a `nil` field is omitted: a default that
    fabricates a value is a lie on a line whose purpose is evidence. `user` is the
    only free text on the line, so it is quoted and escaped — a username cannot
    forge a second `src=` nor end the line early. `src` is an address, never a
    hostname, and an IPv6 address is written unbracketed.
    """

    @type type ::
            :auth_failure | :invalid_domain | :invalid_packet | :transport_error | :api_auth

    @type t :: %__MODULE__{
            type: type | nil,
            src: :inet.ip_address() | nil,
            port: :inet.port_number() | nil,
            proto: String.t() | nil,
            method: atom() | String.t() | nil,
            realm: String.t() | nil,
            user: String.t() | nil,
            reason: atom() | nil
          }

    defstruct type: nil,
              src: nil,
              port: nil,
              proto: nil,
              method: nil,
              realm: nil,
              user: nil,
              reason: nil

    @doc "The incident type names, as they are written on the line."
    @spec type_names() :: [String.t()]
    def type_names,
      do: ~w(auth-failure invalid-domain invalid-packet transport-error api-auth)

    @doc "The type atom a line name stands for, or `nil` for a name that is not one."
    @spec type_from_name(String.t()) :: type | nil
    def type_from_name(name) when is_binary(name) do
      if name in type_names(),
        do: name |> String.replace("-", "_") |> String.to_atom(),
        else: nil
    end

    @doc false
    def render(%__MODULE__{} = i) do
      [
        {nil, type_name(i.type)},
        {"src", src(i.src)},
        {"port", i.port},
        {"proto", i.proto},
        {"method", i.method},
        {"realm", i.realm},
        {"user", quoted(i.user)},
        {"reason", i.reason}
      ]
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Enum.map_join(" ", fn
        {nil, v} -> to_string(v)
        {k, v} -> "#{k}=#{v}"
      end)
    end

    defp type_name(nil), do: nil

    defp type_name(type) when is_atom(type),
      do: type |> Atom.to_string() |> String.replace("_", "-")

    defp src(nil), do: nil
    defp src(ip) when is_tuple(ip), do: ip |> :inet.ntoa() |> List.to_string()

    defp quoted(nil), do: nil

    defp quoted(user) when is_binary(user) do
      escaped =
        for <<c <- user>>, into: "" do
          case c do
            ?" ->
              "\\\""

            ?\\ ->
              "\\\\"

            c when c < 0x20 or c == 0x7F ->
              "\\x" <> String.pad_leading(Integer.to_string(c, 16), 2, "0")

            c ->
              <<c>>
          end
        end

      "\"" <> escaped <> "\""
    end

    defimpl String.Chars do
      def to_string(incident), do: Elixip.Security.Incident.render(incident)
    end
  end

  @doc """
  Hand an incident to the configured sink. `:ok` whatever happens: reporting an
  incident is never what stops the server from answering.
  """
  @spec report(Incident.t()) :: :ok
  def report(%Incident{} = incident) do
    case Application.get_env(:elixip2, :security_sink) do
      {mod, fun} when is_atom(mod) and is_atom(fun) ->
        apply(mod, fun, [incident])
        :ok

      _ ->
        :ok
    end
  end
end
