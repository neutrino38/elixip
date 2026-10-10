defmodule Kelix.Mod.SipServers.Route do
  @moduledoc """
  What forwarding a request to a server means: the request as the remote host
  expects it, and the `%SIP.B2bua.Peer{}` that carries it there (design
  `docs/design/sip-server-specs.md`, "Functions").

  | Type | R-URI | To | From |
  |---|---|---|---|
  | `sip-proxy` | kept (`:keep`), its host moved to `ext_domain` when it is ours | follows the R-URI | kept |
  | `sip-application` | rewritten (`:peer`): the user part of the request at the server | kept | kept |
  | `sip-trunk` | rewritten (`:peer`): the user part at `ext_domain`, else at the trunk | as the R-URI | the trunk account |

  A trunk with an `ext_domain` names a domain the DNS would route elsewhere, so its
  targets carry the destination the server's URIs resolved to; without the
  resolution there is nowhere to send it, and `peer/4` says so.

  Pure: the service hands in the server, its resolution and the round-robin
  position, and nothing here keeps state.
  """

  alias Kelix.Mod.SipServers.Server
  alias SIP.B2bua.Peer

  @doc """
  `{newreq, peer}` to forward `req` to `server`, or `{:error, :not_resolved}` for a
  trunk with an `ext_domain` whose URIs have not resolved yet.

  `turn` is the round-robin position: with `ha_mode = loadsharing` the URIs are
  rotated by it, so each call starts on the next one and still fails over to the
  others.
  """
  @spec forward(map(), Server.t(), map(), non_neg_integer(), pid() | nil) ::
          {map(), %Peer{}} | {:error, :not_resolved}
  def forward(req, %Server{} = server, resolved, turn \\ 0, link \\ nil) do
    case shape(req, server, resolved, turn) do
      {newreq, %Peer{} = peer} ->
        {newreq, %Peer{peer | trunk_pid: link, credentials: credentials(server, link)}}

      error ->
        error
    end
  end

  defp shape(req, server, resolved, turn) do
    uris = rotate(uris(server), server.ha_mode, turn)

    case server.type do
      "sip-proxy" ->
        {to_ext_domain(req, server), peer(server, uris, :keep, server.use_dns_srv)}

      "sip-application" ->
        targets = for uri <- uris, do: %SIP.Uri{parse!(uri) | userpart: user(req)}
        {req, peer(server, targets, :peer, server.use_dns_srv)}

      "sip-trunk" ->
        trunk(req, server, uris, resolved)
    end
  end

  @doc """
  The peer a request recognised as coming from `server` is answered through — no
  request to shape, just where the server is.
  """
  @spec peer(Server.t(), pid() | nil) :: %Peer{}
  def peer(%Server{} = server, link \\ nil) do
    ruri = if server.type == "sip-proxy", do: :keep, else: :peer

    %Peer{
      peer(server, uris(server), ruri, server.use_dns_srv)
      | trunk_pid: link,
        credentials: credentials(server, link)
    }
  end

  # Only a trunk answers a challenge, and only with a password entered for it.
  defp credentials(%Server{type: "sip-trunk", auth_ha1: [_ | _]}, link) when is_pid(link),
    do: link

  defp credentials(_server, _link), do: nil

  defp peer(_server, targets, ruri, use_srv) do
    %Peer{uris: targets, fork: :serial, ruri: ruri, use_srv: use_srv}
  end

  defp uris(server), do: Enum.reject([server.primary_uri, server.backup_uri], &is_nil/1)

  defp rotate(uris, "loadsharing", turn) when uris != [] do
    n = rem(turn, length(uris))
    Enum.drop(uris, n) ++ Enum.take(uris, n)
  end

  defp rotate(uris, _mode, _turn), do: uris

  # ── sip-proxy ───────────────────────────────────────────────────────────────

  # A request for one of the proxy's AORs may arrive addressed to us; the proxy
  # serves `ext_domain`, so that is the domain it must read in the R-URI and To.
  defp to_ext_domain(req, %Server{ext_domain: nil}), do: req

  defp to_ext_domain(req, %Server{ext_domain: ext} = server) do
    if host(req.ruri) in [ext | server.ext_domain_aliases] do
      req
    else
      req
      |> Map.put(:ruri, %SIP.Uri{req.ruri | domain: ext, port: nil})
      |> put_header_domain(:to, ext)
    end
  end

  # ── sip-trunk ───────────────────────────────────────────────────────────────

  defp trunk(req, server, uris, resolved) do
    user = user(req)
    host = server.ext_domain || host(parse!(server.primary_uri))
    account = parse!(server.primary_uri).userpart

    newreq =
      req
      |> put_header(:to, user, host)
      |> put_header(:from, account, host)

    if server.ext_domain do
      case located_targets(uris, user, server.ext_domain, resolved) do
        [] -> {:error, :not_resolved}
        targets -> {newreq, peer(server, targets, :peer, false)}
      end
    else
      targets = for uri <- uris, do: %SIP.Uri{parse!(uri) | userpart: user}
      {newreq, peer(server, targets, :peer, server.use_dns_srv)}
    end
  end

  # `sip:<user>@<ext_domain>`, each sent to where one of the trunk's URIs resolved.
  defp located_targets(uris, user, ext_domain, resolved) do
    for uri <- uris, {transport, ip, port} <- Map.get(resolved, uri, []) |> Enum.take(1) do
      %SIP.Uri{
        scheme: parse!(uri).scheme,
        userpart: user,
        domain: ext_domain,
        destip: ip,
        destport: port,
        destproto: transport
      }
    end
  end

  # ── helpers ─────────────────────────────────────────────────────────────────

  defp user(%{ruri: %SIP.Uri{userpart: user}}), do: user
  defp user(_req), do: nil

  defp host(%SIP.Uri{domain: d}) when is_binary(d), do: String.downcase(d)
  defp host(_), do: nil

  # The display name of a From is the caller's claim about itself; on a trunk the
  # From is the account, and a name the operator did not give it is dropped.
  defp put_header(req, :from, user, domain) do
    case Map.get(req, :from) do
      %SIP.Uri{} = from ->
        Map.put(req, :from, %SIP.Uri{
          from
          | userpart: user,
            domain: domain,
            port: nil,
            displayname: nil
        })

      _ ->
        req
    end
  end

  defp put_header(req, :to, user, domain) do
    case Map.get(req, :to) do
      %SIP.Uri{} = to ->
        Map.put(req, :to, %SIP.Uri{to | userpart: user, domain: domain, port: nil})

      _ ->
        req
    end
  end

  defp put_header_domain(req, header, domain) do
    case Map.get(req, header) do
      %SIP.Uri{} = uri -> Map.put(req, header, %SIP.Uri{uri | domain: domain, port: nil})
      _ -> req
    end
  end

  defp parse!(uri) do
    {:ok, parsed} = SIP.Uri.parse(uri)
    parsed
  end
end
