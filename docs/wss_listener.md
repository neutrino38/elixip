# WSS Listener Design

## Context and Motivation

The current WSS transport (`SIP.Transport.WSS`) supports **outbound client connections only**.
For UAS scenarios over WSS — browser-based WebRTC clients, for instance — we need the symmetric
counterpart: a **WSS listener** that binds a TLS server socket, accepts inbound connections,
completes the WebSocket upgrade handshake, and routes each connection through the same SIP
processing pipeline as the existing outbound WSS transport.

The `--listen wss:PORT` option is already parsed by `ElixippCLI` but the implementation is
currently `:not_implemented` in `start_listeners/1`.

This design mirrors `SIP.Transport.TLSListener` with the one structural difference that WSS
requires a second handshake layer (HTTP WebSocket upgrade) after the TLS handshake.

---

## Architecture Overview

```
SIP.Transport.WSSListener                   (one per bound port)
   │  :ssl.listen — binds a TLS server socket
   │  accept Task loops on :ssl.transport_accept + :ssl.handshake
   │                     + Socket.Web upgrade (two-step)
   │
   ├── SIP.Transport.WSS  :inbound          (one per accepted + upgraded connection)
   │      same GenServer as the outbound WSS client, new init/1 clause
   │      stores %Socket.Web{} struct (passive, no active-mode yet)
   │      :activate_socket cast spawns a Socket.Web reader process
   │      reader delivers {:web, ws, data} to the WSS GenServer
   │      no SIP.Transport.Depack — WebSocket frames are message-delimited
   │      calls ImplHelpers.process_incoming_message
   │
   └── SIP.Transport.WSS  :inbound          (another accepted connection)
         ...
```

---

## Handshake Sequence

WSS requires **two sequential handshakes** in the accept Task:

```
1. TLS handshake     :ssl.transport_accept + :ssl.handshake
                     → raw :sslsocket (same as TLSListener)

2. WebSocket upgrade Socket.Web.accept! step A — accepts underlying SSL conn,
                     reads HTTP Upgrade request, returns pending %Socket.Web{}
                     (key is set, 101 not yet sent)

                     Socket.Web.accept! step B — sends HTTP/1.1 101 Switching
                     Protocols, returns the underlying %Socket.SSL{} struct

                     Reconstruct %Socket.Web{} from pending + upgraded socket
                     → ws_socket ready for send!/recv!
```

Both handshakes run inside the accept Task (never in the Listener GenServer), so a slow or
failing client does not stall the Listener's `handle_call` loop.

---

## Ownership and Activation Sequence

`Socket.Web` active mode works differently from raw TLS active mode:

- **TLS**: `:ssl.setopts(socket, [{:active, true}])` makes OTP deliver `{:ssl, sock, data}`
  directly to the controlling process. The TLS GenServer IS the controlling process.

- **WSS**: `Socket.Web.active(ws, true)` spawns a **reader process** (`active_pid`) that
  calls `Socket.Web.recv!/1` (passive `:ssl.recv`) in a loop and delivers
  `{:web, ws, data}` to `ws.target_pid`. The WSS GenServer is the target, not the reader.
  Since `recv!` is a blocking synchronous call, the underlying SSL socket's
  `:controlling_process` attribute is irrelevant for data delivery.

```
accept Task              WSSListener GenServer       WSS GenServer      Reader process
    |                           |                         |                    |
    |--:ssl.transport_accept()  |                         |                    |
    |--:ssl.handshake()         |                         |                    |
    |--Socket.Web.accept! (A)   |                         |                    |
    |--Socket.Web.accept! (B)   |                         |                    |
    |  ws_socket assembled      |                         |                    |
    |--call(:spawn_connection, ws_socket, peer_ip, peer_port)                  |
    |                           |--GenServer.start_link   |                    |
    |                           |  {:inbound, ws_socket,…}|                    |
    |<-- {:ok, conn_pid} -------|                         |                    |
    |--cast(conn_pid, :activate_socket)------------------>|                    |
    |                           |         Socket.Web.process(ws, self())       |
    |                           |         Socket.Web.active(ws, true)--------->|
    |                           |                         |  recv! loop starts |
    |                           |                         |<---{:web, ws, data}|
```

---

## SIP.Transport.WSS — Extended for Inbound Connections

### New `init/1` Clause

The existing clause handles outbound connections (unchanged):

```elixir
def init({dest_ip, dest_port}) do   # outbound — unchanged
  ...
  SIP.Transport.ImplHelpers.connect(initial_state, :wss)
  ...
end
```

A new clause handles inbound accepted and upgraded connections:

```elixir
def init({:inbound, ws_socket, localip, localport, peer_ip, peer_port}) do
  state = %{
    t_isreliable: true,
    upperlayer:   nil,
    destip:       peer_ip,
    destport:     peer_port,
    socket:       ws_socket,    # %Socket.Web{} — passive, reader not yet started
    localip:      localip,
    localport:    localport
    # No Depack buffer — WebSocket frames are message-delimited
  }
  {:ok, state}
end
```

### New `handle_cast(:activate_socket, state)`

Called by the accept Task once the WSS GenServer is started. Registers `self()` as the
delivery target and starts the reader process:

```elixir
@impl true
def handle_cast(:activate_socket, state) do
  ws = Socket.Web.process(state.socket, self()) |> Socket.Web.active(true)
  {:noreply, %{state | socket: ws}}
end
```

`Socket.Web.process/2` updates `target_pid` in the `%Socket.Web{}` struct.
`Socket.Web.active/2` spawns `active_pid` running `active_websocket_process/1`, which
delivers `{:web, ws, data}` messages to this process.

### Inbound Message Handling

No new callbacks needed — the existing `handle_info` clauses already cover both cases:

```elixir
def handle_info({:web, _socket, data}, state) do
  SIP.Transport.ImplHelpers.process_incoming_message(
    state, data, "WSS", __MODULE__, state.socket, state.destip, state.destport)
  {:noreply, state}
end

def handle_info({:web_closed, _socket}, state) do
  Logger.debug([module: __MODULE__, message: "WSS connection closed, stopping transport"])
  SIP.Dialog.broadcast({:wss_client_closed, state.destip, state.destport})
  {:stop, :normal, state}
end
```

The existing `handle_call({:sendmsg, ...})`, `terminate/2`, and all `setupperlayer` clauses
work without modification for both outbound and inbound connections.

---

## SIP.Transport.WSSListener

### Module Skeleton

```elixir
defmodule SIP.Transport.WSSListener do
  use GenServer
  require Logger
  require SIP.Transport.ImplHelpers

  @transport_str "wss"
  def transport_str, do: @transport_str

  @default_max_connections 100
  @handshake_timeout       10_000
  @default_certfile        "certs/certificate.pem"
  @default_keyfile         "certs/private_key.pem"
end
```

### Public API

```elixir
@spec start_link({:all | :inet.ip_address(), :inet.port_number()}) :: GenServer.on_start()
def start_link({addr, port}), do: GenServer.start_link(__MODULE__, {addr, port, []})

@spec start({:all | :inet.ip_address(), :inet.port_number()}) :: GenServer.on_start()
def start({addr, port}), do: GenServer.start(__MODULE__, {addr, port, []})

@doc "Returns the number of currently active inbound WSS connections."
@spec connection_count(pid()) :: non_neg_integer()
def connection_count(pid), do: GenServer.call(pid, :connection_count)
```

The third element in the init tuple is an optional keyword list for test overrides
(`:max_connections`, `:certfile`, `:keyfile`), mirroring `TLSListener`.

### State

```elixir
%{
  localip:         :inet.ip_address(),
  localport:       :inet.port_number(),
  socket:          :ssl.sslsocket(),       # the TLS listen socket
  upperlayer:      pid() | (atom(), map() -> :ok) | nil,
  max_connections: non_neg_integer(),
  connections:     %{reference() => {:inet.ip_address(), :inet.port_number(), pid()}}
}
```

`connections` is keyed by monitor reference (O(1) lookup on `:DOWN`), identical to
`TLSListener`.

### `init/1`

```elixir
@impl true
def init({addr, port, opts}) do
  localip  = resolve_localip(addr)
  max_conn = Keyword.get(opts, :max_connections,
    Application.get_env(:elixip2, :wss_max_connections, @default_max_connections))
  certfile = Keyword.get(opts, :certfile,
    Application.get_env(:elixip2, :tls_certfile, @default_certfile))
  keyfile  = Keyword.get(opts, :keyfile,
    Application.get_env(:elixip2, :tls_keyfile, @default_keyfile))
  bind_addr = if addr == :all, do: {0, 0, 0, 0}, else: addr

  ssl_opts = [
    :binary, {:packet, :raw}, {:active, false}, {:reuseaddr, true},
    {:ip, bind_addr},
    {:certfile, to_charlist(certfile)},
    {:keyfile,  to_charlist(keyfile)},
    {:versions, [:"tlsv1.2", :"tlsv1.3"]}
  ]

  case :ssl.listen(port, ssl_opts) do
    {:ok, listen_socket} ->
      {:ok, {_, actual_port}} = :ssl.sockname(listen_socket)
      listener_pid = self()
      Task.start_link(fn -> accept_loop(listen_socket, listener_pid) end)
      Logger.info([module: __MODULE__,
                   message: "WSS listener started on #{SIP.NetUtils.ip2string(localip)}:#{actual_port}"])
      state = %{
        localip:         localip,
        localport:       actual_port,
        socket:          listen_socket,
        upperlayer:      nil,
        max_connections: max_conn,
        connections:     %{}
      }
      {:ok, state}

    {:error, reason} ->
      Logger.error([module: __MODULE__,
                    message: "Failed to bind WSS socket on port #{port}: #{inspect(reason)}"])
      {:stop, reason}
  end
end
```

Configuration reuses `:tls_certfile` / `:tls_keyfile` (same certificate pair as TLS),
but has its own `:wss_max_connections` cap.

### Accept Loop (Task)

```elixir
defp accept_loop(listen_socket, listener_pid) do
  case :ssl.transport_accept(listen_socket) do
    {:ok, tls_transport_socket} ->
      case :ssl.handshake(tls_transport_socket, @handshake_timeout) do
        {:ok, ssl_socket} ->
          case do_ws_upgrade(ssl_socket) do
            {:ok, ws_socket, peer_ip, peer_port} ->
              case GenServer.call(listener_pid, {:spawn_connection, ws_socket, peer_ip, peer_port}) do
                {:ok, conn_pid} ->
                  GenServer.cast(conn_pid, :activate_socket)
                :rejected ->
                  :ok   # Listener already closed the socket.
              end

            {:error, reason} ->
              Logger.warning([module: __MODULE__,
                message: "WSS WebSocket upgrade failed: #{inspect(reason)}"])
              :ssl.close(ssl_socket)
          end

        {:error, reason} ->
          Logger.warning([module: __MODULE__,
            message: "WSS TLS handshake failed: #{inspect(reason)}"])
      end
      accept_loop(listen_socket, listener_pid)

    {:error, :closed} -> :ok

    {:error, reason} ->
      Logger.warning([module: __MODULE__, message: "WSS accept error: #{inspect(reason)}"])
      accept_loop(listen_socket, listener_pid)
  end
end
```

### WebSocket Upgrade Helper

```elixir
defp do_ws_upgrade(ssl_socket) do
  try do
    {:ok, {peer_ip, peer_port}} = :ssl.peername(ssl_socket)

    # Wrap the raw :sslsocket in a %Socket.Web{} for the upgrade handshake.
    # key: nil signals "listening socket" to Socket.Web.accept!/1.
    ssl_struct     = %Socket.SSL{socket: ssl_socket}
    listen_wrapper = %Socket.Web{socket: ssl_struct, key: nil}

    # Step A: accept the underlying SSL connection and read the HTTP Upgrade request.
    # Returns %Socket.Web{socket: ssl_struct, key: ws_key, path: path, ...}
    pending = Socket.Web.accept!(listen_wrapper)

    # Optionally inspect pending.path / pending.origin here before committing.

    # Step B: send HTTP/1.1 101 Switching Protocols.
    # Returns the underlying %Socket.SSL{} (upgrade complete, raw framing).
    upgraded_ssl = Socket.Web.accept!(pending, protocol: "sip")

    # Reconstruct a usable %Socket.Web{} from the pending struct + upgraded socket.
    ws_socket = %{pending | socket: upgraded_ssl, mask: nil}

    {:ok, ws_socket, peer_ip, peer_port}
  rescue
    e -> {:error, e}
  end
end
```

**Why `mask: nil`?**  In `socket2`, `mask: nil` means "no mask" and triggers the
`forge(nil, data)` branch which emits an unmasked frame. `mask: false` incorrectly
falls into the integer-key branch and crashes at runtime. RFC 6455 §5.1: the server
MUST NOT mask outgoing frames. Clients always mask their frames; the reader in
`Socket.Web.active/2` handles unmasking transparently.

**Why reconstruct `%Socket.Web{}` manually?**  `Socket.Web.accept!` step B only sends
the HTTP 101 and returns the raw underlying socket — it does not build a `%Socket.Web{}`
usable for framing. The pending struct from step A carries `path`, `origin`, `version`,
`protocols`, and `extensions`; keeping it avoids re-parsing.

### `handle_call({:spawn_connection, ws_socket, peer_ip, peer_port}, ...)` 

```elixir
def handle_call({:spawn_connection, ws_socket, peer_ip, peer_port}, _from, state) do
  if map_size(state.connections) >= state.max_connections do
    Logger.warning([module: __MODULE__,
      message: "WSS connection limit (#{state.max_connections}) reached — rejecting"])
    Socket.Web.abort(ws_socket)
    {:reply, :rejected, state}
  else
    case GenServer.start_link(SIP.Transport.WSS,
           {:inbound, ws_socket, state.localip, state.localport, peer_ip, peer_port}) do
      {:ok, conn_pid} ->
        unless is_nil(state.upperlayer) do
          GenServer.call(conn_pid, {:setupperlayer, state.upperlayer})
        end
        ref = Process.monitor(conn_pid)
        connections = Map.put(state.connections, ref, {peer_ip, peer_port, conn_pid})
        Logger.debug([module: __MODULE__,
          message: "Accepted WSS connection from #{SIP.NetUtils.ip2string(peer_ip)}:#{peer_port}"])
        {:reply, {:ok, conn_pid}, %{state | connections: connections}}

      {:error, reason} ->
        Logger.error([module: __MODULE__,
          message: "Failed to start WSS connection handler: #{inspect(reason)}"])
        Socket.Web.abort(ws_socket)
        {:reply, :rejected, state}
    end
  end
end
```

### Remaining Callbacks

These are structurally identical to `TLSListener` with `wss`/`:ssl` substituted for
`tls`/`:ssl`:

```elixir
def handle_call({:setupperlayer, ul}, _from, state) ...   # propagate to all connections
def handle_call(:connection_count, _from, state) ...
def handle_call(:getlocalipandport, _from, state) ...
def handle_call({:sendmsg, msg, dest_ip, dest_port}, _from, state) ...  # route to conn_pid

def handle_info({:DOWN, ref, :process, _pid, _reason}, state) ...  # remove from connections

def terminate(_reason, state) do
  :ssl.close(state.socket)
end
```

---

## Key Differences from TLSListener

| Aspect | TLSListener | WSSListener |
|---|---|---|
| Handshake steps | TLS only | TLS + HTTP WebSocket upgrade |
| Listen socket type | raw `:sslsocket` | raw `:sslsocket` (same) |
| Connection handler | `SIP.Transport.TLS` | `SIP.Transport.WSS` |
| Activate mechanism | `:ssl.setopts({:active, true})` | `Socket.Web.process + active` |
| Receives data as | `{:ssl, sock, data}` → Depack | `{:web, ws, data}` (framed) |
| Depack buffer | yes | **no** |
| Frame masking | n/a | `mask: nil` (server MUST NOT mask, RFC 6455 §5.1) |
| Peer IP retrieval | `:ssl.peername(ssl_socket)` | `:ssl.peername(ssl_socket)` (same) |
| Connection close | `{:ssl_closed, _}` | `{:web_closed, _}` |
| Config key (cap) | `:tls_max_connections` | `:wss_max_connections` |
| Config key (certs) | `:tls_certfile`, `:tls_keyfile` | same (reused) |

---

## Configuration

```elixir
# config/config.exs or config/runtime.exs
config :elixip2,
  # Maximum simultaneous inbound WSS connections (default: 100).
  wss_max_connections: 100,

  # Certificates are shared with the TLS transport.
  tls_certfile: "certs/certificate.pem",
  tls_keyfile:  "certs/private_key.pem"
```

---

## Integration with ElixippCLI

Replace the stub in `start_listeners/1`:

```elixir
{:wss, addr, port} ->
  case SIP.Transport.WSSListener.start({addr, port}) do
    {:ok, pid} -> {:ok, pid}
    {:error, reason} ->
      Logger.error([module: __MODULE__,
        message: "Failed to start WSS listener on port #{port}: #{inspect(reason)}"])
      {:error, reason}
  end
```

Then set the upper layer on the returned pid, same as for UDP and TLS:

```elixir
GenServer.call(listener_pid, {:setupperlayer, upper_layer_pid_or_fun})
```

CLI invocation:

```bash
elixipp --listen wss:443 --scenario scenarios/uas_register.exs
```

---

## Sequence Diagram: Inbound REGISTER over WSS

```
Browser/WebRTC client     accept Task           WSSListener      WSS GenServer    RegistrarUAS
        |                     |                     |                 |                |
        |--TCP SYN/ACK------->|                     |                 |                |
        |--TLS ClientHello--->|                     |                 |                |
        |<-TLS ServerHello----|                     |                 |                |
        |  (TLS handshake)    |                     |                 |                |
        |--HTTP GET / Upgrade>|                     |                 |                |
        |<-HTTP 101 ----------|                     |                 |                |
        |  (WS upgraded)      |                     |                 |                |
        |                     |--call(:spawn_connection, ws, ip, port)|                |
        |                     |                     |--start_link     |                |
        |                     |                     |  {:inbound,...} |                |
        |                     |<--{:ok, conn_pid}---|                 |                |
        |                     |--cast(:activate_socket)-------------->|                |
        |                     |                     |  Socket.Web reader spawned       |
        |                     |                     |                 |                |
        |--REGISTER (WS text frame)---------------->|                 |                |
        |                     |                {:web, ws, data}       |                |
        |                     |                     |  process_incoming_message        |
        |                     |                     |  start UAS transaction---------->|
        |                     |                     |  spawn scenario instance-------->|
        |<--100 Trying (WS text frame)------------------------------------------------|
        |<--200 OK / 401 Unauthorized (WS text frame)---------------------------------|
```

---

## Open Questions

1. **Protocol negotiation**: RFC 7118 §3 recommends that both sides advertise `sip` as
   the WebSocket sub-protocol. The design includes `Sec-WebSocket-Protocol: sip` in the
   101 response. A stricter implementation would close the connection if the client does
   not advertise `sip` in its `Sec-WebSocket-Protocol` request header.

2. **Reader process supervision**: `Socket.Web.active/2` spawns an unlinked, unmonitored
   process. If the reader crashes silently, the WSS GenServer stops receiving messages
   without being notified. A future improvement is to monitor `active_pid` returned by
   `active/2` and stop the GenServer on failure.

3. **Origin / path filtering**: The upgrade helper reads `path` and the `Origin` header
   before sending 101. A configurable allow-list would let operators restrict which origins
   may connect. Not implemented in the initial version.

---

## Implementation Plan

> Découpé en phases indépendamment testables. Chaque phase se termine par
> `mix test` vert avant de passer à la suivante.

### Prérequis — constater l'existant

| Brique | Localisation | Réutilisation |
|---|---|---|
| TLS handshake et socket SSL | `SIP.Transport.TLSListener` | pattern identique : `:ssl.listen` + `:ssl.transport_accept` + `:ssl.handshake` |
| Frame delivery via `Socket.Web` | `SIP.Transport.WSS.handle_info({:web, …})` | repris tel quel pour l'inbound |
| `process_incoming_message` | `SIP.Transport.ImplHelpers` | fonctionne déjà avec `%Socket.Web{}` via la clause `_ ->` et `Socket.local/1` |
| Tests TLS listener | `test/sip_tls_listener_test.exs` | patron copié pour WSS : connexion cliente Socket.Web, attente `connection_count`, envoi REGISTER |
| Démarrage listeners | `ElixippCLI.start_listeners/1` | clause `{:tls, …}` à dupliquer pour `{:wss, …}` |

**Dépendance critique** : le HTTP WebSocket upgrade utilise `:crypto.hash(:sha, …)` et
`Base.encode64/1`, tous deux disponibles sans dépendance supplémentaire.

---

### Phase 1 — `SIP.Transport.WSS` : clause inbound + activation

**But** : étendre le GenServer WSS existant pour accepter une connexion déjà négociée,
sans modifier le comportement outbound.

**Fichier** : `lib/framework/SIPTransportWSS.ex`

- Nouvelle clause `init/1` pour les connexions inbound :

  ```elixir
  def init({:inbound, ws_socket, localip, localport, peer_ip, peer_port}) do
    state = %{
      t_isreliable: true,
      upperlayer:   nil,
      destip:       peer_ip,
      destport:     peer_port,
      socket:       ws_socket,   # %Socket.Web{} passif, reader pas encore démarré
      localip:      localip,
      localport:    localport
    }
    {:ok, state}
  end
  ```

  Pas de `buffer: %SIP.Transport.Depack{}` — inutile pour WSS.

- Nouvelle clause `handle_cast(:activate_socket, state)` :

  ```elixir
  def handle_cast(:activate_socket, state) do
    ws = Socket.Web.process(state.socket, self()) |> Socket.Web.active(true)
    {:noreply, %{state | socket: ws}}
  end
  ```

  `Socket.Web.process/2` pose `target_pid = self()` dans la struct.
  `Socket.Web.active/2` spawne le reader process qui délivre `{:web, ws, data}` à ce GenServer.

**Test (Phase 1)** — `test/sip_wss_listener_test.exs` (squelette) :

```elixir
defmodule SIP.Test.WSSListenerTest do
  use ExUnit.Case, async: false
  # Pas encore de Listener : démarre un WSS GenServer inbound directement
  # à partir d'une paire de sockets SSL + upgrade faite manuellement,
  # pour valider la clause init et activate_socket en isolation.
end
```

Ce test de Phase 1 peut rester vide (placeholder) ; les assertions réelles
arrivent en Phase 3.

**Vérification** : `mix compile` sans warning ; `mix test` vert (pas de régression
sur les tests WSS outbound existants).

---

### Phase 2 — `SIP.Transport.WSSListener`

**But** : implémenter le listener complet. Ficher créé à `lib/framework/SIPTransportWSSListener.ex`.

#### 2a — Init et accept loop

L'init utilise `:ssl.listen` directement (même pattern que `TLSListener`) :

```elixir
ssl_opts = [:binary, {:packet, :raw}, {:active, false}, {:reuseaddr, true},
            {:ip, bind_addr}, {:certfile, …}, {:keyfile, …},
            {:versions, [:"tlsv1.2", :"tlsv1.3"]}]
{:ok, listen_socket} = :ssl.listen(port, ssl_opts)
Task.start_link(fn -> accept_loop(listen_socket, self()) end)
```

L'accept loop enchaîne TLS handshake puis upgrade HTTP WebSocket :

```elixir
defp accept_loop(listen_socket, listener_pid) do
  case :ssl.transport_accept(listen_socket) do
    {:ok, tls_transport} ->
      case :ssl.handshake(tls_transport, @handshake_timeout) do
        {:ok, ssl_socket} ->
          case do_ws_upgrade(ssl_socket) do
            {:ok, ws_socket, peer_ip, peer_port} ->
              case GenServer.call(listener_pid,
                     {:spawn_connection, ws_socket, peer_ip, peer_port}) do
                {:ok, conn_pid} -> GenServer.cast(conn_pid, :activate_socket)
                :rejected       -> :ok
              end
            {:error, reason} ->
              Logger.warning(…)
              :ssl.close(ssl_socket)
          end
        {:error, reason} -> Logger.warning(…)
      end
      accept_loop(listen_socket, listener_pid)
    {:error, :closed} -> :ok
    {:error, reason}  -> Logger.warning(…); accept_loop(listen_socket, listener_pid)
  end
end
```

#### 2b — Upgrade HTTP WebSocket manuel

**Pourquoi manuel et non via `Socket.Web.accept!` ?**
`Socket.Web.accept!` step A appelle `Socket.accept!` sur la socket d'écoute, ce qui
relance `:ssl.transport_accept` — incompatible avec un `:sslsocket` déjà connecté issu
de `ssl.handshake`. L'upgrade est donc réalisé directement avec `:ssl.setopts` et `ssl.recv`.

```elixir
@ws_magic "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

defp do_ws_upgrade(ssl_socket) do
  try do
    {:ok, {peer_ip, peer_port}} = :ssl.peername(ssl_socket)

    # Lire la requête HTTP Upgrade en mode http_bin.
    :ssl.setopts(ssl_socket, [{:packet, :http_bin}])
    {path, headers} = read_http_request(ssl_socket, nil, %{})

    ws_key = Map.get(headers, "sec-websocket-key")
    unless ws_key, do: raise("missing Sec-WebSocket-Key")

    unless String.downcase(Map.get(headers, "upgrade", "")) == "websocket",
      do: raise("not a WebSocket upgrade")

    # Calculer Sec-WebSocket-Accept (RFC 6455 §4.2.2).
    accept_key =
      :crypto.hash(:sha, ws_key <> @ws_magic) |> Base.encode64()

    :ssl.setopts(ssl_socket, [{:packet, :raw}])
    :ssl.send(ssl_socket,
      "HTTP/1.1 101 Switching Protocols\r\n" <>
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" <>
      "Sec-WebSocket-Accept: #{accept_key}\r\n" <>
      "Sec-WebSocket-Version: 13\r\n" <>
      "Sec-WebSocket-Protocol: sip\r\n\r\n")

    ws_socket = %Socket.Web{
      socket:    ssl_socket,
      version:   13,
      path:      path,
      key:       ws_key,
      mask:      nil,      # nil = no mask; server MUST NOT mask (RFC 6455 §5.1)
      protocols: ["sip"]
    }
    {:ok, ws_socket, peer_ip, peer_port}
  rescue
    e -> {:error, e}
  end
end

defp read_http_request(ssl_socket, path, headers) do
  case :ssl.recv(ssl_socket, 0, 5_000) do
    {:ok, {:http_request, :GET, {:abs_path, p}, _}} ->
      read_http_request(ssl_socket, to_string(p), headers)
    {:ok, {:http_header, _, field, _, value}} ->
      key = field |> to_string() |> String.downcase()
      read_http_request(ssl_socket, path, Map.put(headers, key, to_string(value)))
    {:ok, :http_eoh} ->
      {path, headers}
    {:error, reason} ->
      raise "HTTP read error: #{inspect(reason)}"
  end
end
```

#### 2c — `spawn_connection` et callbacks restants

Identiques à `TLSListener`, avec les substitutions `tls` → `wss` / `:ssl.close` → `Socket.Web.abort` pour les connexions WSS :

```elixir
def handle_call({:spawn_connection, ws_socket, peer_ip, peer_port}, _from, state) do
  if map_size(state.connections) >= state.max_connections do
    Socket.Web.abort(ws_socket)
    {:reply, :rejected, state}
  else
    case GenServer.start_link(SIP.Transport.WSS,
           {:inbound, ws_socket, state.localip, state.localport, peer_ip, peer_port}) do
      {:ok, conn_pid} ->
        unless is_nil(state.upperlayer), do: GenServer.call(conn_pid, {:setupperlayer, state.upperlayer})
        ref = Process.monitor(conn_pid)
        {:reply, {:ok, conn_pid}, %{state | connections: Map.put(state.connections, ref, {peer_ip, peer_port, conn_pid})}}
      {:error, _} ->
        Socket.Web.abort(ws_socket)
        {:reply, :rejected, state}
    end
  end
end
```

`terminate/2` :

```elixir
def terminate(_reason, state), do: :ssl.close(state.socket)
```

**Vérification** : `mix compile` sans warning.

---

### Phase 3 — Tests `test/sip_wss_listener_test.exs`

Patron calqué sur `sip_tls_listener_test.exs`. Le client de test utilise
`Socket.Web.connect!/3` (déjà dans le projet via `socket2`).

```elixir
@wss_client_opts [secure: true, verify: false,
                  versions: [:"tlsv1.2"], protocol: ["sip"]]

setup do
  {:ok, pid} = GenServer.start(SIP.Transport.WSSListener,
    {:all, 0, [certfile: @certfile, keyfile: @keyfile]})
  {:ok, _ip, port} = GenServer.call(pid, :getlocalipandport)
  on_exit(fn -> try do GenServer.stop(pid) catch :exit, _ -> :ok end end)
  {:ok, listener: pid, port: port}
end
```

**Tests transport (sans assertions SIP)** :

| Test | Description |
|---|---|
| `initial connection_count is zero` | identique TLS |
| `accepts an inbound WSS connection` | `Socket.Web.connect!` + `wait_until(count == 1)` |
| `tracks multiple simultaneous WSS connections` | deux connexions, count == 2 |
| `connection removed on client disconnect` | `Socket.Web.close!` + `wait_until(count == 0)` |
| `excess connections are rejected` | `max_connections: 1`, second connect reçoit `{:web_closed, _}` |

**Test SIP data-flow** :

```elixir
test "SIP REGISTER over WSS receives a response", %{port: port} do
  ws = Socket.Web.connect!("127.0.0.1", port, @wss_client_opts)
  Socket.Web.send!(ws, {:text, build_register()})
  {:ok, {:text, response}} = Socket.Web.recv!(ws, timeout: 5_000)
  assert String.starts_with?(response, "SIP/2.0 ")
  Socket.Web.close!(ws)
end
```

**Pas de test "fragmentation"** : contrairement à TLS/TCP, le framing WebSocket délimite
les messages — un SIP REGISTER tient dans une frame, la réassemblage `Depack` est absent.

**Vérification** : `mix test test/sip_wss_listener_test.exs` vert ; `mix test` global vert.

---

### Phase 4 — Intégration `ElixippCLI`

**Fichier** : `lib/elixipp/ElixippCLI.ex`, fonction `start_listeners/1` (ligne ~443).

Remplacer la clause stub WSS :

```elixir
# Avant :
{proto, _addr, _port} = l when proto in [:tls, :wss] ->
  {l, :not_implemented}

# Après :
{:tls, addr, port} = l ->
  case SIP.Transport.TLSListener.start({addr, port}) do
    {:ok, _pid} -> {l, :ok}
    {:error, reason} -> {l, {:error, reason}}
  end

{:wss, addr, port} = l ->
  case SIP.Transport.WSSListener.start({addr, port}) do
    {:ok, _pid} -> {l, :ok}
    {:error, reason} -> {l, {:error, reason}}
  end
```

Mettre à jour le texte `--help` pour documenter `--listen wss:PORT`.

**Test (Phase 4)** : smoke test manuel (pas de test automatisé `ElixippCLI` existant) :

```bash
mix escript.build
./elixipp --listen wss:5065 scenarios/uas_register.exs &
# Connecter un client WebSocket SIP (ex. JsSIP, ou le test Phase 3 pointé sur 5065)
```

**Vérification** : `mix test` global vert (TLS clause déplacée n'a pas régressé).

---

### Phase 5 — Documentation

**Fichier** : `docs/TLS_WSS.md`

- Mettre à jour la section *WSS (WebSocket over TLS)* (actuellement « not yet
  implemented ») pour décrire l'architecture `WSSListener` → `WSS :inbound`, la
  différence d'activation (reader process vs `{:active, true}`), et l'absence de Depack.
- Ajouter sous *Runtime Configuration* la clé `:wss_max_connections`.
- Ajouter sous *Starting a TLS Listener via elixipp* un équivalent WSS :
  ```bash
  elixipp --listen wss:443 --scenario scenarios/uas_register.exs
  ```

**Fichier** : `CLAUDE.md`

Ajouter dans la section *Transport Layer* une ligne pour `SIP.Transport.WSSListener`,
et noter l'absence de Depack pour WSS dans la section *Message Layer*.

**Vérification** : relire `docs/TLS_WSS.md` et `CLAUDE.md` ; `mix test` final vert.

---

### Ordre recommandé et jalons

```
Phase 1  →  Phase 2a  →  Phase 2b  →  Phase 2c  →  Phase 3  →  Phase 4  →  Phase 5
  WSS          init      upgrade       spawn        tests       CLI          doc
inbound      Listener    manuel       connection   complets   intégré     à jour
```

**Jalon MVP** : Phases 1–3 — un listener WSS fonctionnel avec tests automatisés.
**Jalon CLI** : Phase 4 — `elixipp --listen wss:PORT` opérationnel.
**Jalon doc** : Phase 5 — documentation cohérente avec l'implémentation.

### Vérification globale

```bash
mix compile --warnings-as-errors
mix test                                  # suite complète
mix test test/sip_wss_listener_test.exs  # listener WSS en isolation
mix escript.build && ./elixipp --listen wss:5065 scenarios/uas_register.exs
```
