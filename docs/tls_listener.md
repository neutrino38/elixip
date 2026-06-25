# TLS Listener Design

## Context and Motivation

`SIP.Transport.TLS` was previously outbound-only (client connections via `Socket.SSL`).
For UAS (server) scenarios over TLS, we need the symmetric counterpart: a **TLS listener**
that binds to a local port, performs the TLS handshake for each accepted connection, and
routes each one through the same SIP processing pipeline as the TCP listener.

The design mirrors `SIP.Transport.TCPListener` exactly; the differences are confined to
the OTP `:ssl` API vs `:gen_tcp`.

---

## Architecture Overview

```
SIP.Transport.TLSListener          (one per bound port)
   │  :ssl.listen — binds a TLS server socket
   │  accept Task loops on :ssl.transport_accept + :ssl.handshake
   │
   ├── SIP.Transport.TLS  :inbound  (one per accepted + handshaked connection)
   │      same GenServer as the outbound TLS client, second init/1 clause
   │      receives {:ssl, socket, data} from OTP's SSL application
   │      owns a %SIP.Transport.Depack{} reassembly buffer
   │      calls ImplHelpers.process_incoming_message
   │
   └── SIP.Transport.TLS  :inbound  (another accepted connection)
         ...
```

`SIP.Transport.TLS` is extended with a second `init/1` clause for accepted sockets.
No new module is introduced on the connection side.

---

## API differences: `:gen_tcp` → `:ssl`

| Step | TCP | TLS |
|---|---|---|
| Listen | `:gen_tcp.listen/2` | `:ssl.listen/2` (+ certfile/keyfile) |
| Accept | `:gen_tcp.accept/1` | `:ssl.transport_accept/1` then `:ssl.handshake/1` |
| Ownership transfer | `:gen_tcp.controlling_process/2` | `:ssl.controlling_process/2` |
| Activate | `:inet.setopts(socket, active: true)` | `:ssl.setopts(socket, active: true)` |
| Close | `:gen_tcp.close/1` | `:ssl.close/1` |
| Incoming data | `{:tcp, socket, data}` | `{:ssl, socket, data}` |
| Disconnect | `{:tcp_closed, socket}` | `{:ssl_closed, socket}` |

The TLS handshake (`:ssl.handshake/1`) is blocking (~50–200 ms). It runs inside the
accept Task, not in the Listener's GenServer loop, to avoid stalling `handle_call`.

---

## SIP.Transport.TLS — Extended for Inbound Connections

### New `init/1` clause

The existing clause handles outbound connections via `ImplHelpers.connect/2`:

```elixir
def init({dest_ip, dest_port}) do   # outbound — unchanged
  ...
  SIP.Transport.ImplHelpers.connect(initial_state, :tls)
  ...
end
```

A new clause handles inbound accepted sockets:

```elixir
def init({:inbound, ssl_socket, localip, localport, peer_ip, peer_port}) do
  state = %{
    t_isreliable: true,
    upperlayer:   nil,
    destip:       peer_ip,
    destport:     peer_port,
    buffer:       %SIP.Transport.Depack{},
    socket:       ssl_socket,
    localip:      localip,
    localport:    localport
  }
  {:ok, state}
end
```

### `handle_cast(:activate_socket)`

Activates the socket after ownership transfer from the accept Task:

```elixir
def handle_cast(:activate_socket, state) do
  :ssl.setopts(state.socket, [{:active, true}])
  {:noreply, state}
end
```

### Socket duality

Inbound sockets are raw `:sslsocket` tuples (OTP `:ssl`); outbound sockets are
`%Socket.SSL{}` structs (the `socket2` library). Private helpers abstract the difference:

```elixir
defp tls_send({:sslsocket, _, _} = s, data), do: :ssl.send(s, data)
defp tls_send(s, data), do: Socket.Stream.send(s, data)

defp tls_close({:sslsocket, _, _} = s), do: :ssl.close(s)
defp tls_close(s), do: Socket.close(s)
```

---

## SIP.Transport.TLSListener

### State

```elixir
%{
  localip:         {a, b, c, d},
  localport:       integer(),
  socket:          listen_socket :: :sslsocket,
  upperlayer:      pid | (atom, map -> :ok) | nil,
  max_connections: integer(),
  connections:     %{ ref() => {peer_ip, peer_port, conn_pid} }
}
```

`connections` is keyed by monitor reference so `{:DOWN, ref, …}` lookup is O(1).

### Init

```elixir
def init({addr, port, opts}) do
  ssl_opts = [
    :binary, {:packet, :raw}, {:active, false}, {:reuseaddr, true}, {:ip, bind_addr},
    {:certfile, to_charlist(certfile)},
    {:keyfile,  to_charlist(keyfile)},
    {:versions, [:"tlsv1.2", :"tlsv1.3"]}
  ]
  {:ok, listen_socket} = :ssl.listen(port, ssl_opts)
  {:ok, {_, actual_port}} = :ssl.sockname(listen_socket)
  Task.start_link(fn -> accept_loop(listen_socket, self()) end)
  ...
end
```

### Ownership transfer sequence

```
accept Task                  TLSListener GenServer        TLS GenServer
     |                              |                           |
     |--:ssl.transport_accept()     |                           |
     |--:ssl.handshake()            |                           |
     |--GenServer.call(:spawn_connection, ssl_socket)           |
     |                              |--GenServer.start_link---->|
     |                              |  {:inbound, ssl_socket,…} |
     |<-----{:ok, conn_pid}---------|                           |
     |--:ssl.controlling_process(ssl_socket, conn_pid)          |
     |--GenServer.cast(conn_pid, :activate_socket)------------->|
     |                              |      :ssl.setopts active:true
```

**Why handshake in the Task?** `:ssl.handshake/1` blocks for the full TLS negotiation.
Running it in the Task avoids holding the Listener's GenServer during that time.
A failed handshake is logged at `warning` level and the loop continues.

**Critical ordering: `controlling_process` → `activate_socket`.**
`:ssl` delivers `{:ssl, socket, data}` to the *controlling process*. Setting
`active: true` before the transfer would deliver frames to the Task instead of
the `TLS` GenServer.

---

## ImplHelpers — `:sslsocket` case

`process_incoming_message` resolves the local IP/port from the socket. Inbound TLS
sockets require a dedicated branch since `:ssl.sockname/1` must be used instead of
`Socket.local/1`:

```elixir
s when is_tuple(s) and elem(s, 0) == :sslsocket ->
  case :ssl.sockname(s) do
    {:ok, {{0,0,0,0}, _}} -> {state.localip, state.localport}
    {:ok, {ip, port}}     -> {ip, port}
    _                     -> {state.localip, state.localport}
  end
```

---

## Configurable connection limit

```elixir
# config/config.exs
config :elixip2, :tls_max_connections, 100
```

When the limit is reached, the Listener closes the accepted (already handshaked) socket
immediately and logs a warning. No SIP 503 is sent — rejecting at the transport layer is
consistent with what a saturated system does.

---

## Sequence Diagram: Inbound REGISTER over TLS

```
Client          TLSListener (accept Task)   SIP.Transport.TLS    RegistrarUAS
  |                      |                         |                   |
  |--TLS handshake------->|                         |                   |
  |                      |--{:spawn_connection}---->|                   |
  |                      |   start_link {:inbound}  |                   |
  |                      |   controlling_process    |                   |
  |                      |   activate_socket        |                   |
  |                      |                          |                   |
  |--REGISTER (SIP)------>|                          |                   |
  |               {:ssl, socket, data}               |                   |
  |                      |------------------------>|                    |
  |                      |         Depack.on_data_received               |
  |                      |         process_incoming_message              |
  |                      |         (start UAS transaction)               |
  |                      |         (dispatch to RegistrarUAS)---------->|
  |<--200 OK (or 401)----|-------------------------|                    |
```

---

## WSS Listener (planned)

A WSS listener will follow the same pattern: `:ssl.listen` + handshake in the Task,
then a WebSocket upgrade (via `Socket.Web.accept!/1` or equivalent) before spawning a
`SIP.Transport.WSS` inbound instance. Certificate configuration will reuse the same
`tls_certfile` / `tls_keyfile` keys. See [TLS_WSS.md](../TLS_WSS.md) for shared
certificate guidance.
