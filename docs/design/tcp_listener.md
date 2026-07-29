# TCP Listener Design

## Context and Motivation

The current transport layer supports **TCP only as an outbound client** (`SIP.Transport.TCP`):
it connects to a known destination and handles `{:tcp, socket, data}` for an established connection.
For UAS (server) scenarios, we need the symmetric counterpart: a **TCP listener** that binds to a
local port, accepts inbound connections, and routes each one through the same SIP processing pipeline
as UDP.

The `--listen tcp:PORT` option is already parsed by `ElixippCLI` but the implementation is currently
`:not_implemented` (`start_listeners/1`, lines 416-427 of `ElixippCLI.ex`).

---

## Architecture Overview

A TCP listener requires two distinct GenServer types:

```
SIP.Transport.TCPListener          (one per bound port)
   │  binds a server socket, loops on accept()
   │
   ├── SIP.Transport.TCP  :inbound  (one per accepted connection)
   │      same GenServer as the outbound TCP, new init clause
   │      handles {:tcp, socket, data}
   │      owns a %SIP.Transport.Depack{} buffer
   │      calls ImplHelpers.process_incoming_message
   │
   └── SIP.Transport.TCP  :inbound  (another accepted connection)
         ...
```

`SIP.Transport.TCP` is extended with a second `init/1` clause for accepted sockets.
No new module is introduced.

---

## SIP.Transport.TCP — Extended for Inbound Connections

### New `init/1` Clause

The existing clause handles outbound connections:

```elixir
def init({dest_ip, dest_port}) do   # outbound — unchanged
  ...
  SIP.Transport.ImplHelpers.connect(initial_state, :tcp)
  ...
end
```

A new clause handles inbound accepted sockets:

```elixir
def init({:inbound, socket, localip, localport, peer_ip, peer_port}) do
  state = %{
    t_isreliable: true,
    upperlayer:   nil,
    destip:       peer_ip,
    destport:     peer_port,
    buffer:       %SIP.Transport.Depack{},
    socket:       socket,
    localip:      localip,
    localport:    localport
  }
  {:ok, state}
end
```

The socket is already open and owned by this process (ownership transfer is done by
`TCPListener` before calling `start_link/1`, see below). All subsequent `handle_info`,
`handle_call`, and `terminate` callbacks are **identical** for both directions — no other
change is needed in `SIP.Transport.TCP`.

### `terminate/2` — Already Correct

```elixir
def terminate(_reason, state) do
  if not is_nil(state.socket) do
    Socket.close(state.socket)   # covers both outbound and inbound
  end
end
```

---

## SIP.Transport.TCPListener

### Responsibilities

- Bind a TCP server socket on `{addr, port}`.
- Run an accept loop: for each accepted socket, enforce the connection limit, then spawn a
  `SIP.Transport.TCP` instance with the `:inbound` init tuple.
- Register itself in `Registry.SIPTransport` under the key `"tcp_listener_addr:port"`.
- Monitor each spawned `TCP` process; decrement the connection count on exit.
- Propagate `upperlayer` to each spawned connection.
- Expose a `send/3` API that routes outbound messages through the right connection process.

### Configurable Connection Limit

```elixir
# config/config.exs
config :elixip2, :tcp_max_connections, 100
```

The limit is read at listener startup:

```elixir
max_connections = Application.get_env(:elixip2, :tcp_max_connections, 100)
```

When the limit is reached, the listener closes the accepted socket immediately (TCP RST) and
logs a warning. No SIP 503 is sent at this level — rejecting at the transport layer is simpler
and consistent with what a saturated system would do anyway.

### State

```elixir
%{
  t_isreliable:    true,
  localip:         {a, b, c, d},
  localport:       integer(),
  socket:          listen_socket :: port(),
  upperlayer:      pid | (atom, map -> :ok) | nil,
  max_connections: integer(),
  connections:     %{ ref() => {peer_ip, peer_port, conn_pid} }
  # keyed by monitor ref so DOWN messages are O(1)
}
```

`connections` is keyed by monitor reference (not peer address) so `{:DOWN, ref, ...}` lookup
is O(1). A reverse index `{peer_ip, peer_port} => conn_pid` is maintained alongside for
outbound send routing.

### Init

```elixir
def init({addr, port}) do
  localip = SIP.NetUtils.resolve_local_ip(addr)
  max_conn = Application.get_env(:elixip2, :tcp_max_connections, 100)

  {:ok, listen_socket} = :gen_tcp.listen(port, [
    :binary, {:packet, :raw}, {:active, false},
    {:reuseaddr, true}, {:ip, normalize_addr(addr)}
  ])

  Task.start_link(fn -> accept_loop(listen_socket, self()) end)

  state = %{
    t_isreliable:    true,
    localip:         localip,
    localport:       port,
    socket:          listen_socket,
    upperlayer:      nil,
    max_connections: max_conn,
    connections:     %{}
  }
  {:ok, state}
end

defp normalize_addr(:all), do: {0, 0, 0, 0}
defp normalize_addr(ip),   do: ip
```

**Why passive mode for the server socket?** `:gen_tcp.accept/1` is a blocking call. Running it
inside a linked Task avoids blocking the GenServer's `handle_info` loop. The Task sends each
accepted socket back to the listener via a message.

### Accept Loop (Task)

```elixir
defp accept_loop(listen_socket, listener_pid) do
  case :gen_tcp.accept(listen_socket) do
    {:ok, client_socket} ->
      send(listener_pid, {:new_connection, client_socket})
      accept_loop(listen_socket, listener_pid)

    {:error, :closed} ->
      :ok

    {:error, reason} ->
      Logger.warning("TCP accept error: #{inspect(reason)}")
      accept_loop(listen_socket, listener_pid)
  end
end
```

### handle_info: new connection

```elixir
def handle_info({:new_connection, client_socket}, state) do
  if map_size(state.connections) >= state.max_connections do
    Logger.warning([module: __MODULE__,
      message: "TCP connection limit #{state.max_connections} reached, rejecting inbound connection"])
    :gen_tcp.close(client_socket)
    {:noreply, state}
  else
    {:ok, {peer_ip, peer_port}} = :inet.peername(client_socket)

    # Transfer ownership before starting the GenServer so no :tcp message is
    # delivered to the listener between start_link and controlling_process.
    # start_link is synchronous: the TCP process is alive when it returns.
    {:ok, conn_pid} =
      SIP.Transport.TCP.start_link({:inbound, client_socket,
                                     state.localip, state.localport,
                                     peer_ip, peer_port})

    # Transfer socket ownership, then activate — order is critical.
    :gen_tcp.controlling_process(client_socket, conn_pid)
    :inet.setopts(client_socket, [{:active, true}])

    # Set upper layer on the new connection
    if not is_nil(state.upperlayer) do
      GenServer.call(conn_pid, {:setupperlayer, state.upperlayer})
    end

    ref = Process.monitor(conn_pid)
    connections = Map.put(state.connections, ref, {peer_ip, peer_port, conn_pid})
    {:noreply, %{state | connections: connections}}
  end
end
```

**Critical ordering: `controlling_process` → `setopts active: true`.**  
`:gen_tcp` delivers `{:tcp, socket, data}` to the *controlling process*. Setting `active: true`
before the transfer would deliver frames to the listener instead of the `TCP` process.

**Why start first, then transfer?** `start_link` is synchronous — the `TCP` process is alive
and has a registered pid when it returns. Doing the transfer before start would require a
two-step handshake (pass socket, process sends back readiness). The current order is simpler
and safe because no data can arrive between `start_link` and `controlling_process` while the
socket is still passive.

### handle_info: connection down

```elixir
def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
  connections = Map.delete(state.connections, ref)
  {:noreply, %{state | connections: connections}}
end
```

### Outbound sends via the listener

For a UAS, replies go directly through the `tp_pid` stored in `ruri_with_tp` (see below), so
the listener's `send` API is only needed if the Selector routes a new outbound request through
an existing inbound connection.

```elixir
def handle_call({:sendmsg, msg, dest_ip, dest_port}, _from, state) do
  conn_pid =
    state.connections
    |> Map.values()
    |> Enum.find_value(fn {ip, port, pid} ->
         if ip == dest_ip and port == dest_port, do: pid
       end)

  case conn_pid do
    nil ->
      {:reply, {:error, :no_connection}, state}

    pid ->
      result = GenServer.call(pid, {:sendmsg, msg, dest_ip, dest_port})
      {:reply, result, state}
  end
end
```

### Registry Key

```elixir
name = "tcp_listener_#{SIP.NetUtils.ip2string(localip)}:#{port}"
{:via, Registry, {Registry.SIPTransport, name}}
```

---

## SIP.Transport.Depack — Body Completion

The current `SIP.Transport.Depack` stops at `:reading_body` without accumulating bytes.
For TCP this must be completed before INVITE/200 OK flows work (SDP bodies). For a
REGISTER-only UAS, the body is empty and this is not blocking for the initial implementation,
but it must be done before any other method is served.

The fix is to accumulate `data` in `buf.body` until `byte_size >= clen`, then emit `:msg`
with the full message and re-process any trailing bytes:

```elixir
defp handle_reading_body(buf, data) do
  accumulated = buf.body <> data
  if byte_size(accumulated) >= buf.clen do
    {body, rest} = String.split_at(accumulated, buf.clen)
    complete_msg = buf.buffer <> body
    new_buf = %SIP.Transport.Depack{}
    {new_buf2, msgs} = on_data_received(new_buf, rest)
    {new_buf2, [{:msg, complete_msg} | msgs]}
  else
    {%{buf | body: accumulated}, []}
  end
end
```

---

## Integration with ElixippCLI

Replace the stub in `start_listeners/1`:

```elixir
defp start_listeners(listeners) do
  Enum.map(listeners, fn
    {:udp, addr, port} ->
      GenServer.start(SIP.Transport.UDP, {addr, port})

    {:tcp, addr, port} ->
      name = "tcp_listener_#{format_ip(addr)}:#{port}"
      GenServer.start(
        SIP.Transport.TCPListener,
        {addr, port},
        name: {:via, Registry, {Registry.SIPTransport, name}}
      )

    {proto, _addr, _port} when proto in [:tls, :wss] ->
      :not_implemented
  end)
end
```

The `upperlayer` is set on the listener after startup (same pattern as UDP today):

```elixir
GenServer.call(listener_pid, {:setupperlayer, upper_layer_pid_or_fun})
```

The listener propagates it to every subsequently accepted `TCP` process.

---

## Transport Selector — Reply Path

When a dialog arrives over an inbound TCP connection, RFC 3261 §18.2.2 requires that
replies go back on the **same connection**. This is already handled without any Selector
change: `process_incoming_message` enriches the parsed message with:

```elixir
ruri_with_tp = %SIP.Uri{
  destip:    peer_ip,
  destport:  peer_port,
  tp_module: SIP.Transport.TCP,
  tp_pid:    self()           # the TCP process for this connection
}
```

`SIP.Transac.*` modules send replies via `GenServer.call(tp_pid, {:sendmsg, ...})`, which
routes directly to the right `TCP` process — the Selector is not involved.

For new outbound requests on an existing dialog, the Selector can optionally look up an open
connection in the `TCPListener` connections map (via `{:sendmsg, _, dest_ip, dest_port}` on
the listener pid). This is a future optimisation; the initial implementation can fall back to
opening a new outbound `TCP` connection when no inbound one exists.

---

## Sequence Diagram: Inbound REGISTER over TCP

```
Client              TCPListener (accept loop)    SIP.Transport.TCP    RegistrarUAS
  |                        |                            |                   |
  |--TCP SYN/ACK---------->|                            |                   |
  |                        |--{:new_connection, sock}-->|                   |
  |                        |   start_link {:inbound}    |                   |
  |                        |   controlling_process      |                   |
  |                        |   active: true             |                   |
  |                        |                            |                   |
  |--REGISTER (SIP msg)--->|                            |                   |
  |                     {:tcp, socket, data}            |                   |
  |                        |-------------------------->|                    |
  |                        |              Depack.on_data_received            |
  |                        |              process_incoming_message           |
  |                        |              (start UAS transaction)            |
  |                        |              (dispatch to RegistrarUAS)-------->|
  |                        |              (spawn scenario instance)          |
  |<--100 Trying-----------|-----------------------------|                   |
  |<--200 OK (or 401)------|-----------------------------|                   |
```

---

## Open Questions

TLS and WSS listeners follow the same design (same Depack, same `SIP.Transport.TCP` extension)
and are deferred to a later iteration. Depack body completion is already implemented.
