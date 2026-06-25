# TLS and WSS Transport Configuration

This document covers certificate management, runtime configuration, and operational
guidance for the TLS (`SIP.Transport.TLS` / `SIP.Transport.TLSListener`) and WSS
(`SIP.Transport.WSS`) transports.

---

## Certificate Requirements

Both TLS and WSS use X.509 certificates for authentication and encryption.
Two files are required:

| File | Purpose |
|---|---|
| Certificate (PEM) | Server identity sent to the peer during the TLS handshake |
| Private key (PEM) | Proves ownership of the certificate — keep this secret |

### Generating a self-signed certificate (development / testing)

```bash
# Generate a 2048-bit RSA key and a self-signed certificate valid for 365 days.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/private_key.pem \
  -out    certs/certificate.pem \
  -days   365 \
  -subj   "/C=FR/ST=Isere/L=Grenoble/O=Elixip/CN=localhost"
```

> Self-signed certificates are **not trusted by default** by remote peers. They are
> suitable for local testing and interoperability tests with `verify: :verify_none`,
> but must be replaced by a CA-signed certificate in production.

### Obtaining a CA-signed certificate (production)

Options, from simplest to most complex:

1. **Let's Encrypt / ACME** — free, auto-renewed, trusted everywhere.
   Use [certbot](https://certbot.eff.org/) or an ACME client library.
   Certificate lives in `/etc/letsencrypt/live/<domain>/`.

2. **Internal CA** — for closed-network deployments; sign with your organisation's CA.

3. **Commercial CA** — Digicert, Sectigo, etc.

After obtaining the certificate, place both files somewhere accessible to the Elixir
process (absolute paths are safest in production).

---

## Runtime Configuration

### Application environment (`config/config.exs` or `config/runtime.exs`)

```elixir
config :elixip2,
  # Path to the PEM certificate used by TLS and WSS server sockets.
  tls_certfile: "/etc/elixip/certs/certificate.pem",

  # Path to the unencrypted PEM private key.
  tls_keyfile: "/etc/elixip/certs/private_key.pem",

  # Maximum simultaneous inbound TLS connections (default: 100).
  tls_max_connections: 200,

  # Allowed TLS versions. Restrict to :"tlsv1.3" only for highest security.
  # Default: [:"tlsv1.2", :"tlsv1.3"]
  tls_versions: [:"tlsv1.2", :"tlsv1.3"],

  # Cipher suite override (list of charlists, Mozilla "Intermediate" profile by default).
  # tls_ciphers: [~c"ECDHE-ECDSA-AES256-GCM-SHA384", ...]
```

> The `tls_certfile` and `tls_keyfile` keys are used both by the **TLS listener**
> (`TLSListener.init/1`) and by the **outbound TLS client** (`ImplHelpers.connect/2`).

### Per-listener override (tests and programmatic use)

When starting a listener directly, pass overrides in the opts keyword list:

```elixir
GenServer.start(SIP.Transport.TLSListener,
  {:all, 5061, [
    certfile: "/path/to/cert.pem",
    keyfile:  "/path/to/key.pem",
    max_connections: 50
  ]})
```

---

## Starting a TLS Listener via `elixipp`

```bash
elixipp --listen tls:5061 --scenario scenarios/uas_register.exs
```

The `--listen tls:PORT` option is parsed by `ElixippCLI`. The listener reads
`tls_certfile` / `tls_keyfile` from the application environment, so set them in
`config/runtime.exs` or via environment variables before startup.

---

## TLS Listener Architecture

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

### Ownership transfer sequence

```
accept Task                  TLSListener GenServer        TLS GenServer
     |                              |                           |
     |--:ssl.transport_accept()     |                           |
     |--:ssl.handshake()            |                           |
     |--GenServer.call(:spawn_connection, ssl_socket)---------->|
     |                              |  GenServer.start_link     |
     |                              |  {:inbound, ssl_socket,…} |
     |<----- {:ok, conn_pid} -------|                           |
     |--:ssl.controlling_process(ssl_socket, conn_pid)          |
     |--GenServer.cast(conn_pid, :activate_socket)------------->|
     |                              |         :ssl.setopts active:true
```

The handshake happens in the Task (blocking, ~50–200 ms) to avoid stalling the
Listener's `handle_call` loop. A failed handshake is logged and the loop continues.

---

## WSS (WebSocket over TLS)

WSS uses the same certificates as TLS. The `SIP.Transport.WSS` outbound client
reads `tls_certfile` and `tls_keyfile` through `ImplHelpers.connect/2` (`:wss` branch).

A WSS **listener** (`SIP.Transport.WSSListener`) is not yet implemented. When added,
it will follow the same pattern as `TLSListener` but wrap the accepted TLS socket in
a WebSocket upgrade handshake (via `Socket.Web.accept!/1` or equivalent), before
spawning a `SIP.Transport.WSS` inbound instance.

---

## Security Recommendations

| Topic | Recommendation |
|---|---|
| Key protection | Set permissions `chmod 600 private_key.pem`; never commit to git |
| TLS versions | Disable TLS 1.0 and 1.1 (already excluded by default) |
| Certificate expiry | Automate renewal (Let's Encrypt with 90-day certs) |
| Client auth (mTLS) | Add `{:verify, :verify_peer}` and `{:cacertfile, "..."}` for mutual TLS |
| SNI | For multi-domain servers, add `{:sni_hosts, [{hostname, ssl_opts}]}` |

### Enabling mutual TLS (mTLS)

To require the client to present a certificate, add to the listener opts:

```elixir
{:verify, :verify_peer},
{:cacertfile, to_charlist("/path/to/ca-bundle.pem")},
{:fail_if_no_peer_cert, true}
```

---

## Troubleshooting

### `{:error, :enoent}` on startup

The certfile or keyfile path does not exist or is not readable by the OS user running
Elixir. Verify the paths and file permissions.

### Handshake timeout / `tls_alert`

- Self-signed cert rejected by client: use `verify: :verify_none` in the client, or add
  the cert to the client's CA store.
- Version mismatch: ensure both sides support a common TLS version
  (e.g. both allow `:"tlsv1.2"`).
- Cipher mismatch: check `tls_ciphers` on both ends.

### `{:error, :closed}` immediately after connect

Connection limit reached (`tls_max_connections`). Raise the limit or investigate why
connections are not being released.
