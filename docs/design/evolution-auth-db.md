# auth_db evolution — challenging calls, and an `Auth` behaviour

**Status: discussion, nothing implemented.** Decisions marked **OPEN** are the ones
to settle before writing code.

Two things, related but separable:

1. **authenticate more than REGISTER** — INVITE first, then any request that starts
   a dialog or stands alone;
2. **make the backend replaceable** — MariaDB today, LDAP / HTTP / **Diameter**
   tomorrow, without touching a scenario.

## 1. Where we stand

`Kelix.Mod.AuthDb` is a `Kelix.Module` exporting `do_registration_auth/3` and
`lookup_ha1/2`. It decides, it never composes a response (§11.1). The verdict is
`:ok | {:requireauth, stale?} | {:reject, code, reason}`.

What is **already method-agnostic** and needs nothing:

- the digest itself — `SIP.Auth.expected_response_from_ha1(algorithm, ha1, req_method(req), auth)`
  takes the method from the request;
- the nonce — `SIP.Auth.Nonce` is stateless, HMAC'd over `(ts, rand, realm)`, with
  `:ok | :stale | :invalid`. Nothing about it is REGISTER-specific;
- replay protection — `Kelix.NonceCache.check_nc/2` on the `nc` counter;
- credential reading — `auth_header/1` already accepts **both** `Authorization` and
  `Proxy-Authorization`.

So the function is 90 % of the way to being general. What is REGISTER-specific is
everything *around* it, and that is where the design decisions are.

## 2. What actually changes when the request is an INVITE

### 2.1 Which realm

- REGISTER: the realm is the domain of the **To** — the AOR being bound.
- INVITE: the realm is the domain of the **From** — the *caller* is who we
  authenticate. The R-URI domain may be someone else entirely (that is the point of
  a call).

Getting this wrong makes every out-of-domain call unauthenticatable, or worse,
authenticatable against the wrong subscriber table.

### 2.2 Which identity, and checking it

REGISTER binds the AOR in `To`; the digest username must be that AOR (or its
subscriber, cf. `subscriber_of/1`).

INVITE is the dangerous one: **a successful digest proves who holds the password,
not who the `From` claims to be.** Without an explicit check, Alice authenticates
with her own credentials and places a call with `From: Bob` — identity spoofing, and
in a billing deployment, fraud. This is the single most-often-omitted rule in SIP
servers.

Proposal: the verdict carries the **authenticated identity**, and identity checking
is a stated policy rather than an accident:

```elixir
{:ok, %{user: "alice", realm: "example.com"}}
```

with `identity_check: :strict | :warn | :off` (default `:strict` for INVITE,
irrelevant for REGISTER where the check is inherent). **OPEN:** `:strict` breaks
trunk scenarios where one account legitimately asserts many `From`s. A per-domain
or per-subscriber "may assert" list is the real answer, and is its own feature —
`:warn` exists so the check can be turned on in observation mode first.

### 2.3 401 or 407

- A **UAS** answers `401` + `WWW-Authenticate` (RFC 3261 §22.2).
- A **proxy** answers `407` + `Proxy-Authenticate` (§22.3).

kelixip is a B2BUA, i.e. a UAS, so `401` is formally right — but real UAs and their
provisioning very often expect `407` for calls, and many will not retry a `401` on
an INVITE. This is a deployment fact, not a spec question.

Proposal: the **module stays neutral** (`{:requireauth, stale}`) and the **script
composes** 401 or 407, exactly as §11.1 prescribes. The backend only needs to read
whichever header came back, which it already does.

**Decided and implemented** (2026-08-11): `challenge_invite(realm, code \\ 407)`
was the wrong verb for it — it makes the *dialog layer* mint the nonce, which loses
`qop=auth`, `stale` and the backend's algorithm. A call script challenges with

```elixir
b2bua_challenge(req, Kelix.Auth.challenge_params(realm, stale: …, algorithm: …), 407)
```

the exact counterpart of `challenge_registration(sip_ctx, req, params)`: the
application builds the challenge (its own stateless nonce, which it validates
itself) and the verb puts it in the header the code calls for
(`SIP.Msg.Ops.challenge_header/1`, one reading of 401→`WWW-Authenticate` /
407→`Proxy-Authenticate`). `Kelix.Auth.challenge_www_authenticate/2` was renamed
`challenge_params/2` for the same reason: the params are header-agnostic, and only
the code decides which header carries them.

### 2.4 Which requests get challenged

| Request | Challenge? | Why |
|---|---|---|
| REGISTER | yes | as today |
| initial INVITE | yes | the point of this work |
| ACK | **never** | it has no response (§17.1.1.3) — challenging it is meaningless |
| CANCEL | **never** | §22.1; it must be accepted for the transaction it cancels |
| re-INVITE / UPDATE / BYE in-dialog | **no** | the dialog was authenticated when it was created; re-challenging mid-call breaks UAs and buys nothing |
| SUBSCRIBE / REFER out of dialog | yes | dialog-creating, same treatment as INVITE |
| MESSAGE / PUBLISH / OPTIONS | **OPEN** | not dialog-creating but abusable. OPTIONS especially: challenging it breaks liveness probing (see `Kelix.Options`), so probably never |

So the rule is not "creates a dialog" but **"is an initial request other than ACK,
CANCEL and OPTIONS"**. Worth stating that way in the spec: it is checkable in one
place and does not need a list to be maintained per method.

### 2.5 Nonce lifetime

A registration refresh happens every ~30 min; a call is placed once. **OPEN:** a
shorter `max_age` for call challenges (say 60 s vs. the registration default) costs
nothing to a caller — the retry is immediate — and shrinks the replay window. It
means `max_age` becomes a per-use parameter rather than a constant.

## 3. The `Auth` behaviour

### 3.1 Which layer to abstract

Two possible contracts, and they are not equivalent:

- **(A) the secret** — `fetch_ha1(user, realm) :: {:ok, ha1} | :notfound | {:error, r}`.
  kelixip keeps the digest logic. Fits MariaDB, LDAP, a file, an HTTP endpoint.
  Fits Diameter **Cx MAR/MAA with `SIP-Authentication-Scheme = Digest-MD5`**, which
  returns the H(A1) in `SIP-Digest-Authenticate`. Does **not** fit AKA (MAA returns
  RAND/AUTN/XRES — a challenge-response vector, not a password hash), nor any
  backend wanting its own policy (lockout counters, time-of-day rules).
- **(B) the verdict** — `authenticate(req_facts, opts) :: verdict`. The backend owns
  everything, including how the challenge is built. Fits everything, including AKA.
  Cost: every trivial backend must re-implement digest correctly, which is exactly
  the code nobody should write twice.

**Proposal: both, layered.** The behaviour is (B); kelixip ships a generic digest
implementation that a backend gets by implementing only (A):

```elixir
defmodule Kelix.Auth.Backend do
  @callback authenticate(req :: map, ctx :: auth_ctx, opts :: keyword) :: verdict
  @callback challenge_params(ctx :: auth_ctx, opts :: keyword) :: map
  # optional — implemented instead of the two above by a credential-shaped backend
  @callback fetch_credential(user :: String.t(), realm :: String.t()) ::
              {:ok, credential} | :notfound | {:error, term}
end

# a simple backend:
defmodule Kelix.Mod.AuthDb do
  use Kelix.Auth.Digest        # supplies authenticate/3 + challenge_params/2
  def fetch_credential(user, realm), do: ...   # the only thing it writes
end
```

`credential` is deliberately **not** "an HA1 string": `{:ha1, "MD5" | "SHA256", hex}`
today, room for `{:cleartext, pass}` and `{:aka_vector, rand, autn, xres, ck, ik}`
later. Freezing it as a hex string is the decision that would have to be undone the
day AKA lands.

`auth_ctx` is what the caller resolved from the request — `%{realm, identity_from:
:to | :from, method, uri}` — so the backend never re-parses the SIP message. Same
rule as the framework's message layer: one reading, in one place.

### 3.2 Where the behaviour lives

In the **core** (`apps/kelixip`), not in `kelix_modules`. A module must be able to
declare it without depending on another module, and `Kelix.Auth` (the challenge
builder) is already core. `Kelix.Mod.AuthDb` becomes *an* implementation; a future
`Kelix.Mod.AuthDiameter` is another.

### 3.3 Selecting a backend

Today a scenario names the module: `Kelix.Mod.AuthDb.do_registration_auth(req, domain)`.
That is what makes the backend unswappable — the script has the name baked in.

Proposal: a per-domain binding plus a core facade that routes:

```toml
[[domain]]
name = "example.com"
  [domain.auth]
  backend = "auth_db"        # a loaded module instance name
```

```elixir
# in the script — no backend named anywhere
case Kelix.Auth.authenticate(sip_ctx, req) do
  :ok -> ...
  {:requireauth, stale} -> ...
  {:reject, code, reason} -> ...
end
```

This is worth doing for its own sake, independently of Diameter: it removes the last
place where a reference script names an optional package.

**OPEN:** `config uses_modules: [:registrar, :auth_db]` in the script then names a
backend again. Either it becomes `[:auth]` (an abstract capability the preflight
resolves through `[domain.auth]`), or the preflight checks the *bound* backend per
domain. The second is more honest and slightly more work.

### 3.4 Compatibility

`do_registration_auth/3` stays, as `authenticate/3` with `identity_from: :to` and
the registration nonce lifetime. Existing scripts keep working unchanged.

## 4. Diameter, concretely

Only to check that the shape above survives contact with it. Cx/Dx (IMS HSS):

- **MAR/MAA** — `SIP-Auth-Data-Item` per scheme. With `Digest-MD5` the answer carries
  `SIP-Digest-Authenticate` (H(A1), realm, algorithm): maps onto `fetch_credential/2`
  and the generic digest path — **(A) suffices**;
- with **AKAv1-MD5**, the answer carries RAND/AUTN/XRES/CK/IK: the challenge is not a
  password hash and the exchange is two-legged. Needs the full `authenticate/3` —
  **(B) is required**;
- **SAR/SAA** (registration state) is a *different* concern: it belongs to whatever
  replaces/accompanies the registrar, not to the auth backend. Worth stating so the
  behaviour does not grow a registration-state callback by accident;
- transport: a Diameter stack is a long-lived peer connection with pending-request
  state. It fits `Kelix.Module` (supervised child + `safe_call/3`), but the
  non-blocking guarantee (§8.2) matters much more than for MyXQL: an HSS round trip
  under load is where a scenario instance would hang. **OPEN:** does the verdict
  facade stay synchronous with a timeout (simple, and what every script expects), or
  does a slow backend need an async verdict delivered as an event? Synchronous with a
  bounded timeout is the right first answer; FSL has no shape for the other today.

## 5. Proposed sequencing

1. `Kelix.Auth.Backend` behaviour + `Kelix.Auth.Digest` generic implementation;
   `Kelix.Mod.AuthDb` reduced to `fetch_credential/2` (pure refactor, no behaviour
   change, existing tests must stay green);
2. `authenticate/3` generalised (realm source, identity, method rule of §2.4), with
   `do_registration_auth/3` as a thin alias;
3. `[domain.auth].backend` + the `Kelix.Auth.authenticate(sip_ctx, req)` facade;
   reference scripts stop naming `Kelix.Mod.AuthDb`;
4. INVITE challenge in the reference call scripts + `identity_check` — **done**
   (2026-08-11): `apps/kelixip/scripts/direct-call-with-auth.exs`, `direct-call.exs`
   plus the three states in front of the call, and the `b2bua_challenge/3` verb
   §2.3 describes. Steps 1 and 3 are still open, so the script still names
   `Kelix.Mod.AuthDb`;
5. *(later)* a second backend, which is what proves the behaviour is right —
   nothing before it does.

Steps 1–2 are internal and safe. Step 3 is the one that changes what scripts look
like; it also feeds [integration-fail2ban.md](integration-fail2ban.md) §4, which
needs a reason code (`bad_password` vs. `unknown_user`) on the rejection verdict —
worth landing in step 1 while the verdict type is being touched anyway.
