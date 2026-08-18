# Authentication: what kelixip challenges, and what a digest proves

**Status: implemented.** This is the design of record for the authentication
kelixip performs — which realm, which identity, which code, which requests. What
is still open is marked **OPEN** in place.

Making the backend replaceable — MariaDB today, LDAP / HTTP / Diameter tomorrow —
is a separate thread, still unbuilt:
[evolution-auth-db.md](evolution-auth-db.md).

Reference: [`Kelix.Mod.AuthDb`](../kelixip/modules/auth_db.md) is the module that
holds the verdict, `Kelix.Auth` the challenge params, `SIP.Auth` the digest and
the nonce.

## 1. What the module answers

`Kelix.Mod.AuthDb` **decides; it never composes a response** — the script builds
the 401 or the 407 from the verdict
([DESIGN-KELIXIP.md](DESIGN-KELIXIP.md#6-authentication)). Its face:

| Function | Answers |
|---|---|
| `authenticate(req, realm, opts)` | `{:ok, identity}` · `{:requireauth, stale?}` · `{:reject, code, reason}` — the verdict for **any** request |
| `do_registration_auth(req, domain, opts)` | the same, for REGISTER, pinning the identity to `To` and flattening `{:ok, _}` to `:ok` |
| `challengeable?(req)` | whether this request may be challenged at all (§2.4) |
| `lookup_ha1(user, realm)`, `fetch_credential(user, realm, opts)` | the stored secret |
| `challenge_algorithm()` | what a challenge must advertise |

`{:ok, identity}` carries `%{user:, realm:}` — the subscriber the digest actually
proved, which a script can bill or log, and which §2.2 holds against what the
request claims.

Nothing in the digest itself is method-specific, and none of it needed changing
to authenticate a call:

- the digest — `SIP.Auth.expected_response_from_ha1(algorithm, ha1, method, auth)`
  takes the method from the request;
- credential reading — `auth_header/1` accepts **both** `Authorization` and
  `Proxy-Authorization`.

What is method-specific is everything *around* it: §2.

### 1.1 Where the nonce lives

The nonce is **not** this layer's: it is the SIP stack's stateless one, minted
and verified by recomputation, never stored. What it is and why is
[DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md#6-authentication); repeating it here
would be a second copy to keep true.

What belongs here is which module does what with it:

| Step | Where |
|---|---|
| mint the challenge params, nonce included | `Kelix.Auth.challenge_params(realm, opts)` — the application, so the params carry `qop`, `stale` and the backend's algorithm |
| put them in the right header | `b2bua_challenge/3` and `challenge_registration/3`, on the 401 or the 407 the script chose (§2.3) |
| validate the nonce | `Kelix.Mod.AuthDb`, through `SIP.Auth.Nonce.validate/3`: `:invalid` ⇒ challenge afresh, `:stale` ⇒ challenge with `stale=true`, `:ok` ⇒ check the credentials |
| refuse a replay | `Kelix.NonceCache.check_nc/2`, on the `nc` counter — the one thing statelessness cannot give, kept in ETS with a TTL equal to the nonce's max age |
| key the whole thing | `SIP.Auth.Secret`, regenerated at boot |

The **application mints and the application validates**: that is why
`challenge_invite/2` was dropped (§2.3). A dialog-layer verb minting the nonce
would put the two halves in different layers.

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

The check is `identity_check: :strict | :warn | :off`, set per module in
`[module.auth_db]` and overridable per call, and it holds the authenticated user
against the claim the request makes: `To` for a REGISTER, `From` for everything
else (`identity: :auto`). A mismatch is logged either way; `:strict` also rejects
with a 403.

**The default is `:warn`, not `:strict`**, and that is a deliberate hold rather
than a verdict: `:strict` breaks trunk scenarios where one account legitimately
asserts many `From`s. **OPEN:** a per-domain or per-subscriber "may assert" list
is the real answer, and is its own feature — `:warn` exists so the check can run
in observation mode until it lands.

### 2.3 401 or 407

- A **UAS** answers `401` + `WWW-Authenticate` (RFC 3261 §22.2).
- A **proxy** answers `407` + `Proxy-Authenticate` (§22.3).

kelixip is a B2BUA, i.e. a UAS, so `401` is formally right — but real UAs and their
provisioning very often expect `407` for calls, and many will not retry a `401` on
an INVITE. This is a deployment fact, not a spec question.

So the **module stays neutral** (`{:requireauth, stale}`) and the **script
composes** 401 or 407. The backend reads whichever header came back either way.

A dedicated `challenge_invite(realm, code \\ 407)` was tried and dropped
(2026-08-11): it makes the *dialog layer* mint the nonce, which loses `qop=auth`,
`stale` and the backend's algorithm. A call script challenges with

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
means `max_age` becomes a per-use parameter rather than a constant. What `max_age`
does when it expires — `:stale`, re-challenge, transparent replay — is
[DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md#6-authentication).

