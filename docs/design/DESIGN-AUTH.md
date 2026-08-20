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


---

## 3. The authentication block

**Status: implemented** (`Kelix.Mod.AuthDb.SBB.Authenticate`, tested by
`apps/kelix_modules/test/auth_sbb_test.exs`).

Everything above is the *verdict*. This is the **sequence** around it — challenge,
wait for the credentials, verify them, challenge again — packaged as a service
building block so that no script writes it twice.

### 3.1 What it replaces

`direct-call-with-auth.exs` gated its INVITE behind two states,
`authenticate_caller` and `wait_credentials`: forty lines whose useful half was
comments about SIP rules that had nothing to do with that call flow — 407 rather
than 401 (§2.3), `stale`, "answer a refusal and keep waiting", and the 32 s a
challenge is worth. They were already copied verbatim into the media variant, and
`uas_register.exs` holds the same loop under different state names. That is the
definition of a block: a sequence somebody got right, that everything else calls
rather than re-derives.

### 3.2 The face, and the call site

The block is published by the module that decides, following the pattern
[DESIGN-SBB.md](DESIGN-SBB.md#74-a-kelixip-module-publishes-its-blocks) sets out —
a kelixip module publishes functions for a decision and blocks for a sequence:

```
Kelix.Mod.AuthDb                    # authenticate/3, challenge_algorithm/0
Kelix.Mod.AuthDb.SBB                # the face: __using__ and authenticate/1
Kelix.Mod.AuthDb.SBB.Authenticate   # the FSM, @sbb_namespace :auth
```

```elixir
defmodule Kelix.DirectCallWithAuth do
  use SIP.Scenario
  use SBB.Call
  use Kelix.Mod.AuthDb

  uas(:invite)
  config(uses_modules: [:registrar, :auth_db])

  state authenticate_caller do
    AuthDb.SBB.authenticate()

    on_events do
      {:auth, :authenticated, %{user: user}} ->
        goto(place_call, "INVITE authenticated as #{user}")

      {:auth, :cancelled, _} ->
        scenario_success("caller cancelled the challenged call")

      {:auth, :caller_gone, %{reason: reason}} ->
        scenario_success("caller gave up: #{inspect(reason)}")

      {:auth, :timeout, _} ->
        scenario_success("no credentials came back")

      {:auth, :refused, %{attempts: n}} ->
        scenario_success("gave up on this sender after #{n} attempts")
    end
  end
```

**The verb is `authenticate/1`**, not `authenticate_caller/1`: the block
authenticates whoever sent the request it is given — the caller for an INVITE, the
holder of the AOR for a REGISTER (§2.2) — and naming it after one of the two would
have to be undone the day the registrar scripts use it. The specificity belongs in
the state name.

**It lives in `kelix_modules`, with the backend it needs.** The general rule is in
DESIGN-SBB; three facts made it concrete here, and they are why the rule was
written from this block rather than guessed at:

- **it takes two collaborators, not one.** The block does not only ask for a
  verdict, it composes a challenge, and the nonce is minted by
  `Kelix.Auth.challenge_params/2` — which lives in `apps/kelixip`, a third
  application. Injecting the authenticator alone into a library block would not
  have been enough;
- **the library consumer does not exist.** The one `elixipp` scenario that
  authenticates, `apps/elixip2/scenarios/uas_register.exs`, verifies a *single
  configured password* through `check_registration_auth/3` and
  `challenge_registration/3`. No subscriber table, no re-authentication cycle;
- **`kelix_modules` is already the app for both halves** — the reference scripts
  and the core-to-module tests live there because it is the only place both are
  present.

### 3.3 What it answers

Blocks return `{namespace, outcome, data}` — three elements, the last a map
([DESIGN-SBB.md](DESIGN-SBB.md#21-the-shape-of-a-return)):

| Outcome | Data | Meaning |
|---|---|---|
| `:authenticated` | `%{user, realm}` | The digest checked out and §2.2's identity check had its say |
| `:cancelled` | `%{}` | The caller CANCELled the challenged request |
| `:caller_gone` | `%{reason}` | The dialog ended while waiting for credentials |
| `:timeout` | `%{block}` | Nothing came back before the block's deadline |
| `:refused` | `%{code, reason, attempts}` | `max_attempts` rejected attempts were answered |

`args`: `:realm` (default `sip_ctx.domain`, §2.1), `:code` (default 407, §2.3),
`:max_attempts` (default 3).

Four things are worth stating, because none is obvious from the table.

**`:timeout` is not declared, and arrives anyway.** A bounded block gets it free
from `@sbb_timeout 32_000` — the `after` clause the two states carried, which was
never a property of a call flow but of how long a challenge is worth waiting for.

**A single rejection is not an outcome; a run of them is.** A 403 is answered and
the block **keeps waiting**: one request's verdict is not the end of the
conversation, and a client that fixes its password must be able to say so. Ending
the instance would leave the dialog matching the next INVITE of that Call-ID and
casting it to a dead process — the caller would then get no answer at all until
the dialog expires.

**The count is of 403s only.** Not the challenges — a first INVITE without
credentials always yields `{:requireauth, false}`, which is the protocol working.
Not `stale`. And **not the 500s**: a backend that cannot answer is our fault, and
counting it would turn a database outage into a simultaneous lockout of every
legitimate subscriber, the failure mode of every naive attempt counter.

**Running out is not a new behaviour, only an earlier one.** The block answers the
last attempt and returns, so the scenario ends and the caller meets silence on
whatever it sends next. That is already what the 32 s timer produced;
`max_attempts` reaches it in three exchanges instead of thirty seconds. Worth
writing down, because it is what someone will rediscover in a capture and mistake
for a regression. `max_attempts: :infinity` restores the earlier behaviour.

Brute-force *visibility* is deliberately not here: it is a core observer, for
every script and every backend
([integration-fail2ban.md](integration-fail2ban.md) §4). `:refused` bounds the
work one unauthenticated dialog can extract — a scanner fits dozens of attempts
into 32 s, each one a query against the subscriber table — and raises no alarm.

### 3.4 The verbs it answers with

The block answers 100, 407 and 403 on the leg the request arrived on, in a B2BUA
script *and* in one that is not a B2BUA at all — an MCU answering an INVITE has
the same challenge to issue. So it uses `reply_invite/3` rather than
`b2bua_reply/4`, which resolves its leg through machinery a plain UAS scenario
does not set up. That works for a reason worth recording:

> `SIP.Session.B2bua.leg_pid(sip_ctx, :inbound)` **is** `sip_ctx.dialogpid`.

The inbound leg of a B2BUA is the scenario's own dialog, so inside this block —
which runs before anything is forwarded — the two verbs put the same response on
the same wire.

Two things were added for it, and both stay in `:elixip2` even though the block
does not, because challenging an INVITE is SIP:

- **`challenge_invite/2` takes a second form.** It already existed, but only as a
  *realm* handed to `SIP.Dialog.challenge/4` for the dialog layer to mint a nonce
  from. That is not enough here: `stale` and the algorithm the stored secret was
  hashed with are the backend's to decide (§2.3, §2.5) and neither survives being
  re-derived one layer down. The verb now also takes the digest **params** the
  application composed, and sends them verbatim into the header the code calls
  for. One macro, two clauses on `do_challenge_invite/3`;
- **a dead dialog no longer kills the scenario.** `do_reply_invite/4` called
  `SIP.Dialog.reply/5` — a bare `GenServer.call` — so a caller vanishing between
  its INVITE and our 407 exited, the per-state `try` caught it, and ordinary
  traffic read as a crash. It now catches `:exit` and sets `lasterr` to
  `:dialogterminated`, the atom `SIP.Session.send_sip_request/3` already uses for
  the sending side. The block turns it into `{:auth, :caller_gone, …}`.

### 3.5 The verbs stay available

Nothing about the block removes anything. `authenticate/1` expands to
`sbb_fsm(Kelix.Mod.AuthDb.SBB.Authenticate, …)`, and the sequence inside it is
written with the same `reply_invite`, `challenge_invite` and `on_events` a script
can write itself. A scenario wanting a different policy — a hard 403 after three
attempts, a 401 instead of a 407, a challenge only for calls leaving the domain —
writes the states by hand and does not call the block.
`Kelix.Mod.AuthDb.authenticate/3` stays public and stays the contract.

The block is the default most scripts want, not a gate.

---

## 4. P-Asserted-Identity

**Status: implemented.** A proved identity that goes no further than a log entry
is half a feature: once the digest says who the caller is, the leg placed on their
behalf should say so (RFC 3325).

### 4.1 The defect this fixed

`SIP.Msg.Ops.prepare_forwarded_request/2` works from a **denylist**
(`@b2bua_dropped_fields`: Via, Route, Record-Route, Path, Contact, the two
authorization headers, the transaction id). Everything else crossed the leg
boundary verbatim — `P-Asserted-Identity` included.

So a caller could put `P-Asserted-Identity: <sip:boss@example.com>` in an INVITE
and kelixip relayed it onto the outbound leg **as if kelixip had asserted it**: a
claim from an untrusted peer laundered into an assertion by the one node whose
signature the header is supposed to carry, on a script with no authentication in
it at all. A test asserted that it crossed, under the heading "identity headers
pass through unchanged".

### 4.2 The rule

**`P-Asserted-Identity` is dropped on every forward**, with no exception and
nothing to configure, and `prepare_forwarded_request/2` re-adds ours from an
option:

```elixir
SIP.Msg.Ops.prepare_forwarded_request(req, asserted_identity: sip_ctx.asserted_identity)
```

The drop and the re-add are **in the same function**, and that is the guarantee:
the only PAI that can leave this node is one that function wrote. Nothing to
compare, nothing to trust at the call site.

The cost is that a deployment putting kelixip behind a trusted proxy — where RFC
3325 §5 would let an inbound assertion through — cannot say so. That is a
trust-domain policy needing configuration to be stated safely, and the safe
default is the one that does not launder. When a cascaded deployment needs it, it
arrives as `[domain] trusted_peers`, not as a hole in the denylist.

### 4.3 Where the assertion comes from

The verdict carries **no header** — it carries what builds one.
`authenticate/3` answers `{:ok, %{user: "alice", realm: "example.com"}}` and
composes no message (§1). One verb turns that into an identity, and it belongs to
the framework because composing a SIP URI is the message layer's job:

| Step | Who | What |
|---|---|---|
| verdict | `Kelix.Mod.AuthDb.authenticate/3` | `{:ok, %{user, realm}}` — no message touched |
| assertion | `assert_identity/1` (`SIP.Context`) | one `%SIP.Uri{}` → `sip_ctx.asserted_identity` |
| forward | `prepare_forwarded_request/2` | drops any inbound PAI, re-adds ours |

**The field answers two questions with one bit.** Nil means no authentication
happened, so nothing is asserted; set means the digest proved this identity. The
forward needs no separate flag saying whether a backend ran.

**It is a context field, not `appdata`**, because the forward reads it and the
forward is framework code. And **not the request**: a B2BUA hunt re-enters
`create_leg` with the *original* request for every target it tries, so an identity
written onto the stored request would survive the first target and vanish on the
second.

**The display name stays empty.** The verdict has none, and the only one available
is the `From`'s — what the caller *claims*. Copying it into a header meaning "this
was verified" would lend it a guarantee it does not have. If one is ever wanted it
comes from the subscriber table, through the verdict.

### 4.4 The two forward paths

| Call site | Carries |
|---|---|
| `create_leg` | the initial INVITE, and each target of a hunt |
| `relay_request` | in-dialog: re-INVITE, UPDATE, MESSAGE… |

The second matters as much as the first: a caller's identity does not change
mid-dialog, and a re-INVITE relayed without the header would make it flicker in
the middle of a call. Both go through one B2BUA helper, `prepare_forward/3`.

That is also where the residual risk sits: the guarantee says no *foreign* PAI can
leave, not that *ours* always does. A future call site that forgets the option
would silently drop the assertion, so `prepare_forward/3` warns when
`sip_ctx.asserted_identity` is set and the prepared request carries no PAI and the
caller asked for no privacy — the one hole this design leaves, made loud.

### 4.5 Privacy

RFC 3325 §7: a request carrying `Privacy: id` must not leave the trust domain with
a `P-Asserted-Identity`, and a B2BUA forwarding to an arbitrary registered contact
*is* leaving it. `prepare_forwarded_request/2` skips the re-add when the request
asks for it — one line, at the only place that writes the header. Asserting the
identity of a caller who explicitly asked to be anonymous is a privacy breach with
a specification saying so.
