# auth_db evolution — a replaceable authentication backend

**Status: discussion, nothing implemented.** Decisions marked **OPEN** are the
ones to settle before writing code.

MariaDB today, LDAP / HTTP / **Diameter** tomorrow, without touching a scenario.

The other half of this document's original subject — authenticating more than
REGISTER — is built, and is now [DESIGN-AUTH.md](DESIGN-AUTH.md): what kelixip
challenges, which realm and which identity it holds a caller to, and which code
it answers with. Everything below assumes those rules and changes only where the
verdict comes from.

## 1. The `Auth` behaviour

### 1.1 Which layer to abstract

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

### 1.2 Where the behaviour lives

In the **core** (`apps/kelixip`), not in `kelix_modules`. A module must be able to
declare it without depending on another module, and `Kelix.Auth` (the challenge
builder) is already core. `Kelix.Mod.AuthDb` becomes *an* implementation; a future
`Kelix.Mod.AuthDiameter` is another.

### 1.3 Selecting a backend

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

**Decided (2026-08-19): `auth_db` is single-instance and stays that way until
2.0.** Its facade holds no instance name — `authenticate/3` reads its
configuration from an app env that `child_spec/2` posts — so two `[module.…]`
blocks resolving to `Kelix.Mod.AuthDb` would silently overwrite each other. That
is a real gap against the supervisor's named-instance model, and it is not the
one to close first: one instance per domain is the "separation by domain" work,
which is a 2.0 subject. Until then, one `[module.auth_db]` per node, and the
per-domain binding above selects *which backend*, not which instance of one.

### 1.4 Compatibility

`do_registration_auth/3` stays, as `authenticate/3` with `identity_from: :to` and
the registration nonce lifetime. Existing scripts keep working unchanged.

## 2. Diameter, concretely

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

## 3. Proposed sequencing

1. `Kelix.Auth.Backend` behaviour + `Kelix.Auth.Digest` generic implementation;
   `Kelix.Mod.AuthDb` reduced to `fetch_credential/2` (pure refactor, no behaviour
   change, existing tests must stay green);
2. `authenticate/3` generalised — realm source, identity, the method rule, with
   `do_registration_auth/3` as a thin alias. **Done**, and described in
   [DESIGN-AUTH.md](DESIGN-AUTH.md);
3. `[domain.auth].backend` + the `Kelix.Auth.authenticate(sip_ctx, req)` facade;
   reference scripts stop naming `Kelix.Mod.AuthDb`;
4. INVITE challenge in the reference call scripts + `identity_check` — **done**
   (2026-08-11): `apps/kelixip/scripts/direct-call-with-auth.exs` and its media
   variant, and the `b2bua_challenge/3` verb [DESIGN-AUTH.md](DESIGN-AUTH.md)
   describes. Steps 1 and 3 are still open, so the scripts still name
   `Kelix.Mod.AuthDb`;
5. *(later)* a second backend, which is what proves the behaviour is right —
   nothing before it does.

Steps 1–2 are internal and safe. Step 3 is the one that changes what scripts look
like; it also feeds [integration-fail2ban.md](integration-fail2ban.md) §4, which
needs a reason code (`bad_password` vs. `unknown_user`) on the rejection verdict —
worth landing in step 1 while the verdict type is being touched anyway.

---

## 4. Authenticate SBB

**Status: design, nothing implemented.** The layer it is written against ships
([DESIGN-SBB.md](DESIGN-SBB.md)); this is the second block of the catalogue
[sbb_evolutions.md](sbb_evolutions.md) §3 lists, and the first one that is not
made of B2BUA parts.

### 4.1 What it replaces

`direct-call-with-auth.exs` gates its INVITE behind two states,
`authenticate_caller` and `wait_credentials`, forty lines of which the useful
half is comments explaining SIP rules that have nothing to do with this
particular script:

- 407 rather than 401, because a UA expects the server that routes its calls to
  challenge as a proxy;
- `stale` so the client replays without asking its user for a password again;
- a refused INVITE is answered and **waited on again**, never ended, because
  nothing monitors the app pid: an instance that ends leaves the dialog matching
  the next INVITE of that Call-ID and casting it to a dead process, and the
  client then gets no answer at all until the dialog expires;
- 32 s, because a UA replays a challenge within a second and what does not is a
  scanner or a wrong password, neither of which deserves a slot.

Every one of those is a rule about *authenticating a SIP request*, not about
this call flow. They are already copied into `direct-call-with-auth-and-media.exs`
verbatim, and `uas_register.exs` holds the same loop under different state names.
That is the definition of a block: a sequence somebody got right, that everything
else should call rather than re-derive.

### 4.2 The name and the call site

The block is published by the module that decides, following the pattern
[DESIGN-SBB.md](DESIGN-SBB.md#74-a-kelixip-module-publishes-its-blocks) sets out
— a kelixip module publishes functions for a decision and blocks for a sequence:

```
Kelix.Mod.AuthDb                    # authenticate/3, challenge_algorithm/0
Kelix.Mod.AuthDb.SBB                # the face: __using__ and authenticate/1
Kelix.Mod.AuthDb.SBB.Authenticate   # the FSM
```

with `@sbb_namespace :auth`, because `{:auth, :authenticated, …}` reads better
than the `{:authenticate, …}` the module name would give. In a script:

```elixir
defmodule Kelix.DirectCallWithAuth do
  use SIP.Scenario
  use SBB.Call
  use Kelix.Mod.AuthDb

  uas(:invite)
  config(uses_modules: [:registrar, :auth_db])

  ...

  state authenticate_caller do
    AuthDb.SBB.authenticate()

    on_events do
      {:auth, :authenticated, %{user: user}} ->
        goto(place_call, "INVITE authenticated as #{user}")

      {:auth, :cancelled, _} ->
        scenario_success("caller cancelled the challenged call")

      {:auth, :caller_gone, %{reason: reason}} ->
        scenario_success("caller gave up on the challenge: #{inspect(reason)}")

      {:auth, :timeout, _} ->
        scenario_success("no credentials came back")
    end
  end
```

**The verb is `authenticate/1`**, not `authenticate_caller/1`: the block
authenticates whoever sent the request it is given — the caller for an INVITE,
the holder of the AOR for a REGISTER — and naming it after one of the two would
have to be undone the day the registrar scripts use it. The specificity belongs
in the state name, where this script already puts it.

This is the first instance of that pattern, so it is the one that will be copied.
`Kelix.Mod.Registrar` has the same shape waiting for it — `targets/2` is the
decision, the `queue()` of [kelixip-b2bua.md](kelixip-b2bua.md) is the sequence —
and so does `Kelix.Mod.Mcu`, whose `admit()` is a sequence written out by hand in
`mcu.exs` today.

### 4.3 Why the module and not the library

[DESIGN-SBB.md](DESIGN-SBB.md#74-a-kelixip-module-publishes-its-blocks) gives the
rule — a block goes where the thing it sequences lives — and argues the general
case against keeping the block in `:elixip2` with an injected backend. Three
facts make it concrete here, and they are why the rule was written from this
block rather than guessed at:

- **it takes two collaborators, not one.** The block does not only ask for a
  verdict, it composes a challenge, and the nonce is minted by
  `Kelix.Auth.challenge_params/2` — which lives in `apps/kelixip`, a third
  application. Injecting the authenticator alone would not have been enough, and
  injecting both, or folding `challenge_params` into the backend's contract, is
  the packaging leaking that DESIGN-SBB describes;
- **the library consumer does not exist.** The one `elixipp` scenario that
  authenticates, `apps/elixip2/scenarios/uas_register.exs`, verifies a *single
  configured password* — "with no configured password any well-formed
  Authorization is accepted" — through `check_registration_auth/3` and
  `challenge_registration/3`, verbs that already exist. No subscriber table, no
  re-authentication cycle: nothing in `:elixip2` would have called this block;
- **`kelix_modules` is already the app for both halves.**
  [CLAUDE.md](../../CLAUDE.md) says the reference scripts and the core-to-module
  tests live there "since they are the only place both halves are present". A
  block wrapping a SIP sequence around a module's verdict is both halves.

What does **not** move up with the block: `challenge_invite/2`, the dead-dialog
protection of `do_reply_invite/4`, the `asserted_identity` field with its
`assert_identity/1` verb and the `P-Asserted-Identity` handling in
`prepare_forwarded_request/2` (§4.5, §4.6) all stay in `:elixip2`. Challenging an INVITE and writing an identity
header are SIP, and a scenario authenticating against something other than
auth_db needs them just as much.

**A well-formed script carries both declarations, and they are not the same
declaration.** The `use` and the `uses_modules` entry look redundant and are not:

| | Guarantees | Fails when |
|---|---|---|
| `use Kelix.Mod.AuthDb` | the **code** is there | no `.beam` in `module_dir` — when the script is compiled |
| `uses_modules: [:auth_db]` | a **configured instance** exists | no `[module.auth_db]` block — at preflight |

A script can have either without the other, in both directions. The `.beam`
installed with no config block: the `use` compiles and the first request dies
inside `authenticate/3`, which is precisely what `uses_modules` exists to catch.
And the reverse is the common case today — `direct-call.exs` declares
`uses_modules: [:registrar]` and calls `Kelix.Mod.Registrar.targets/2` with no
`use` at all, because the registrar publishes no block yet.

Deriving one from the other is not available either, and would not be even if the
two checks converged: `uses_modules` names an **instance**, not a module.
`Kelix.ModuleSupervisor.resolve_module/2` takes `Kelix.Mod.<Camelize(name)>` only
as a *default*, overridable per block with `module = "…"`, so two instances may
share one module and one module answers to several names. A `use` naming the
module cannot know which instance a script requires.

### 4.4 What it answers

Blocks return `{namespace, outcome, data}` — three elements, the last a map
([DESIGN-SBB.md](DESIGN-SBB.md#21-the-shape-of-a-return), invariant 3). Not
`{:auth, :authentified}` and not `{:auth, {:dialog_terminated, reason}}`: the
arity is fixed so a block can learn to report one more thing by adding a key,
where a nested tuple or a fourth element is a compile error in every scenario
matching the old shape.

```elixir
# in Kelix.Mod.AuthDb.SBB.Authenticate
@sbb_namespace :auth

@sbb_returns [
  authenticated:
    "the digest checked out and the identity check had its say — %{user, realm}",
  cancelled:
    "the caller gave up on the challenge with a CANCEL — %{}",
  caller_gone:
    "the dialog ended while we waited for credentials — %{reason}",
  refused:
    "too many rejected attempts; the block gave up on this sender — " <>
      "%{code, reason, attempts}. The last attempt has been answered"
]

@sbb_timeout 32_000
@default_max_attempts 3
```

Three notes on that list.

**`:timeout` is not in it, and arrives anyway.** A bounded block gets it free
(`@sbb_timeout`), and the host receives `{:auth, :timeout, %{block: …}}`. The
`after 32_000` clause of `wait_credentials` becomes the block's bound, which is
what it always was: not a property of this call flow, but of how long a
challenge is worth waiting for.

**`:authenticated` carries what a script decides on, not what goes on the wire.**
`%{user, realm}` is what a host bills, logs or routes with. The
`P-Asserted-Identity` built from the same verdict travels separately, in
`sip_ctx.asserted_identity` (§4.6), because it is read by the forward and not by
the scenario — and a scenario that never looks at it still gets it right.

**A single rejection is not an outcome; a run of them is.** A 403 answers and
keeps waiting — one request's verdict is not the end of the conversation, and a
client that fixes its password must be able to say so. That is unchanged.
`:refused` is what happens after `max_attempts:` of them, default 3.

Four things about that count, and none of them is obvious.

**It counts 403s, and nothing else.** Not the challenges: a first INVITE without
credentials always yields `{:requireauth, false}`, which is the protocol working,
not a failure. Not `stale`, which is a nonce being renewed. And **not the 500s**:
a backend that cannot answer is our fault, and counting it would turn a database
outage into a lockout of every legitimate subscriber at once — the failure mode
of every naive attempt counter.

**Running out is not a new behaviour, only an earlier one.** The block answers
the last attempt and returns, so the scenario ends and the caller gets silence on
whatever it sends next — because the dialog outlives the instance, which is the
whole reason §4.1's comment says never to end on a refused INVITE. That is
already what happens when the 32 s timer expires today; `max_attempts` reaches it
in three exchanges instead of in thirty seconds. Worth writing down, because it
is exactly what someone will rediscover in a capture and mistake for a new bug.

**The count lives in the block's sandbox**, so it counts the attempts of *one
entry* into the block, not of the call. A scenario looping back with `goto` gets
a fresh count each time — `sbb_fsm(…, resume: true)` is what keeps one, and a
script that loops without it has effectively no bound.

**Why bound it at all**, now that the obvious reason turns out to be wrong: it is
*not* for [integration-fail2ban.md](integration-fail2ban.md), whose §4 weighs the
three possible emission points and picks the core observer — "in the scenario" is
listed there as the worst option, because every script author would have to
remember to log and forgetting is silent. Brute-force *visibility* is not this
block's job and never will be.

What is left is narrower and real: a scanner can fit dozens of attempts into the
32 s window, each one a query against the subscriber table, and the time bound
does not bound that. Three attempts bounds the work a single unauthenticated
dialog can extract. `max_attempts: :infinity` restores exactly today's
behaviour for a script that wants it.

### 4.5 Replying without `b2bua_reply`

The block must answer 100, 407 and 403 on the leg the request came in on, in a
B2BUA script *and* in one that is not a B2BUA at all — an MCU answering an
INVITE has the same challenge to issue.

`b2bua_reply/4` cannot be that verb: it resolves the leg through
`Process.get(:scenario_event_leg)`, machinery a plain UAS scenario does not set
up. The replacement is `reply_invite/3`, and it works for a reason worth writing
down rather than assuming:

> `SIP.Session.B2bua.leg_pid(sip_ctx, :inbound)` **is** `sip_ctx.dialogpid`.

The inbound leg of a B2BUA is the scenario's own dialog. `reply_invite/3` replies
to the stored request on `sip_ctx.dialogpid`, so inside this block — which runs
before anything is forwarded, when the inbound leg is the only leg — the two
verbs put the same response on the same wire. `reply_invite` is exported by
`SIP.Session.CallUAC.__using__`, which `use SIP.Scenario` pulls into every
scenario and every block, so nothing has to be added for a block to use it.

Two things do have to be added.

**A challenge verb that is not B2BUA-shaped.** `b2bua_challenge/3` is the only
way to compose a challenge today, and it is `do_local_reply` plus
`SIP.Msg.Ops.challenge_header/1`. The same three lines belong on the UAS side:
**`challenge_invite(params, code \\ 407)` in `SIP.Session.Invite`**, next to
`reply_invite`, backed by the same `SIP.Msg.Ops.challenge_header/1`. It stays in
`:elixip2` even though the block that calls it does not — challenging an INVITE
is SIP, and a scenario that authenticates against something other than auth_db
needs the verb just as much. `b2bua_challenge/3` stays as it is: scripts use it,
and it is the right verb when a challenge has to go out on a named leg.

**A dead dialog must not kill the block, and the fix goes in the framework.**
`b2bua_reply` wraps its call in `call_leg/1` — four lines, `catch :exit, _ ->
:leg_dead` — and turns a dead leg into `{:b2bua, :leg_dead, …}`.
`do_reply_invite/4` calls `SIP.Dialog.reply/5`, a bare `GenServer.call`, straight
through. A caller that vanishes between its INVITE and our 407 is ordinary
traffic, and it must produce `{:auth, :caller_gone, %{reason: …}}`, not an `:exit`
caught by the per-state wrapper and turned into a scenario failure.

So `do_reply_invite/4` catches `:exit` itself and sets `lasterr`, rather than the
block wrapping its own replies: every UAS scenario has the same exposure, and
none of them should have to know about it. The block then reads `lasterr` like it
reads any other outcome.

**The atom is `:dialogterminated`**, not a new one. `SIP.Session.send_sip_request/3`
already catches exactly this and sets exactly that — `catch :exit, _reason ->
SIP.Context.set(sip_ctx, :lasterr, :dialogterminated)` — for the sending side.
Replying is the same event on the other half of the transaction, and
`reply_lasterr/1` passes any non-`:ok` term through unchanged, so nothing else
has to move. `:leg_dead` stays B2BUA vocabulary, for a *leg*; a scenario with one
dialog has no legs.

**The gap is wider than this one function**, and saying so is not the same as
widening the work: there is no `catch` anywhere in `SIPSessionInvite.ex`, so
`do_reply_invite_with_sdp/3`, `do_reply_request/4` and the in-dialog senders have
the same exposure. Fixing them is a sweep of its own with its own tests, and it
is not owed to this block — `do_reply_invite/4` is what the authentication
sequence calls, and it is what step 2 covers.

### 4.6 P-Asserted-Identity

A proved identity that goes no further than a log entry is half a feature. Once
the digest says who the caller is, the leg we place on their behalf should say so
(RFC 3325), so that what is downstream can bill, route or display it without
re-authenticating anybody.

#### The defect this fixes, which is not the block's

`SIP.Msg.Ops.prepare_forwarded_request/2` works from a **denylist**,
`@b2bua_dropped_fields`: Via, Route, Record-Route, Path, Contact, the two
authorization headers, the transaction id. Everything else crosses the leg
boundary verbatim — `P-Asserted-Identity` included.

So a caller can put `P-Asserted-Identity: <sip:boss@example.com>` in an INVITE
today, and kelixip relays it onto the outbound leg **as if kelixip had asserted
it**. That is a claim from an untrusted peer being laundered into an assertion by
the one node whose signature the header is supposed to carry, and it happens on
`direct-call.exs` — a script with no authentication anywhere in it. It is worth
saying plainly because it changes what this section is: not a feature of the
block, but a fix the block happens to need.

Two consequences follow from the same denylist. Anything we *do* assert will
cross without touching the B2BUA — nothing has to be added to make our header
travel. And nothing stops a peer's header from crossing either, so the two have
to be told apart by construction rather than by inspection.

#### The rule: drop always, re-add from the context

**`P-Asserted-Identity` joins `@b2bua_dropped_fields`.** Every inbound PAI dies
at the forward, with no exception and nothing to configure. `prepare_forwarded_request/2`
then re-adds ours from an option:

```elixir
SIP.Msg.Ops.prepare_forwarded_request(req, asserted_identity: sip_ctx.asserted_identity)
```

The drop and the re-add are **in the same function**, and that is the whole
guarantee: the only PAI that can leave this node is one this function wrote. There
is nothing to compare, nothing to trust and nothing to inspect at the call site,
because no other header of that name survives long enough to be forwarded.

The cost is that a deployment putting kelixip behind a trusted proxy — where RFC
3325 §5 would let an inbound assertion through — cannot express that today. That
is a trust-domain policy, it needs configuration to be stated safely, and the
safe default is the one that does not launder. Recorded here rather than guessed
at: when a cascaded deployment needs it, it arrives as `[domain] trusted_peers`,
not as a hole in the denylist.

#### Where the assertion comes from

The verdict carries **no header** — it carries what is needed to build one.
`Kelix.Mod.AuthDb.authenticate/3` answers

```elixir
{:ok, %{user: "alice", realm: "example.com"}}
```

and keeps its contract untouched: it decides, it composes no message (§11.1).
Turning that into an identity is one verb, and the verb belongs to the framework
because composing a SIP URI is the message layer's job — the rule
[CLAUDE.md](../../CLAUDE.md) states, and the reason the REGISTER lifetime rule
now lives in exactly one place:

```elixir
# in the block, on {:ok, identity}
assert_identity(identity)
```

which stores `%SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"}`
in a new context field, `sip_ctx.asserted_identity`. The full chain:

| Step | Who | What |
|---|---|---|
| verdict | `Kelix.Mod.AuthDb.authenticate/3` | `{:ok, %{user, realm}}` — no message touched |
| assertion | `assert_identity/1`, a scenario verb | one `%SIP.Uri{}` → `sip_ctx.asserted_identity` |
| forward | `prepare_forwarded_request/2` | drops any inbound PAI, re-adds ours |

**The field answers two questions with one bit.** Nil means no authentication
happened, so no PAI goes out; set means the digest proved this identity, and it
is the one to assert. The forward needs nothing else — no flag saying whether
auth_db ran, no second channel.

**It is a context field and not `appdata`**, because the forward reads it and the
forward is framework code: a framework layer reading an application key would be
an implicit contract between two layers. And **not the request**, which is the
part that is easy to get wrong: `SIPSessionB2bua.ex:1129` re-enters `create_leg`
with `hunt.orig_req` for **every target of a hunt**, so `prepare_forwarded_request/2`
runs again on the original request each time. A PAI written onto the stored
request would survive the first target and vanish on the second.

**`assert_identity/1` is a verb, not code inside the block**, so a script that
authenticates without the block — the freedom §4.7 keeps — can assert too.

**The display name stays empty.** We assert `<sip:alice@example.com>` and no
more. The verdict has no display name, and the only one available is the `From`'s
— what the caller *claims*. Copying it into a header whose meaning is "this was
verified" would lend it a guarantee it does not have. RFC 3325 makes the
display-name optional; if one is ever wanted it comes from the subscriber table,
through the verdict, never from the message.

#### The two forward paths, and the one that would be forgotten

| Call site | Today | What it carries |
|---|---|---|
| `create_leg` (`SIPSessionB2bua.ex:1204`) | passes `opts` already | the initial INVITE, and each target of a hunt |
| `relay_request` (`:1541`) | called with **no opts** | in-dialog: re-INVITE, UPDATE, MESSAGE… |

The second matters as much as the first: a caller's identity does not change
mid-dialog, and a re-INVITE relayed without the header would make it flicker in
the middle of a call. Both go through one B2BUA helper — `forward_opts(sip_ctx)`
— so that a third call site added later copies the right thing.

That is also where the residual risk sits, and it is worth naming: the guarantee
above says no *foreign* PAI can leave, not that *ours* always does. A site that
forgets the option silently drops the assertion. So the same function warns when
`sip_ctx.asserted_identity` is set and the prepared request carries no PAI — the
one hole this design leaves, made loud instead of silent.

#### Privacy

RFC 3325 §7: a request carrying `Privacy: id` must not leave the trust domain
with a `P-Asserted-Identity`, and a B2BUA forwarding to an arbitrary registered
contact *is* leaving it. `prepare_forwarded_request/2` therefore skips the re-add
when the request asks for it. Asserting the identity of a caller who explicitly
asked to be anonymous is a privacy breach with a specification saying so, and it
is one line at the only place that writes the header.

#### What closes it

Three tests, and the first one is the regression that exists today:

1. an INVITE arriving with `P-Asserted-Identity` is forwarded **without** it,
   with nothing authenticated — the laundering above;
2. an authenticated call carries `P-Asserted-Identity: <sip:alice@example.com>`
   on the initial INVITE, on the **second target of a serial hunt**, and on a
   relayed re-INVITE;
3. an authenticated call whose INVITE carries `Privacy: id` forwards no PAI at
   all.

### 4.7 The macros stay

Nothing about the block removes a verb. `authenticate/1` expands to
`sbb_fsm(Kelix.Mod.AuthDb.SBB.Authenticate, …)`, and the sequence inside it is written
with the same `reply_invite`, `challenge_invite` and `on_events` a script can
write itself. `Kelix.Mod.AuthDb.authenticate/3` stays public and stays the
contract: a script that does not `use` the block calls it exactly as the
reference scripts do today. A scenario that
wants a different policy — three attempts then a hard 403, a 401 instead of a
407, a challenge only for calls leaving the domain — writes the two states as
they are written today and does not call the block. That is the same freedom
`SBB.Call` leaves: `direct-call.exs` uses `call/1`, and a script that needs to do
something between the 180 and the 200 still can.

The block is the default that most scripts want, not a gate.

### 4.8 What else has to change

- `docs/kelixip/modules/auth_db.md` — the module doc describes what a script does
  with each verdict. Once the block exists, the paragraph that spells out
  challenge-then-wait becomes a reference to it, with the verdicts kept: they are
  still the module's contract, and still what a script that does not use the
  block has to handle;
- `apps/kelixip/scripts/direct-call-with-auth.exs` and
  `direct-call-with-auth-and-media.exs` — two states each become one state and an
  `on_events`, in the shape of §4.2. The comments they lose are the ones that
  move into the block; the ones that stay are the ones about *this* script;
- the `authenticate_caller` / `wait_credentials` tests move with the sequence —
  from the two scripts to the block, where one suite covers both.

### 4.9 Sequencing

1. `P-Asserted-Identity` in `@b2bua_dropped_fields`, the `asserted_identity:`
   option on `prepare_forwarded_request/2` with the `Privacy` rule, the
   `sip_ctx.asserted_identity` field and the `assert_identity/1` verb, and the
   three tests of §4.6. This is a fix on its own — test 1 fails today — and
   nothing in it depends on the block;
2. `challenge_invite/2` beside `reply_invite/3`, and the dead-dialog protection
   in `do_reply_invite/4`;
3. `Kelix.Mod.AuthDb.SBB` + `.SBB.Authenticate` in `apps/kelix_modules`, naming
   `Kelix.Mod.AuthDb` and `Kelix.Auth` directly, plus the load-path test §4.3
   asks for;
4. the two reference scripts and the module doc;
5. *(independent)* the fail2ban observer of
   [integration-fail2ban.md](integration-fail2ban.md) §4, which watches finals in
   the core and owes nothing to this block — listed here only so the two are not
   confused for each other.

Steps 1 and 2 are additive and safe, and they stay in `:elixip2`: a challenge
verb and a reply that survives a dead dialog are SIP, and every UAS scenario has
the same need whether or not it ever sees a subscriber table. Only the block
itself moves up to `kelix_modules`, which is the whole of §4.3.
