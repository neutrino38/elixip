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
