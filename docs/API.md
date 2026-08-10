# Relay API reference (mobile plane)

Every endpoint this app uses. The authoritative implementation is
`src/relay/internal/api/api.go` in the secman repository; this document is the
client's view of it.

Base URL: the relay, over HTTPS. All bodies are JSON. Unknown fields in a
request are **rejected**, not ignored — a field the client thought it was
sending and the server silently dropped is how contract drift becomes invisible.

## Error shape

```json
{ "error": "not permitted for this account", "requestId": "a1b2c3d4" }
```

| Status | Meaning | Client behaviour |
|---|---|---|
| 400 | malformed request | bug; surface it |
| 401 | no or expired access token | re-authenticate silently |
| 403 | not permitted | **do not retry** — a human must change something in secman |
| 404 / 405 | no such route or method | bug |
| 429 | rate limited | honour `Retry-After` |
| 503 | on a read: no snapshot yet. Elsewhere: the relay is busy or its device registry is full | waiting state on a read; a plain error otherwise |

401 and 403 mean genuinely different things and the app treats them
differently. Conflating them produces a sign-in sheet that loops forever against
a revoked device.

503 is likewise overloaded on the relay side and must be read per route. On
`/meta` and `/status` it means "secman has not pushed yet", which is a normal
state with a friendly screen. On `/enroll` it means the device registry is full,
and on the login routes it means the relay cannot issue a nonce right now —
neither of which has anything to do with secman. `RelayClient` decides which
reading applies from the route, not from the status code alone.

## What the app signs

Two responses carry a `signingInput` / `bindingInput` field. They are a
convenience, **not** an instruction: the app reconstructs the same string from
`RelayProtocol` and refuses the operation if the two disagree. A client that
signs whatever the server sends has handed out a signing oracle for the one key
that identifies the device. See `Sources/SecmanRelayKit/RelayProtocol.swift`.

| Purpose | Bytes signed |
|---|---|
| Per-session authentication | `secman-relay-device-auth-v1\|<deviceId>\|<nonce>` |
| Device binding | `secman-relay-device-bind-v1\|<nonce>\|<sha256 hex of SPKI DER>` |

The two prefixes are domain separation: a signature made for a binding must
never be replayable as a session authentication. For GitHub the `<nonce>` is the
*ticket*, because the state travels through a browser and must not double as the
challenge.

---

## Discovery

### `GET /api/v1/providers`

Unauthenticated. What this relay supports and the rule it enforces.

```json
{
  "providers": ["apple", "google"],
  "enrollmentCodes": true,
  "privilegedRoles": ["ADMIN"],
  "strongProviders": ["apple", "google"]
}
```

Publishing the policy is not a leak — it is the same rule the relay will enforce
anyway — and it lets the app grey out a button instead of letting the user
discover the restriction through a 403.

---

## Binding a device

### `POST /api/v1/auth/nonce`

```json
{ "publicKey": "<base64 SPKI DER, ECDSA P-256>" }
```

```json
{
  "nonce": "9f8e…",
  "nonceHash": "b1c2…",
  "expiresAt": "2026-08-09T12:02:00Z",
  "bindingInput": "secman-relay-device-bind-v1|9f8e…|<sha256 of the key>",
  "algorithm": "ECDSA-P256-SHA256-ASN1"
}
```

Single use, and bound to the public key that requested it. `nonceHash` is what
Sign in with Apple wants; `nonce` is what Google wants. Both are returned so the
client does not re-derive the convention and get it subtly wrong.

### `POST /api/v1/auth/oidc`

Apple and Google.

```json
{
  "provider": "apple",
  "idToken": "<the identity token>",
  "nonce": "<the raw nonce>",
  "publicKey": "<same key as the nonce request>",
  "signature": "<base64 ASN.1 ECDSA over bindingInput>",
  "deviceName": "Markus iPhone"
}
```

→ `201` with the binding:

```json
{
  "deviceId": "dev_2f1c…",
  "subject": "markus",
  "displayName": "markus",
  "roles": ["ADMIN"],
  "scopes": ["status:*"],
  "boundVia": "identity",
  "provider": "apple"
}
```

`403` when: the nonce is spent or was issued for another key; the binding
signature does not verify; the ID token fails any check; the identity is not
mapped to a secman user; or the account is privileged and the provider is not
strong enough.

### `POST /api/v1/auth/github/start` → `GET .../callback` → `POST .../complete`

1. `start` with `{publicKey, deviceName}` returns `{authorizationUrl, state}`.
2. The app opens `authorizationUrl` in `ASWebAuthenticationSession`.
3. GitHub calls the relay's `callback`; the relay exchanges the code
   server-side and redirects to `secman-relay://auth/github?ticket=…`.
4. `complete` with `{ticket, publicKey, signature, deviceName}`, where the
   signature is over `secman-relay-device-bind-v1|<ticket>|<key fingerprint>`.

The app never sees a GitHub token. On failure the relay redirects with
`?error=<reason>` instead of a ticket.

### `POST /api/v1/enroll`

```json
{ "enrollmentCode": "7K2QX-3MNPB-…", "publicKey": "…", "deviceName": "…" }
```

Single use. Refused for any account holding a privileged role.

---

## Per-session authentication

### `POST /api/v1/auth/challenge`

```json
{ "deviceId": "dev_2f1c…" }
```

```json
{
  "nonce": "3a4b…",
  "expiresAt": "2026-08-09T12:04:00Z",
  "signingInput": "secman-relay-device-auth-v1|dev_2f1c…|3a4b…",
  "algorithm": "ECDSA-P256-SHA256-ASN1"
}
```

### `POST /api/v1/auth/token`

```json
{ "deviceId": "dev_2f1c…", "nonce": "3a4b…", "signature": "<base64 ASN.1 ECDSA>" }
```

```json
{
  "accessToken": "smrt1.…",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "subject": "markus",
  "roles": ["ADMIN"],
  "scopes": ["status:*"]
}
```

The nonce is consumed **before** the signature is checked, so a wrong signature
costs a fresh round trip and cannot be brute-forced against one challenge.

---

## Reads

All require `Authorization: Bearer <accessToken>`.

### `GET /api/v1/meta`

Freshness and entitlements, without the payload. The app polls this on every
refresh and only fetches `/status` when `generatedAt` has moved, so a phone that
wakes up between secman pushes downloads a few hundred bytes rather than the
whole snapshot.

```json
{
  "instanceId": "secman-prod",
  "schemaVersion": 2,
  "generatedAt": "2026-08-09T12:00:00Z",
  "receivedAt": "2026-08-09T12:00:01Z",
  "ageSeconds": 42,
  "stale": false,
  "maxAgeSeconds": 900,
  "sections": ["kpis", "imports"],
  "deviceId": "dev_2f1c…",
  "subject": "markus",
  "roles": ["ADMIN"],
  "scopes": ["status:*"]
}
```

`maxAgeSeconds` is the relay's own staleness threshold, so the app's "no update
in the last 15 minutes" banner quotes the deployment's number instead of a
constant compiled into the client.

### `GET /api/v1/session`

Who this device is and what it may read. The app builds its navigation from
`sections`.

```json
{
  "deviceId": "dev_2f1c…",
  "subject": "markus",
  "roles": ["ADMIN"],
  "scopes": ["status:*"],
  "boundVia": "identity",
  "provider": "apple",
  "sections": ["exceptions", "imports", "kpis", "top-products", "top-servers", "totals"]
}
```

### `GET /api/v1/status`

The snapshot, already filtered to what this device may read.

```json
{
  "instanceId": "secman-prod",
  "schemaVersion": 2,
  "generatedAt": "2026-08-09T11:59:30Z",
  "ageSeconds": 42,
  "stale": false,
  "roles": ["ADMIN"],
  "sections": {
    "totals": { "assets": 12043, "vulnerabilities": 88211, "users": 64 },
    "kpis": { "awsCleanServers": { "available": true, "percentage": 92.4, … } }
  }
}
```

`stale: true` still carries data. The relay serves the last snapshot it has with
its age, because on an incident call "42 minutes old" beats an empty screen —
and, unlike unlabelled stale data, cannot be mistaken for "all clear right now".

A `schemaVersion` this build does not know is refused outright rather than
half-rendered.

### `GET /api/v1/status/{section}`

One section.

```json
{
  "instanceId": "secman-prod",
  "generatedAt": "2026-08-09T11:59:30Z",
  "ageSeconds": 42,
  "stale": false,
  "section": "kpis",
  "data": { "awsCleanServers": { … } }
}
```

`403` when the section is out of role, out of scope, **or does not exist** — all
three answer identically, so the authorization boundary cannot be used to
enumerate what the relay holds.

---

## Sections and the roles that gate them

Mirrors the `@Secured` annotation on the secman controller each one comes from.

| Section | Roles | Contents |
|---|---|---|
| `totals` | ADMIN | asset, vulnerability and user counts |
| `kpis` | ADMIN, SECCHAMPION | AWS clean-server and EDR coverage |
| `exceptions` | ADMIN, SECCHAMPION | exception requests awaiting review |
| `imports` | ADMIN, VULN | CrowdStrike import freshness |
| `top-products` | ADMIN | products with the most vulnerabilities |
| `top-servers` | ADMIN | servers with the most vulnerabilities |

Section bodies are opaque to the relay and re-served byte for byte, so secman
can add a field without a relay or app release. The app decodes each section
lazily for the same reason.

---

## Not in this API

There is no write route, no route that reaches secman, and no route that returns
a vulnerability record, an asset row, or a user list. If you are looking for one,
the answer is the secman web UI — this app is a read-only status view by design.
