# Architecture

## The shape of the system

```
      trusted network                    DMZ                        internet
 ┌──────────────────────────┐   ┌──────────────────────┐    ┌──────────────────┐
 │  secman                  │   │  secman-relay (Go)   │    │  this app        │
 │                          │   │                      │    │                  │
 │  RelayPublisher ─────────┼──▶│  ingest plane        │    │                  │
 │    every 60s, outbound   │   │   bearer + HMAC      │    │                  │
 │    TLS, no inbound port  │   │                      │    │                  │
 │                          │   │  snapshot (memory)   │◀───┤  mobile plane    │
 │  RelayPrincipalService ──┼──▶│  principals + roles  │    │   device key +   │
 │    users, roles,         │   │  device registry     │    │   15-min token   │
 │    linked identities     │   │   (0600 on disk)     │    │                  │
 └──────────────────────────┘   └──────────────────────┘    └──────────────────┘
        MariaDB, CrowdStrike,        no database                Secure Enclave
        the actual data              no secman credential       no secman URL
                                     no path back
```

Three properties fall out of that picture, and everything else in the app is
downstream of them.

**The relay cannot reach secman.** Not "is not allowed to" — cannot. It has no
secman URL, no secman credential, and no code path that dials inward. Compromise
of the DMZ box does not become a foothold in the trusted network.

**The app cannot reach secman either.** It only knows the relay. There is no
configuration in which pointing the app at secman would work.

**Nothing is writable.** No route on either plane mutates secman state.

## Why a push, and not a proxy

The obvious alternative — a reverse proxy in the DMZ that forwards mobile
requests to secman — was rejected. A proxy needs an inbound path into the
trusted network and a credential to authenticate with, which puts both inside
the DMZ. The blast radius of the proxy box is then "an authenticated session
against secman". Here it is "a copy of yesterday's dashboard numbers".

The cost is freshness: the app sees data as of the last push. The relay reports
the age of every snapshot and flags it stale past a threshold, so the trade is
visible to the user rather than hidden.

## Modules

### `Sources/SecmanRelayKit`

The whole security surface, as a library so it can be tested without a simulator
and reviewed without reading SwiftUI.

| File | Responsibility |
|---|---|
| `DeviceKeyStore.swift` | Secure Enclave P-256 key: create, load, sign, and the X9.63 → SPKI conversion the relay's parser requires |
| `RelayClient.swift` | Every HTTP call, the TLS policy, and the in-memory token |
| `RelaySession.swift` | The binding and session protocol end to end, plus the Keychain device record |
| `SignInProviders.swift` | Apple, Google (OAuth + PKCE, no SDK) and the relay-hosted GitHub flow |
| `RelayModels.swift` | Wire types; snapshot sections stay as opaque JSON |
| `SPKI.swift` | DER encoding for certificate pinning, and a SHA-256 usable without CryptoKit |
| `RelayError.swift` | One error type, with "can signing in again fix this?" as an explicit property |

### `App/SecmanApp`

SwiftUI, one target for iPhone and iPad. `AppModel` is the only state holder;
views read from it and never call the client directly.

## Two decisions worth explaining

### Snapshot sections are opaque JSON

The relay carries each section as raw bytes and re-serves them unparsed. The app
does the same: `RelaySnapshot.sections` is `[String: Data]`, decoded lazily by
whichever view needs it.

The result is that adding a field in secman, or a whole new section, cannot
break a screen the user is looking at. A new field in a known section is ignored
until the app learns about it; an unknown section is listed under its own name
and rendered as labelled rows. Neither the relay nor the app needs a release
when secman gains a widget.

### The UI is built from the server's answer

`GET /api/v1/meta` returns the sections this device may read. The sidebar is
that list — all of it, unfiltered. There is no client-side role check anywhere —
no `if roles.contains("ADMIN")` — because a second implementation of an
authorization rule is a second chance to get it wrong, and the client's copy is
the one an attacker controls.

Unfiltered includes section names this build has never seen. `RelaySection` maps
the six secman publishes today to a title, an icon and a purpose-built view;
`RelaySectionID` wraps whatever the server actually said, and anything without a
match renders generically from the opaque JSON. Dropping the unrecognised ones
would hide data the user is entitled to, and the resulting blank space is
indistinguishable from a permissions problem.

## Data flow of one refresh

```
AppModel.refresh()
 ├─ RelayAuthenticator.ensureSession()
 │    └─ if the token is expired: challenge → sign (Face ID) → token
 ├─ GET /api/v1/session   → identity: name, provider     → settings
 │                          (first refresh only — it does not change)
 ├─ GET /api/v1/meta      → freshness, which sections     → sidebar
 └─ GET /api/v1/status    → the sections themselves       → detail
      only when meta.generatedAt has moved since the copy in memory
```

Only the first request in a steady-state refresh is guaranteed to happen.
`/session` carries identity — a display name and how the device was bound —
which does not change while the app is running, so it is fetched once. `/meta`
is a few hundred bytes and is fetched every time, because both freshness and
entitlements move underneath the app: a snapshot ages, and a role edit in secman
takes effect on the very next request. `/status` is the only large response the
app ever downloads, and it is skipped entirely when `generatedAt` matches the
copy already in memory.

## Failure states, and why each is distinct

| Condition | What the user sees |
|---|---|
| No relay configured | setup screen |
| Relay unreachable | "could not be reached", previous data retained in memory |
| Not yet enrolled | sign-in screen |
| Enrolled, token expired | silent re-authentication (one Face ID prompt) |
| Device revoked, or principal removed | "not permitted" — signing in again is *not* offered, because it cannot help |
| Relay has no snapshot | "waiting for secman", the shell still renders |
| Snapshot older than the threshold | data shown, with an orange age banner |
| Relay speaks a newer schema | "update the app" — refuses to render a version it does not understand |

The distinction between "your session expired" (retry silently) and "you are not
permitted" (a human must change something in secman) is load-bearing: conflating
them produces an app that loops the sign-in sheet forever against a revocation.

## Platform requirements

iOS/iPadOS 26+, Swift 6 with complete concurrency checking, warnings as errors.
No third-party packages.
