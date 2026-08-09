# secman status — iOS & iPadOS app

A read-only view of the security posture that [secman](https://github.com/schmalle/secman)
publishes. Runs on iPhone and iPad, iOS/iPadOS 26 and newer.

The app **never talks to secman**. It talks to the secman *relay* — a small,
hardened Go server that sits in a DMZ and serves a snapshot secman pushed out to
it. There is no path from this app into the secman network, and no write path
into anything.

```
 secman (trusted network)          relay (DMZ)                 this app
 ┌──────────────────────┐        ┌──────────────┐          ┌─────────────┐
 │  publisher           │──push─▶│ snapshot     │◀──read───│  iPhone /   │
 │  (outbound only)     │  TLS   │ (in memory)  │   TLS    │  iPad       │
 └──────────────────────┘        └──────────────┘          └─────────────┘
        never accepts                never dials              never sees
        a connection                 secman                   secman
```

## What you see is what your secman roles allow

The relay enforces the same RBAC as secman itself. Each section of the snapshot
carries the roles the originating secman controller demands, and secman pushes
each user's live roles. A `VULN` user sees the import freshness; a `SECCHAMPION`
sees the KPIs; an `ADMIN` sees everything. Nothing is filtered on the device —
the app asks the relay which sections it may read and builds the UI from the
answer, so a role change in secman changes the app on the next refresh.

## Signing in

| Method | Who can use it | What the relay does |
|---|---|---|
| **Sign in with Apple** | everyone | Verifies the identity token against Apple's JWKS |
| **Sign in with Google** | everyone | Verifies the ID token against Google's JWKS |
| **Sign in with GitHub** | non-privileged accounts only | Runs the OAuth code flow itself; the app never holds a GitHub token |
| **Enrollment code** | non-privileged accounts only | Redeems a single-use code an admin issued |

**Administrator accounts must use Apple or Google.** GitHub and typed codes are
refused for any account holding a privileged role, and the rule is re-checked on
every session — promoting a user to ADMIN immediately invalidates a device that
was bound by a weaker method. The relay publishes the policy at
`GET /api/v1/providers`, so the app greys out what will not work instead of
letting the user discover it via a 403.

Proving who you are is not the same as being allowed in. An Apple account that
no secman administrator has linked to a secman user gets nothing.

## The device is a credential

On first run the app generates a P-256 key pair **inside the Secure Enclave**,
gated by Face ID / Touch ID. The private half never leaves the enclave and never
appears in a backup. Every session begins by signing a fresh server challenge
with it, in exchange for a 15-minute access token that is kept in memory only.

So: a stolen backup is worth nothing, a stolen token is worth minutes, and a
phone unlocked by somebody else still cannot reach the relay.

## Repository layout

```
Sources/SecmanRelayKit/    the whole security surface — enclave key, relay
                           protocol, the three sign-in flows. Dependency-free.
Tests/SecmanRelayKitTests/ the parts checkable without a device
App/SecmanApp/             SwiftUI app (one target, iPhone + iPad)
project.yml                XcodeGen spec; the .xcodeproj is generated
docs/                      architecture, security model, setup, API reference
```

## Building

```bash
brew install xcodegen
xcodegen generate
open SecmanApp.xcodeproj
```

Or run the library's tests without Xcode:

```bash
swift test
```

Before the first build, fill in the deployment values in
`App/SecmanApp/Resources/Info.plist` — the relay hostname, the Google client id,
and the ATS exception domain. [`docs/SETUP.md`](docs/SETUP.md) walks through it,
including what to configure on the relay side.

## No third-party dependencies

Everything is Apple's own frameworks: CryptoKit, Security, AuthenticationServices,
SwiftUI. There is no GoogleSignIn SDK — the Google flow is plain OAuth 2.0 with
PKCE over `ASWebAuthenticationSession`, about 120 lines, and not worth a vendor
runtime with its own networking and update cadence in a security product.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the pieces fit, and why the app cannot reach secman
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, the sign-in protocol in detail, and the security test matrix
- [`docs/SETUP.md`](docs/SETUP.md) — provisioning: Apple, Google, GitHub, the relay, and the app
- [`docs/API.md`](docs/API.md) — the relay endpoints this app uses

The relay itself is documented in the secman repository at `docs/RELAY.md`.

## Status

The Swift sources have not been compiled: they were authored in an environment
with no Swift toolchain and no Xcode. Treat the first `xcodegen generate &&
swift build` as part of review, not as a formality.
