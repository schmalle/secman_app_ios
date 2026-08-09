# Security model

This is a security product, so the interesting question is not "is it
encrypted" but "what does an attacker get for each thing they compromise".

## 1. What the app can do at all

Nothing, in the write direction. There is no endpoint on the relay that mutates
secman state, because there is no connection from the relay to secman: secman
dials out, pushes, and hangs up. The strongest possible outcome of a fully
compromised phone, a fully compromised relay, and a fully compromised app store
build acting together is **disclosure of dashboard-level aggregates** — counts,
percentages and two "top 10" name lists.

That bound is architectural, not a matter of careful coding, and it is the
single most important property of the design.

## 2. Credentials, and what each is worth

| Credential | Lives | Lifetime | Worth if stolen |
|---|---|---|---|
| Secure Enclave P-256 key | enclave, biometry-gated | until re-enrollment | **cannot be stolen** — non-exportable, absent from backups |
| Relay access token | app memory | 15 minutes | read access for the remainder, at the caller's own role level |
| Device record (id, subject) | Keychain, `ThisDeviceOnly` | until sign-out | nothing on its own; authenticates nobody without the key |
| Apple / Google ID token | transient, never stored | ~10 minutes | nothing without the matching device key and the relay's single-use nonce |
| GitHub token | **never on the device** | — | — |
| Enrollment code | shown once, never stored | ≤ 24h, single use | one device binding for a non-privileged account |

Note the absence of a refresh token, an API key, or any long-lived bearer
secret. The long-lived credential is hardware, and the short-lived one expires
faster than most attacks can be staged.

## 3. Sign-in, step by step

### Apple / Google

```
app                          relay                        Apple/Google
 │
 ├─ generate enclave key (once)
 │
 ├─ POST /auth/nonce {publicKey} ──▶
 │                              stores nonce ↔ SHA-256(publicKey)
 │   ◀── {nonce, nonceHash, bindingInput}
 │
 ├─ authenticate, passing nonceHash ─────────────────────▶
 │   ◀────────────────────────────────── id_token {nonce: nonceHash, sub}
 │
 ├─ sign bindingInput with the enclave key   (Face ID)
 │
 ├─ POST /auth/oidc {provider, idToken, nonce, publicKey, signature} ──▶
 │                              1. redeem nonce (single use)
 │                              2. nonce was issued for THIS public key?
 │                              3. signature verifies under that key?
 │                              4. id_token: RS256, iss, aud, exp, nonce
 │                              5. is this `sub` mapped to a secman user?
 │                              6. does that user's role allow this provider?
 │   ◀── {deviceId, subject, roles, scopes}
```

Each numbered check kills a specific attack:

1. **Replay of the whole binding.** The nonce is consumed on first use.
2. **A captured ID token binding somebody else's key.** The nonce was issued
   against one public key; a different one is refused. Without this, anyone who
   observed an ID token could register their own device against your account.
3. **Registering a key you do not hold.** The binding signature proves
   possession of the private half. Without it, an attacker could register a key
   *they* control — or, worse, someone else's public key, quietly attaching
   their session to another person's device record.
4. **Forged or foreign tokens.** RS256 is pinned (no `alg: none`, no algorithm
   confusion), the issuer must match, and `aud` must be this app's client id —
   an ID token minted for a *different* app is a perfectly valid token, and
   checking `aud` is the only thing that stops it being accepted here.
5. **"I have a Google account, therefore I am authorized."** Identity is not
   authorization. Only a principal record that secman pushed grants anything.
6. **A privileged account entering through a weak door.** See §4.

### GitHub

GitHub issues no ID token, so the relay is the OAuth client and holds the
secret. `ASWebAuthenticationSession` opens the relay's start URL; the browser
ends on the relay's callback; the relay exchanges the code server-side, reads
the account's **numeric id** (never the login — a released login can be claimed
by somebody else), and hands the app a single-use *binding ticket* on a custom
URL scheme.

A custom scheme can be claimed by another app, so the ticket is deliberately
worthless alone: it is bound to the device key that started the flow and must be
presented with a signature from that key.

### Every session afterwards

```
app                                   relay
 ├─ POST /auth/challenge {deviceId} ──▶
 │   ◀── {nonce, signingInput}
 ├─ sign signingInput   (Face ID)
 ├─ POST /auth/token {deviceId, nonce, signature} ──▶
 │   ◀── {accessToken, expiresIn: 900, roles, scopes}
```

The identity provider is not consulted again. That keeps the app working when
Apple is having a bad morning, and it means the durable credential is a key in
hardware rather than a token on disk.

## 4. Administrators must use a strong provider

A principal holding a privileged role — `ADMIN` by default — can only be bound
through Apple or Google. Not GitHub, not an enrollment code.

The rule is enforced in three places, and the third is the one that matters:

1. **secman** refuses to link a GitHub account to an ADMIN, so the admin is told
   at link time rather than at a 403.
2. **The relay** refuses the binding.
3. **The relay re-checks on every token issue.** A user promoted to ADMIN
   *tomorrow* immediately loses a device that was bound via GitHub *today*.
   Checking only at binding would leave a privileged account sitting behind a
   credential the policy no longer permits.

The relay also refuses to start if a privileged role is configured but no strong
provider is enabled — otherwise an admin could never sign in, and the failure
would look like an app bug.

## 5. Authorization mirrors secman exactly

Every snapshot section carries the roles the secman controller it came from
demands (`DashboardController`'s `@Secured("ADMIN","SECCHAMPION")` becomes
`requiredRoles: [ADMIN, SECCHAMPION]`), and secman pushes each user's live
roles. A read passes only if:

- the principal holds one of the section's required roles, **and**
- the device's scope names the section.

A scope can narrow, never widen. Roles are resolved from the principal on every
request and never cached on the device or baked into a token, so a demotion in
secman takes effect on the very next request — no logout, no token to revoke.

An out-of-scope section, an out-of-role section and a nonexistent section all
answer identically (403). The authorization boundary is not a map of what the
relay holds.

## 6. Transport

- HTTPS only. A plaintext relay URL is refused at configuration time, not at
  request time, so it cannot slip through in a debug build.
- App Transport Security requires TLS 1.3 for the relay's domain, with no
  arbitrary-loads exception anywhere.
- Optional SPKI pinning, **off by default**. This is a deliberate trade: a
  Let's Encrypt certificate rotates roughly every 60 days, and a stale pin
  bricks every installed copy until an App Store release ships. Turn it on only
  with at least two pins (current plus a spare) and a rotation runbook. When it
  is on, it is an *addition* to the platform's chain validation, never a
  replacement.
- No cookies, no credential store, no redirects followed. The relay never
  redirects an API call, so following one could only help an attacker.

## 7. On-device data

- **Snapshot data is never persisted.** It lives in memory for the lifetime of
  the process. Nothing to find on a seized device, nothing in a backup.
- `.privacySensitive()` blurs the UI in the app switcher, so the fleet's
  vulnerability counts are not in a screenshot of a locked phone.
- Returning from the background re-authenticates rather than resuming a token,
  which removes "left open on a desk" as a threat for one Face ID prompt.
- The Keychain item is `WhenUnlockedThisDeviceOnly`: it does not travel in an
  iCloud backup and cannot confuse a restored device into thinking it is already
  enrolled.

## 8. What sign-out is not

"Sign out on this device" removes the enclave key and the local record. It does
**not** revoke the device on the relay — only an administrator can, from secman.
The UI says exactly that rather than implying otherwise, because on a lost phone
this button is not the control that helps. The control that helps is
`POST /api/relay/revocations`, and it takes effect on the device's very next
request.

## 9. Threats this design does not address

Stated plainly, because a threat model that claims to cover everything covers
nothing:

- **A jailbroken device.** The enclave key still cannot be extracted, but an
  attacker with code execution in the app's process can read the snapshot and
  the live access token from memory, and can ask the enclave to sign while the
  user is present. No jailbreak detection is attempted: it is bypassable, and
  pretending otherwise would be worse than the honest statement.
- **A malicious or compelled administrator.** They can link their own Apple
  account to a privileged secman user. The relay is not a check on secman; the
  audit trail is in secman.
- **Shoulder surfing and screenshots.** Beyond the app-switcher blur, the
  content is on a screen.
- **A compromised relay lying.** It can show a phone stale or fabricated data.
  It cannot reach secman, mint a device, or read anything secman did not push.
  The snapshot is monotonic and instance-pinned, so it cannot replay an old one
  or splice in another instance's.
- **Traffic analysis.** That a device polls a relay is observable.

## 10. Security test matrix

The flows involving the Secure Enclave, biometrics or a browser cannot be
automated in CI. Run these by hand on a real device before each release; the
relay-side equivalents are automated in `src/relay/internal/api/api_test.go`.

| # | Test | Expected |
|---|---|---|
| 1 | Sign in with Apple as an ADMIN | succeeds |
| 2 | Sign in with GitHub as an ADMIN | refused, with the "use Apple or Google" message |
| 3 | Enrollment code as an ADMIN | refused, same message |
| 4 | Enrollment code as a VULN user | succeeds |
| 5 | Reuse the same enrollment code | refused |
| 6 | Sign in with an Apple account no admin has linked | refused, "not authorized" |
| 7 | Sign in as VULN, list sections | only `imports`; no KPIs anywhere in the UI |
| 8 | Open `/api/v1/status/kpis` as that VULN user (via proxy) | 403, identical to a nonexistent section |
| 9 | Have an admin demote the user in secman, pull to refresh | the section disappears without re-signing in |
| 10 | Have an admin revoke the device | next refresh fails; re-signing in does not help |
| 11 | Deny the Face ID prompt | clean cancel, no error alert, no session |
| 12 | Add a fingerprint/face to the device, then refresh | key invalidated, re-enrollment required |
| 13 | Airplane mode | clear "could not be reached" state, no crash, no stale data shown as current |
| 14 | Stop secman's publisher for 30 minutes | stale banner with the age, data still visible |
| 15 | Restart the relay (memory-only store) | "waiting for secman" until the next push, then normal |
| 16 | Background the app, screenshot the app switcher | content blurred |
| 17 | Point the app at an `http://` URL | refused at setup |
| 18 | MITM with a trusted-root proxy, pins configured | connection refused |
| 19 | MITM with a trusted-root proxy, pins empty | connects — expected; document that pinning is the control |
| 20 | Restore a device backup onto another phone | not enrolled; the enclave key did not travel |
