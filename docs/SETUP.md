# Setup

End to end: provision the identity providers, configure the relay, link users in
secman, then build the app. Roughly an hour the first time.

Nothing in this file is a secret except where it says so. The two real secrets —
the relay's ingest credentials and the GitHub client secret — never go near the
app bundle or this repository.

---

## 1. Apple — Sign in with Apple

Required. It is the default (and, for administrators, one of only two allowed)
sign-in methods.

1. In the Apple Developer portal, enable the **Sign in with Apple** capability
   on the app id (`io.secman.status`, or your own).
2. No Services ID and no key are needed: the app uses the native flow and the
   relay verifies the identity token against Apple's public JWKS. There is no
   client secret anywhere in this design.
3. On the relay:

   ```bash
   RELAY_APPLE_ENABLED=true
   RELAY_APPLE_AUDIENCES=io.secman.status   # your app's bundle identifier
   ```

   `RELAY_APPLE_AUDIENCES` is a security control, not boilerplate: it is what
   stops an Apple ID token minted for a *different* app from being accepted.

---

## 2. Google — Sign in with Google

Optional, but recommended as the second strong provider so administrators are
not single-homed on Apple.

1. Google Cloud console → **APIs & Services → Credentials → Create OAuth client
   ID → iOS**. Enter the bundle identifier.
2. Copy the client id, e.g. `123456-abcdef.apps.googleusercontent.com`. An iOS
   OAuth client is a **public client** — the id is not a secret and there is no
   client secret to protect.
3. In `App/SecmanApp/Resources/Info.plist`, set `SecmanGoogleClientID`.
4. Add the reversed client id as a URL scheme. XcodeGen users can add it to
   `CFBundleURLTypes` in `Info.plist`:

   ```xml
   <string>com.googleusercontent.apps.123456-abcdef</string>
   ```

5. On the relay:

   ```bash
   RELAY_GOOGLE_ENABLED=true
   RELAY_GOOGLE_AUDIENCES=123456-abcdef.apps.googleusercontent.com
   ```

---

## 3. GitHub — optional, non-privileged accounts only

The relay is the OAuth client here, so the secret stays server-side and never
reaches a device. Administrators cannot use this method.

1. GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Authorization callback URL: `https://relay.example.com/api/v1/auth/github/callback`
   — the relay's own callback, not a custom scheme.
3. On the relay:

   ```bash
   RELAY_GITHUB_ENABLED=true
   RELAY_GITHUB_CLIENT_ID=Iv1.xxxxxxxxxxxx
   RELAY_GITHUB_CLIENT_SECRET=...          # secret — pass-cli, never a file in git
   RELAY_GITHUB_REDIRECT_URI=https://relay.example.com/api/v1/auth/github/callback
   RELAY_APP_CALLBACK_SCHEME=secman-relay
   ```

`RELAY_APP_CALLBACK_SCHEME` must match `CFBundleURLSchemes` in `Info.plist`.

---

## 4. The relay

Full reference: `docs/RELAY.md` in the secman repository. The identity-related
settings:

```bash
# Which roles demand a strong provider, and which providers count as strong.
# These defaults are the deployment rule: an ADMIN signs in with Apple or
# Google, never GitHub and never a typed code.
RELAY_PRIVILEGED_ROLES=ADMIN
RELAY_STRONG_PROVIDERS=apple,google

# Set to false for a federated-login-only deployment.
RELAY_ENROLLMENT_CODES_ENABLED=true
```

The relay refuses to start if `RELAY_PRIVILEGED_ROLES` is set but none of the
strong providers is enabled — otherwise an administrator could never sign in and
the failure would look like an app bug.

Verify before touching the app:

```bash
curl -s https://relay.example.com/api/v1/providers | jq
```

```json
{
  "providers": ["apple", "google"],
  "enrollmentCodes": true,
  "privilegedRoles": ["ADMIN"],
  "strongProviders": ["apple", "google"]
}
```

---

## 5. Link users in secman

Signing in proves who somebody is. It grants nothing until an administrator maps
that external account to a secman user.

```bash
# Apple: the `sub` claim from the identity token, e.g. 001234.abc…def.5678
curl -X POST https://secman.example.com/api/relay/identities \
  -H 'Content-Type: application/json' -b "$COOKIE" \
  -d '{"username":"markus","provider":"apple","providerSubject":"001234.abcdef","label":"Markus iPhone"}'
```

Getting the provider subject:

| Provider | Value | How to find it |
|---|---|---|
| Apple | the `sub` claim | Have the user attempt a sign-in; the relay logs `identitySubject` on the refusal |
| Google | the `sub` claim | Same |
| GitHub | the **numeric** account id | `curl -s https://api.github.com/users/<login> \| jq .id` |

Never use an email address or a login name. Both are mutable, and a released
GitHub login can be claimed by somebody else — which would silently transfer a
user's mobile access to a stranger. secman rejects a non-numeric GitHub subject
for exactly this reason.

Linking a GitHub account to an ADMIN is refused at this point, with an
explanation, rather than surfacing later as an opaque 403 in the app.

Check the result:

```bash
curl -s https://secman.example.com/api/relay/identities -b "$COOKIE" | jq
curl -s https://secman.example.com/api/relay/status      -b "$COOKIE" | jq '.principalsPublished'
```

### Enrollment codes, for non-privileged users

```bash
curl -X POST https://secman.example.com/api/relay/enrollments \
  -H 'Content-Type: application/json' -b "$COOKIE" \
  -d '{"subject":"scanner-user","ttlMinutes":15}'
```

The plaintext code is in the response **once**. secman does not store it and
cannot show it again; the relay only ever holds its SHA-256.

---

## 6. The app

In `App/SecmanApp/Resources/Info.plist`:

| Key | Value |
|---|---|
| `SecmanRelayURL` | `https://relay.example.com` — leave empty for the in-app setup screen |
| `SecmanGoogleClientID` | the iOS OAuth client id, or empty to hide the Google button |
| `SecmanRelayPublicKeyPins` | leave empty unless you have read the pinning warning below |
| `NSAppTransportSecurity` → `NSExceptionDomains` | replace `relay.example.com` with your host, or delete the block entirely |

Then:

```bash
brew install xcodegen
xcodegen generate
open SecmanApp.xcodeproj
```

Set your team and bundle identifier in Signing & Capabilities, confirm **Sign in
with Apple** is present, and run on a real device — the simulator has no Secure
Enclave, and while the app falls back to a software key there, that path must
never ship.

### About certificate pinning

Leave `SecmanRelayPublicKeyPins` empty unless you have a rotation runbook. A
Let's Encrypt certificate rotates about every 60 days; if the key changes and
the pin does not, **every installed copy stops working until an App Store
release ships** — days at best. If you do pin:

- pin the SubjectPublicKeyInfo, not the certificate;
- list at least two (current and a spare key you control);
- configure the relay with `RELAY_TLS_MODE=file` and a key you rotate on your
  own schedule, rather than ACME.

```bash
openssl s_client -connect relay.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
```

---

## 7. Verify

1. Launch, sign in with Apple as a linked ADMIN → all six sections.
2. Sign in as a linked VULN user → only **Imports**.
3. Try GitHub as an ADMIN → refused, with the "use Apple or Google" message.
4. Demote the user in secman, pull to refresh → the section disappears without
   re-signing in.
5. Revoke the device from secman → the next refresh fails and stays failed.

Then work through the full matrix in [`SECURITY.md`](SECURITY.md) §10.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| "This account is not authorized" | No identity link in secman for that provider subject. Check the relay log for the exact `identitySubject`. |
| "Requires a stronger login method" | The account holds a privileged role and tried GitHub or a code. Working as intended. |
| Apple sign-in fails immediately | `RELAY_APPLE_AUDIENCES` does not match the bundle identifier. |
| Google sheet opens then errors | Reversed client id missing from `CFBundleURLSchemes`. |
| GitHub returns to the app with `error=` | Callback URL mismatch between the GitHub app and `RELAY_GITHUB_REDIRECT_URI`. |
| "Waiting for secman" forever | The relay is up but no push has landed. Check `GET /api/relay/status` in secman. |
| Everything 403s after a role change | Expected while the principal push is in flight; at most one publish interval. |
