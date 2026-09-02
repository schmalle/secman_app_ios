# Screens

What each screen shows, where every element gets its data, and which state it
is in when. The relay endpoints are documented in [`API.md`](API.md); this file
is the map from those fields to pixels.

Two rules hold on every screen:

- **The relay decides what exists.** Every section, every sign-in button and
  every policy line comes from a relay response. The app orders and formats;
  it never filters, and it never invents a threshold the server did not state.
- **Freshness is always on screen.** Nothing is shown without its age. A number
  that looks current and is forty minutes old is the one thing a status app
  must never produce.

---

## 1. Set up

Shown when no relay URL is baked into `Info.plist` (`SecmanRelayURL`) and none
has been entered yet.

| Element | Source |
|---|---|
| Relay address field | typed; a bare hostname becomes `https://`, an explicit `http://` is refused |

---

## 2. Sign in

Shown when the device is not enrolled. Built entirely from
`GET /api/v1/providers`.

| Element | Source | Notes |
|---|---|---|
| One button per provider | `providers` | only what the relay enabled; order Apple, Google, GitHub |
| Caption under each button | `strongProviders`, `privilegedRoles` | "For every account, including ADMIN" or "Not for ADMIN accounts" |
| Policy footer | same | states the rule before the user taps |
| Enrollment-code field | `enrollmentCodes` | hidden when the relay disabled codes |
| Connection section | local settings, `providers` | relay host and the enabled methods |

The captions are the app's answer to a 403 the user would otherwise discover
after a browser round trip. They are derived, not hard-coded: a relay that
declares `github` strong shows the opposite caption without an app release.

---

## 3. Status (the list)

The first screen once signed in. On iPad it is the sidebar of a split view;
on iPhone it is the whole screen, which is why it carries more than names.

### Freshness row

| Line | Source | Behaviour |
|---|---|---|
| "Status from 2 min ago" | `/meta.generatedAt` | ticks on its own; green check, or orange clock when `stale` |
| "Checked 15 s ago · secman-prod" | time of the last successful refresh, `/meta.instanceId` | ticks on its own |
| "Waiting for secman" | `/meta` answered 503 | the relay is up, secman has not pushed |

### Banners

Appear under the freshness row, and again at the top of every section on
iPhone, where the list is off screen.

| Banner | Condition | Colour | What stays on screen |
|---|---|---|---|
| Relay unreachable for 3 min | the last refresh got no answer | red | everything from the last successful refresh, still aged |
| Data is 42 min old | `/meta.stale` | orange | the snapshot, labelled |
| Update the app | `/status.schemaVersion` is not one this build knows | orange | nothing — refreshing cannot help, and the banner says so |

The three are distinct on purpose. "Unreachable" is the app's own problem and
may be a tunnel; "stale" is the relay saying secman's publisher has gone quiet;
"update the app" is neither, and clears only with a release. Conflating them
sends an operator to debug the wrong system.

### Section rows

One row per name in `/meta.sections`, in a stable order (the six known
sections first, anything new after, alphabetically). Each carries a trailing
highlight computed from the snapshot by `RelaySnapshot.highlight(for:)`:

| Section | Highlight | Orange when | Red when |
|---|---|---|---|
| Overview | "88,211 vulnerabilities" | — | — |
| Security KPIs | "AWS 92.4% · EDR 97.5%" | either KPI is not calculated yet (shown as "–") | — |
| Exceptions | "14 pending" / "none pending" | pending > 0 | — |
| Imports | "no errors" / "3 errors" / "no import yet" | no import has run | the last import had errors |
| Top products / servers | "nginx · 1,204" (the top entry) | — | — |
| anything unknown | none | — | — |

A highlight is a convenience. When the app cannot summarise a section — an
unknown name, a known name with a shape this build does not expect — the row
shows the name alone and the detail view still renders the raw rows.

### Empty state

"Nothing to show" when `/meta.sections` is empty: the account is valid but its
roles reach none of the sections this relay publishes.

---

## 4. Section detail

`List` per section, with the banners above (iPhone only) and a **Source**
section below. Pull to refresh everywhere.

### Overview (`totals`)

Assets, vulnerabilities, users. Footer states these are totals across
everything secman holds, as of the snapshot.

### Security KPIs (`kpis`)

Two blocks, each a percentage with a bar, the counts behind it, and when secman
last calculated it.

**AWS clean servers** — `awsCleanServers`

| Row | Field |
|---|---|
| gauge "AWS servers with no finding open past 30 days" | `percentage` |
| Clean / all AWS servers | `cleanServers` / `totalServers` |
| Calculated | `lastCalculatedAt`, server local time |

The footer spells out what "clean" means as of secman's August 2026 changes: no
open, non-excepted finding older than 30 days, with the age measured **from the
date a fix became available** where secman knows one (falling back to
detection), and installer artifacts excluded. That anchor is why a rebuilt host
no longer resets the clock, and why the number can drop on the first import
after upgrading secman — a patch date is usually much earlier than a detection
date.

**EDR coverage** — `edrCoverage`

| Row | Field |
|---|---|
| gauge "Eligible EC2 instances with a live CrowdStrike sensor" | `percentage` |
| Covered / eligible | `coveredInstances` / `eligibleInstances` |
| All EC2 instances | `totalInstances` — shown so the effect of exemptions stays visible |
| Excluded by "No EDR possible" exception | `excludedByException`, only when > 0 |
| Sensor seen within | `agentSeenWithinDays` |
| Calculated | `lastCalculatedAt`, server local time |

`available: false` on either block renders "Not calculated yet" and never a
percentage: a fresh install has not measured anything, and 0% would read as a
fleet-wide outage.

The gauges have **no thresholds and no red/green**. secman defines none for
these KPIs, and a colour the server did not choose would be the app inventing
a policy.

### Exceptions (`exceptions`)

A status line ("Waiting on a reviewer" / "Nothing waiting") and the pending
count. The footer says review happens in secman — there is no approve button
anywhere in this app, by construction.

### Imports (`imports`)

| Row | Field |
|---|---|
| status line "Completed" / "Completed with errors" | `errorCount` |
| Last import | `importedAt`, server local time |
| Servers processed | `serversProcessed` |
| Vulnerabilities imported | `vulnerabilitiesImported` |
| Errors | `errorCount`, red when > 0, "none" otherwise |

The footer notes secman's current reconcile behaviour: a host whose fetch
failed keeps its previous findings rather than having them swept as remediated.

### Top products / Top servers

Ranked rows: position, name, count, and a bar relative to the top entry so the
shape of the list reads without the numbers. The same ten-entry lists the admin
summary mail sends.

### Anything else

A section this build has no view for renders as labelled rows straight from
the JSON, with a footer saying so. That is the app's side of the relay's
"section bodies are opaque" bargain: a new section in secman is a refresh, not
a release.

### Source

| Row | Field |
|---|---|
| Generated | `/status.generatedAt`, absolute plus a ticking "ago" |
| Received by relay | `/meta.receivedAt` |
| Stale after | `/meta.maxAgeSeconds` — the relay's own threshold |
| secman instance | `instanceId` |
| Status format | `schemaVersion` |

The gap between generated and received is the one diagnostic a phone can offer
about the publisher: a large one means a slow push, not old data.

---

## 5. Settings

| Section | Rows | Source |
|---|---|---|
| Account | user, name (when it differs), roles, signed in with | `/session` |
| This device | device id, registered date, scope, readable sections | `/session`, the Keychain record, `/meta.sections` |
| Freshness | last checked, unreachable since, snapshot age, stale threshold, instance, status format, poll interval | model state, `/meta` |
| Relay policy | sign-in methods, enrollment codes, privileged roles, strong providers | `/providers` |
| Connection | relay host, pinning on/off, app version | local settings, bundle |
| Sign out | — | local only; the footer says it does not revoke the device |

"Scope" is the per-device narrowing an administrator can grant on top of a
user's roles (`status:*` or a list of sections). Most devices carry the
wildcard, shown as "all sections"; a narrowed device lists its sections so a
user who sees less than a colleague with the same role can see why.

---

## 6. Time and timestamps

The relay carries two kinds of timestamp, and the app treats them differently
on purpose (`RelayTimestamp`):

| Kind | Examples | Rendering |
|---|---|---|
| Instant with a zone | `generatedAt`, `receivedAt` | device's time zone |
| Server wall-clock, zone unknown | `importedAt`, `lastCalculatedAt` | as written, captioned "server local time" |

secman reads the second kind out of the database as `LocalDateTime` and does
not stamp a zone on it, because inventing UTC would shift every displayed time
by the server's offset. The app follows suit. Converting would look more
precise and be wrong by hours.

Every relative age on screen ("2 min ago") is a live `Text(date, style:
.relative)` and ticks without a refresh.

---

## 7. Refresh behaviour

| Trigger | What happens | Face ID? |
|---|---|---|
| Launch, return from background | full refresh; a lapsed token is re-minted | yes, if the token lapsed |
| Pull to refresh | same | yes, if the token lapsed |
| Foreground poll, every 60 s while the app is on screen | `/meta` (a few hundred bytes); `/status` only when `generatedAt` moved | **never** — the poll skips silently once the 15-minute token lapses |

The poll interval matches secman's default publish interval. It is a
`Task.sleep` loop keyed on "signed in and scene active", so backgrounding the
app cancels it and nothing runs while the phone is in a pocket.

A poll that finds a lapsed token does nothing rather than prompting. A Face ID
sheet that appears on its own every fifteen minutes while a phone sits on a
desk is exactly the prompt people learn to approve without looking.
