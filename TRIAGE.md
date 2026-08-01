# Open-issue triage — 2026-07-31

Snapshot triage of the 47 open issues (#2–#49, no #1 which is the closed audit
umbrella). Each issue is classified by **severity**, **area**, and
**actionability**:

- **fix-here** — a code/config change in this repository; addressed (or
  attempted) on this branch. See the *Status* column.
- **ops** — requires access this repo does not control (GitHub org/repo
  settings, Fly console, live deploys, secrets rotation). Needs the operator.
- **design** — requires a protocol/product decision before implementation is
  meaningful (trust model, custody model, escape hatch semantics).

## Critical / High

| # | Title (short) | Area | Class | Notes |
|---|---|---|---|---|
| 2 | Circuit changes auto-deploy vs immutable VK | ci/deploy | fix-here | Add VK-vs-contract guard to deploy workflow |
| 3 | Enforce HTTPS for production wallet | pages | ops | GitHub Pages `https_enforced` + custom-domain redirect; repo can only add an external check |
| 4 | Production outage: Fly service down | ops | ops | Live incident; needs Fly logs/deploy access. Do not auto-deploy from triage branch |
| 5 | Off-machine recovery for state + DA | ops/design | design | Needs RPO/RTO decision and off-machine storage target |
| 6 | Clickjacking: no frame-ancestors header | pages | ops | GitHub Pages cannot set response headers; requires host move or fronting CDN |
| 7 | Pin deployment identity before deposits | wallet | fix-here | Pin expected contract/network at build time; refuse mismatch |
| 8 | Gate deploys on complete CI; protect main | ops | ops | Branch protection + environments are repo-settings changes |
| 9 | Key derivation reproducible by any origin | wallet/design | design | Needs migration plan for existing keys; breaking change to derivation message |
| 10 | Dependency-aware health checks, task supervision | sequencer | fix-here | |
| 11 | Hard timeouts on Stellar CLI subprocesses | sequencer | fix-here | |
| 12 | Exclude local secrets from build contexts | build | fix-here | `.dockerignore` allowlist |
| 14 | Soroban TTL extension/restoration | contracts | design | Concrete but custody-critical contract change; needs redeploy + migration plan |
| 15 | Nightly proving of production batch_repo fixture | ci | fix-here | |
| 36 | Automated real E2E acceptance test | ci | design | Large; needs hermetic localnet runner decision |
| 42 | L2 key in plaintext localStorage | wallet/design | design | Custody model decision (encrypt-at-rest vs platform keystore) |
| 43 | Full account tree jams settlement | contracts/design | design | Contract admission/refund change; interacts with #14/#49 |
| 44 | Public DA discloses bilateral repo terms | api/design | design + fix-here | Redesign is design work; overstated claims corrected now (see #47) |
| 49 | Forced exit / escape hatch | contracts/design | design | Largest structural item; depends on DA availability model |

## Medium

| # | Title (short) | Area | Class | Notes |
|---|---|---|---|---|
| 13 | Commit confirmed state before advancing memory | sequencer | fix-here | |
| 16 | Nonce admission vs batch execution order | sequencer | fix-here | |
| 17 | Lapsed batch discarded on unknown chain state | sequencer | fix-here | |
| 18 | SPA deep links 404 on Pages | wallet/ops | ops | Real rewrites need host support; hash routing is the in-repo fallback |
| 20 | Unbounded repo intents; header spoofing | sequencer | fix-here | |
| 21 | Inclusion verification vs combined root | wallet | fix-here | |
| 22 | Terminal status for accepted repo intents | sequencer+wallet | fix-here (partial) | Backend lifecycle + wallet display |
| 25 | Deadlines/cancellation for wallet network ops | wallet | fix-here | |
| 26 | Local interest estimate presented as quote | wallet | fix-here | |
| 27 | Exact parsing of repo financial inputs | wallet | fix-here | |
| 28 | CSP must follow validated RPC config | wallet | fix-here (partial) | Meta-CSP generated from pinned config at build |
| 30 | API failures rendered as empty states | wallet | fix-here | |
| 31 | Params cached forever | wallet | fix-here | |
| 32 | Mobile navigation at narrow widths | wallet | fix-here | |
| 34 | Metrics, alerts, runbooks | ops | design | Needs metrics stack decision (where dashboards/alerts live) |
| 35 | fmt/clippy/all-package tests in CI | ci | fix-here | |
| 37 | Fixed-delay E2E assertions | scripts | fix-here | |
| 38 | Pin actions/tools/base images immutably | ci | fix-here | |
| 41 | Vulnerable wallet dependencies | wallet | fix-here | Upgrade + documented triage of remaining advisories |
| 45 | Reused nonce with different payload | sequencer | fix-here | |
| 46 | Account-key uniqueness not in circuit | circuits/design | design | Document operator-trust assumption now; circuit change later |
| 47 | Non-ZK proving vs privacy claims | docs | fix-here (docs) | Correct claims now; ZK benchmark is follow-up |
| 48 | Focused tests for API/watcher/batcher/DB/wallet | tests | fix-here (incremental) | Partially covered by regression tests added with each fix |

## Low

| # | Title (short) | Area | Class | Notes |
|---|---|---|---|---|
| 19 | Deposit hash lost on ambiguous timeout | wallet | fix-here | |
| 23 | Activity asset/direction/repo semantics | wallet | fix-here | |
| 24 | Pending deposits by asset + delta | wallet | fix-here | |
| 29 | RPC outage vs unfunded account | wallet | fix-here | |
| 33 | Accessibility: nav, labels, live regions | wallet | fix-here | |
| 39 | Obsolete operational scripts | scripts | fix-here | |
| 40 | Chain root/batch read not snapshot-consistent | sequencer | fix-here | |

## Ordering rationale

1. **Custody/consistency correctness first** (#13, #17, #16, #45): these can
   corrupt or strand user funds/state under normal failure modes.
2. **Liveness hardening** (#11, #10, #40, #20): a single hung subprocess or
   dead task currently stops the system silently.
3. **Supply-chain / deploy safety** (#12, #2, #15, #35, #38, #39): cheap
   insurance against shipping a broken or compromised artifact.
4. **Wallet correctness** (#21, #23, #27, #29, #30, then #19, #24, #25, #26,
   #31): users acting on wrong information.
5. **Docs honesty** (#44/#47 immediate items): remove overstated privacy
   claims until the design work lands.

Issues classified **ops** or **design** are intentionally not "addressed" by
code here; they need operator access or a decision. See the session report for
the specific decision each one is blocked on.

## Status

Updated at end of session — see final section of the session report.
