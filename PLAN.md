# Project Plan: Soribium-Repo — a Private Repo ZK-Rollup on Stellar

A prototype extending **Soribium** (`github.com/tomerweller/soribium`) from a payments
validium into a **private bilateral repo venue**: cash lent against tokenized-Treasury
collateral, fixed term and rate, timestamp-enforced maturity, oracle-driven margining —
all off-chain in a Noir circuit, settled on Stellar testnet via one UltraHonk proof per
batch. Position sizes, rates, and counterparties are invisible on L1; only escrow
totals, state roots, and commitments touch the chain.

**Base:** fork of Soribium `main`. Reuse its toolchain, harness, sequencer, contract
skeleton, and wallet. Read `DESIGN.md` and `REPORT.md` in the repo root before writing
any code — they are the source of truth for hash layouts, toolchain pins, and measured
budgets. This plan describes deltas against them.

**Scope decisions (already made — do not revisit):**

- Fork/extend Soribium; do not restructure the workspace.
- Phase 1 + margining: intraday/term repo with oracle price and liquidation. No
  rehypothecation, no DAC, no forced exits (tracked as out of scope).
- Assets: native XLM = cash leg; a newly deployed mock SEP-41 token `tUST`
  (7 decimals, mintable by an admin key) = collateral leg.
- UI: evolve the existing React wallet into a minimal repo desk.
- Testnet only. Not audited. Same trust model as Soribium (validium, single sequencer).

---

## 0. Ground rules

1. **Toolchain stays pinned** as in Soribium's `DESIGN.md` (nargo, bb, soroban-sdk,
   ultrahonk-soroban-verifier rev, rust). Do not upgrade anything unless a task is
   impossible without it; if you must, record why in `DESIGN.md`.
2. **The three-way hash contract is sacred.** Every hash layout must be identical in
   the Noir circuit, the Soroban contract, and the Rust harness (which hashes through a
   Soroban `Env`). Any new domain or leaf layout gets: a constant in all three places,
   a shared test vector in `fixtures/`, and a cross-vector test that fails if any of
   the three drifts. This is the #1 source of silent breakage.
3. **Keep the e2e green at every milestone.** `scripts/e2e_testnet.sh` (extended per
   milestone) must pass before a milestone is complete. Never merge a milestone with a
   broken pipeline.
4. **Measure, don't assume.** After every circuit change, record: gate count (log2),
   `bb prove` wall time and peak RSS on the dev machine, and `submit_batch` declared
   instructions via `simulateTransaction` (wasm metering ≈ 1.5× the native test env —
   only trust simulation). Append rows to a table in `REPORT.md`. Budgets: verify +
   contract work ≤ 400M instructions (expect ~90–110M; alarm at 200M), prove ≤ 3.5s
   target on deployment hardware (laptop numbers are indicative only).
5. **Update `DESIGN.md` in the same commit** as any change to domains, leaf layouts,
   public inputs, or message formats.

---

## 1. Target design (deltas from payments Soribium)

### 1.1 State

The contract stores a single `state_root = Poseidon2([account_root, position_root])`.

**Account tree** — depth 8 (256 accounts), as today, but the leaf gains a second
balance:

```
bal_hash = Poseidon2([cash, coll])
leaf     = Poseidon2([DOMAIN_LEAF, pk_x, bal_hash, nonce])
```

`cash` = XLM stroops, `coll` = tUST base units, both range-constrained to u64 (both
assets satisfy the total-supply ≤ u64::MAX invariant: XLM natively; tUST because its
mint authority is ours — enforce a supply cap in the token or document the invariant).

**Position tree** — new, depth 8 (256 open positions), same node/empty conventions as
the account tree. Position record:

```
{ borrower_pk_x, lender_pk_x, cash: u64, coll: u64,
  rate_bps: u32, haircut_bps: u32, open_ts: u64, maturity_ts: u64 }

term_hash = Poseidon2([rate_bps, haircut_bps, open_ts, maturity_ts])
amt_hash  = Poseidon2([cash, coll])
pos_leaf  = Poseidon2([DOMAIN_POS, borrower_pk_x, lender_pk_x, Poseidon2([term_hash, amt_hash])])
```

Empty slot = 0. Slot allocation: find-first free slot (prover-supplied index, circuit
verifies the old leaf at that index is 0). Closing a position zeroes the leaf.
**Position-slot reuse within one batch is forbidden** (constrain opened indices
distinct from each other and from closed indices in the same batch — simplest: process
all closes/defaults/liquidations before all opens).

### 1.2 New domain separators

Extend the domain table (values continue from Soribium's 7):

| Domain | Value | Use |
|---|---|---|
| `DOMAIN_POS` | 8 | position leaf |
| `DOMAIN_OPEN` | 9 | repo-open signing message |
| `DOMAIN_CLOSE` | 10 | repo-close signing message |
| `DOMAIN_DEP2` | 11 | deposit fold (now binds asset id) |
| `DOMAIN_WD2` | 12 | withdrawal fold (now binds asset id) |

Asset id: `0` = cash (XLM), `1` = collateral (tUST), as a Field in hashes and a `u32`
in envelopes.

### 1.3 Batch operations

Fixed-size arrays with `is_active` padding, exactly like payments Soribium (padding
freezes roots and fold accumulators; the padding keypair remains blacklisted for
active ops). Suggested starting sizes: `D=4` deposits, `O=2` opens, `C=2` closes,
`L=2` liquidations/defaults, `T=4` transfers, per batch. Make all of them const
generics/parameters from day one so we can grow them after measuring.

**Deposit** `{pk_x, asset, amount}` — as today but with asset id; one FIFO queue on
the contract per asset (two queues; `deposit_count` in the envelope becomes a pair).
Fold: `acc' = Poseidon2([DOMAIN_DEP2, acc, Poseidon2([pk_x, asset, amount])])`.

**Transfer / withdraw** — keep Soribium's L2 payment op, extended with `asset`.
Withdrawal fold uses `DOMAIN_WD2` and binds `(address_field, asset, amount)`.

**Repo open** — bilateral. Message:

```
open_msg = Poseidon2([DOMAIN_OPEN, borrower_pk_x, lender_pk_x,
                      Poseidon2([term_hash, amt_hash, borrower_nonce, lender_nonce])])
```

Circuit verifies **two** Grumpkin-Schnorr signatures (borrower and lender, same scheme
and defenses as Soribium's tx signature: range-checked s, on-curve checks, even-y
keys), checks `lender.cash ≥ cash`, `borrower.coll ≥ coll`,
`coll_value_at_open ≥ cash × (1 + haircut_bps/10⁴)` using the batch price (see 1.5),
`maturity_ts > batch_ts`, both nonces match and increment, then: lender.cash −= cash,
borrower.cash += cash, borrower.coll −= coll, position leaf written to a free slot.
Collateral sits **in the position**, not in either account (title-transfer analog).

**Repo close (repay)** — borrower-signed. Message binds `DOMAIN_CLOSE`, the position
slot index, position leaf hash, and borrower nonce. Requires `batch_ts ≤ maturity_ts`.
Interest (see 1.4): borrower.cash −= (cash + interest), lender.cash += (cash +
interest), borrower.coll += coll, position zeroed.

**Default** — permissionless (no signature; the sequencer includes it). Requires
`batch_ts > maturity_ts` and position open. lender.coll += coll, position zeroed.
Borrower keeps the cash. (Haircut economics play out exactly as in tradfi.)

**Liquidation (margin breach)** — permissionless. Requires
`coll × price < cash × (10⁴ + haircut_bps/2) / 10⁴` at the batch price (breach of half
the initial haircut). Same effect as default. Note: prototype does full liquidation —
no top-up flow. A borrower avoids liquidation by closing early.

### 1.4 Interest math

`rate_bps` is annualized, ACT/360 on seconds:

```
interest = floor( cash × rate_bps × elapsed_secs / (10⁴ × 360 × 86400) )
elapsed_secs = batch_ts − open_ts
```

In-circuit: compute `interest` as a prover witness and **constrain the floor division**
with a multiplication + range check:
`interest × DENOM ≤ cash × rate_bps × elapsed_secs < (interest + 1) × DENOM`,
with the product computed in Field (it fits: u64 × u32 × u40 < 2^136 « BN254 Fr) and
`interest` range-checked to u64. Add unit vectors: zero-elapsed, one-day at 4.30% on
$10M-equivalent, max-term boundary. The same computation must exist in the harness
(u128 arithmetic) and be fixture-tested against the circuit.

### 1.5 Public inputs (7)

```
main(old_state_root: pub, new_state_root: pub,
     deposit_hash: pub, withdraw_hash: pub, da_commitment: pub,
     batch_ts: pub, price: pub,
     ...private op arrays...)
```

- `batch_ts` — the contract binds `env.ledger().timestamp()` (allow the envelope to
  carry a claimed ts and require `|claimed − ledger.timestamp| ≤ 60` so proving isn't
  racing the ledger; the circuit uses the claimed value).
- `price` — tUST/XLM price in fixed-point 1e7, read by `submit_batch` from the oracle
  contract (see 1.6) inside the same invocation, and bound as a public input. Reject
  if the oracle's `last_updated` is older than 5 minutes.
- Everything else as in Soribium (`da_commitment` fold now runs over every active op's
  message/record so the blob fully reconstructs both trees).

### 1.6 Oracle (mock)

New tiny Soroban contract `contracts/oracle/`: stores `{price: i128, ts: u64}`,
settable only by an admin key, readable by anyone. Mimic the Reflector interface shape
loosely but do not integrate real Reflector in this prototype. The sequencer gets a
CLI/env-driven way to push prices in dev, and `scripts/` gets a `set_price` helper.
The e2e uses it to trigger a liquidation deterministically.

### 1.7 Contract (`contracts/rollup/`)

`submit_batch(envelope)` extends Soribium's: two deposit queues and counts, withdrawal
list entries gain `asset`, reads oracle price + ledger timestamp and places both into
the public-input blob (7 × 32 bytes = 224-byte PI blob), custody of **two** SACs
(XLM SAC + tUST SAC; addresses fixed at init). Keep the existing negative-test posture:
every way to lie in the envelope (wrong root, wrong count, redirected withdrawal,
wrong asset, stale price, replayed proof) gets an explicit failing test.

### 1.8 Sequencer

- Mempool gains typed ops: `open_intent` (half-signed), `open` (fully signed), `close`,
  plus existing transfers. **Matching flow:** party A posts a half-signed open intent;
  the sequencer exposes it (`GET /intents`, filtered to the named counterparty only —
  privacy); party B countersigns; the fully signed open enters the batch queue.
- A **maturity/margin watcher**: every tick, scan open positions; enqueue `default`
  ops for past-maturity positions and `liquidation` ops for under-margined ones at the
  current oracle price.
- DA blob v2: versioned serialization of all op records (document the byte layout in
  `DESIGN.md`); `GET /da/:batch_num` unchanged; state API additionally serves
  positions (`GET /positions/:pk_x`, both legs).
- Keep eager batching and the ≤3.5s proving budget; if the repo circuit blows the
  budget on dev hardware, shrink batch sizes (they're parameters) and note it in
  `REPORT.md` rather than blocking.

### 1.9 Wallet (repo desk)

Extend, don't redesign: two balances (XLM/tUST) with deposit/withdraw for each; a
"Repos" tab: post open-intent form (counterparty pk, cash, collateral, rate, haircut,
maturity), incoming-intents list with Accept (countersign), open positions with live
accrued interest and Close button, history. Client-side verification extends to both
tree roots. Show a clear "liquidation price" per position.

---

## 2. Milestones

Each milestone = one PR-sized unit with its own tests; e2e green before moving on.

**M0 — Baseline.** Fork compiles; `just check` and `scripts/e2e_testnet.sh` pass
untouched. Deploy mock tUST SEP-41 token + oracle contract; `just bootstrap` extended
to deploy both and write their addresses to `.env`. *Accept: existing payments e2e
green; tUST mintable; oracle settable/readable via script.*

**M1 — Multi-asset accounts.** New leaf layout, two custody pools, two deposit queues,
asset-aware transfers/withdrawals. Circuit + contract + harness + fixtures updated
together. *Accept: e2e deposits XLM and tUST to two users, L2-transfers each, withdraws
each; all cross-vector hash tests pass; negative tests for wrong-asset withdrawal.*

**M2 — Position tree + repo open.** Position tree, combined `state_root`, `DOMAIN_POS/
OPEN`, bilateral-signature verification, open op end-to-end (intent → countersign →
batch → on-chain root advance). No time logic yet (`maturity_ts` stored, not enforced).
*Accept: e2e opens a repo between two funded users; balances and position query
correct; sequencer-root == on-chain root; duplicate-slot and single-signature
negative tests fail as expected.*

**M3 — Time, close, default.** `batch_ts` public input bound by the contract, interest
constraint, close op, default op, maturity watcher. *Accept: e2e opens a repo with
maturity = now+60s, closes one before maturity (interest asserted to the stroop
against the harness computation), lets a second expire and asserts auto-default
credited the lender's collateral; close-after-maturity rejected in-circuit.*

**M4 — Margining.** `price` public input from the oracle, open-time collateral-adequacy
check, liquidation op, margin watcher, staleness rejection. *Accept: e2e opens a repo,
admin drops the oracle price past the threshold, watcher liquidates in the next batch;
opening an under-collateralized repo fails; stale-price submit_batch rejected.*

**M5 — Wallet repo desk.** UI per 1.9 against the real sequencer, plus mock-sequencer
fixtures for `dev:mock`. *Accept: full demo flow in the browser — two browser profiles,
deposit → intent → accept → position visible both sides with accruing interest →
close; crypto vector tests still gate the wallet build.*

**M6 — Hardening & report.** Full negative-test sweep (list in §3), measurement table
in `REPORT.md` (gates, prove time, RSS, declared instructions, fee per batch, per-op
cost), `DESIGN.md` fully updated, README rewritten for the repo use case, demo script
(`scripts/demo.sh`) that narrates the M3+M4 story on testnet. *Accept: `just check`,
`cargo test`, e2e, and demo all green from a clean clone.*

---

## 3. Security invariants (each needs a test)

Value conservation per batch across both assets (sum of balances + open-position
amounts + pending queues is constant modulo deposits/withdrawals). No position slot
collision. Both signatures required to open; neither party can be bound unilaterally.
Close only by borrower, only before/at maturity. Default/liquidation only when their
condition holds at the bound `batch_ts`/`price` — never on a signature. Interest floor
division exact vs harness. Withdrawal cannot be redirected, re-amounted, or re-asseted.
Stale/failed oracle blocks batches containing liquidations but must not block pure
payment batches (decide: either two circuit variants or always require a fresh price —
**always require it**; simpler, and the sequencer controls the mock oracle anyway —
document this). Replay: old_root binding covers it as in Soribium. Padding keypair
blacklisted in every new active-op position (both roles).

## 4. Out of scope (do not build)

Rehypothecation/claim tokens; DAC signatures; forced exits; VK rotation; sequencer
decentralization; real Reflector integration; partial liquidation or margin top-up;
multi-collateral; mainnet anything; audits. If a task seems to require one of these,
stop and flag it instead.

## 5. Known risks / notes for the builder

- **Prove-time growth** is the main scaling risk (two trees + two sigs per open).
  Measure at M2 before choosing final batch sizes. Verification instructions are a
  non-issue (logarithmic; see REPORT.md).
- **Poseidon arity**: `soroban_poseidon::poseidon2_hash::<4, _>` — all layouts above
  are chosen to keep ≤4 inputs per absorb. Keep it that way.
- The 7-PI blob changes the VK (`public_inputs_size`); regenerate the VK whenever the
  interface changes and remember `--oracle_hash keccak` on **both** prove and
  write_vk.
- Timestamp skew: the ±60s claimed-ts window (1.5) exists because proving takes
  seconds; without it, batches race the ledger clock.
- tUST decimals (7) vs price fixed-point (1e7): write the units conversion once in the
  harness and test it; unit bugs here are the classic DeFi exploit.

---

## 6. Refinements (agreed 2026-07-31, pre-implementation Q&A)

These amend the sections above and take precedence where they conflict.

### 6.1 Decided by the user

1. **Price convention (amends 1.5, 1.3):** the oracle stores
   `price = (XLM per 1 whole tUST) × 1e7`. Because tUST has 7 decimals and the
   fixed point is 1e7, collateral value in stroops = `coll_base_units × price / 1e7`.
   All in-circuit comparisons are cross-multiplied (no division):
   - Open adequacy: `coll × price × 10⁴ ≥ cash × (10⁴ + haircut_bps) × 1e7`
   - Liquidation trigger: `coll × price × 2·10⁴ < cash × (2·10⁴ + haircut_bps) × 1e7`
     (doubling both sides avoids `floor(haircut_bps/2)`)
   Products fit comfortably in BN254 Fr given u64/u32 range checks on inputs.
   Write the units conversion once in the harness and fixture-test it (per §5).

2. **Public-input schedule (amends M2–M4):** the full 7-PI `main` signature
   (incl. `batch_ts` and `price`) lands at **M2**. The contract binds both from
   day one; circuit constraints that *use* them arrive in M3 (time) and M4
   (margin). One VK regeneration instead of three. Milestone acceptance
   criteria unchanged.

3. **Timestamp binding (amends 1.5):** one-sided, past-only window. Contract
   requires `claimed_ts ≤ ledger.timestamp()` and
   `ledger.timestamp() − claimed_ts ≤ 60`. Premature default/liquidation via a
   future-dated batch_ts is impossible; sequencer time-delay only ever favors
   the borrower. Document in DESIGN.md.

4. **Repo setup:** clone `tomerweller/soribium` into `~/cellarium`, work
   locally on a branch. GitHub repo creation and final project naming
   deferred until there's something to push.

### 6.2 Implementer defaults (flagged; change only if the user objects)

- **In-batch op order (fixes 1.3's "simplest" note):** deposits →
  closes/defaults/liquidations → opens → transfers/withdrawals. All
  closing-type ops (close/default/liquidation) must target distinct slots
  within a batch; opened slots distinct from each other and from all
  closed slots.
- **Default vs liquidation:** one circuit op type with a mode flag
  (`is_liquidation`); mode selects which condition (maturity vs margin) is
  constrained. Same state effect.
- **Deposit fold with two queues:** single `deposit_hash` accumulator; fold
  the XLM-queue prefix first, then the tUST-queue prefix; envelope carries
  `(deposit_count_xlm, deposit_count_tust)`. Order documented in DESIGN.md.
- **tUST implementation** *(revised during M0)*: a pure Soroban SEP-41 token
  contract (`contracts/tust/`), 7 decimals, admin-mintable, supply cap
  ≤ u64::MAX enforced in the token. The classic-asset/SAC route was tried
  first but requires a change-trust step on every receiving G account, which
  frictions the e2e and the browser demo; a native Soroban token needs no
  trustlines. `just bootstrap` deploys it; `scripts/mint_tust.sh` mints; a
  dev-only faucet path funds browser users with tUST for the M5 demo.
- **Close-interest determinism note:** the borrower signs close without
  knowing the exact inclusion `batch_ts`, so the repaid interest floats with
  inclusion time — but close is only valid through `maturity_ts`, so the
  worst-case repay is computable at signing time. Accept; surface the
  at-maturity repay amount in the wallet next to Close.
- **Intent privacy (1.8):** `GET /intents?counterparty=<pk_x>` is filtered but
  unauthenticated in this prototype (privacy from casual observers only; the
  sequencer sees everything anyway under the validium trust model). Document
  as a caveat rather than building signature-authenticated queries.
- **Oracle admin:** a dedicated admin keypair generated at bootstrap and
  written to `.env`; `scripts/set_price` uses it. Per §3's decision, every
  batch requires a fresh price, so the sequencer (or e2e script) refreshes the
  oracle before submitting when the last update is older than the 5-minute
  staleness bound.
