# Cellarium

A **private bilateral repo venue** running as a ZK-rollup (validium) on the
Stellar network. Built with [Noir](https://noir-lang.org) and UltraHonk
proofs verified on Soroban via Protocol 25/26's native BN254 + Poseidon host
functions.

Cash (native XLM) is lent against tokenized-Treasury collateral (a mock
SEP-41 token, `tUST`) at a fixed term and rate. Maturity is
timestamp-enforced, margining is oracle-driven, and everything — position
sizes, rates, counterparties — lives off-chain inside a Noir circuit.
Each batch of activity settles on Stellar testnet as **one UltraHonk proof**;
only escrow totals, state roots, and commitments touch the chain.

> Research prototype on **testnet only**. Not audited; see [Trust model &
> limitations](#trust-model--limitations).

## What a repo looks like here

1. **Deposit** — both parties escrow into the rollup contract: the lender
   XLM (cash), the borrower tUST (collateral). One FIFO queue per asset.
2. **Open** — party A posts a half-signed *intent* (counterparty, cash,
   collateral, rate, haircut, term); the sequencer shows it only to the named
   counterparty; party B countersigns. The batch circuit verifies **both**
   Grumpkin-Schnorr signatures, checks the lender's cash, the borrower's
   collateral, and open-time collateral adequacy at the oracle price, then
   moves cash to the borrower and the collateral into the position
   (title-transfer analog).
3. **Close (repay)** — borrower-only, before maturity. Interest is annualized
   ACT/360 on seconds, floor division enforced *in-circuit*:
   `interest = ⌊cash · rate_bps · elapsed / (10⁴·360·86400)⌋`.
4. **Default** — permissionless once `batch_ts > maturity_ts`: the maturity
   watcher hands the lender the collateral; the borrower keeps the cash.
5. **Liquidation** — permissionless on a margin breach at half the initial
   haircut, at the oracle price bound into the batch:
   `coll·price·2·10⁴ < cash·(2·10⁴+haircut)·10⁷`.

Every batch proves the 8-public-input relation
`(old_state_root, new_state_root, deposit_hash, withdraw_hash, da_commitment,
batch_ts, price, instance_id)` where `state_root = Poseidon2([account_root,
position_root])` and `instance_id = address_to_field(rollup contract)` binds
each proof to its deployment (no cross-instance replay, issue #1 L10).
The contract binds `batch_ts` to the ledger clock (one-sided: claimed ≤
ledger, lag ≤ 60s — a batch can never be future-dated into a premature
default) and reads `price` from the oracle in the same invocation, rejecting
stale (>5 min) prices.

## What's here

| Component | Path | What it is |
|---|---|---|
| Circuits | `circuits/` | Noir batch state-transition (`batch_repo`: 4 deposits, 2 closes, 2 defaults/liquidations, 2 opens, 4 payments per batch; Poseidon2 trees, Grumpkin Schnorr). |
| Rollup contract | `contracts/rollup/` | Soroban: two-asset SEP-41 custody, per-asset deposit queues (with a timeout refund for jammed heads), `submit_batch` verifying the 8-PI UltraHonk proof, timestamp window + oracle price binding. |
| tUST | `contracts/tust/` | Mock collateral token: pure Soroban SEP-41, 7 decimals, admin mint, supply cap ≤ u64::MAX enforced in-contract. |
| Oracle | `contracts/oracle/` | Mock price oracle (admin-set XLM-per-tUST × 1e7 + ledger timestamp), loosely Reflector-shaped. |
| Harness | `harness/` | Shared Rust: both trees, keys, Poseidon2 (through a Soroban `Env`, so off-chain ≡ on-chain), witness builder, interest math (fixture-tested against the circuit), prover driver. |
| Sequencer | `sequencer/` | Long-running backend (axum): mempool + intent matching + close queue, maturity/margin watcher, batch/prove/submit pipeline, DA + state HTTP API (`/positions`, `/intents`). |
| Wallet | `wallet/` | Browser repo desk (Vite + React + TS): two balances, deposit/withdraw per asset, post/countersign intents, live accrued interest + liquidation price per position, borrower close. |

Architecture overview: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Design details: [`DESIGN.md`](DESIGN.md). Project plan and agreed refinements:
[`PLAN.md`](PLAN.md). Measurements: [`REPORT.md`](REPORT.md).

## Quick start (local, against testnet)

Prereqs: Rust 1.95 + `wasm32v1-none`, `nargo` 1.0.0-beta.11 + `bb` 0.87.0
(`just setup-check` verifies), the Stellar CLI, Node 22.

```sh
just bootstrap      # fund identities; deploy tUST + oracle + rollup; write .env
just sequencer      # native sequencer (reads .env)
cd wallet && npm run dev            # repo desk → VITE_SEQUENCER_URL
```

Wallet-only development needs no backend at all:

```sh
cd wallet && npm run dev:mock &     # fixture-backed mock sequencer
cd wallet && npm run dev
```

Give a browser user collateral to play with:

```sh
scripts/mint_tust.sh G...USER 1000000000    # 100 tUST to their Stellar account
scripts/set_price.sh 250000000              # 25 XLM per tUST
```

Guided testnet demo (the full story: open → close-with-interest → default →
price-crash liquidation):

```sh
scripts/demo.sh
```

**Cloud deployment is self-healing:** pushing to `main` deploys the
sequencer to Fly (`.github/workflows/fly.yml`) and the wallet to GitHub
Pages. The sequencer container self-bootstraps
(`scripts/docker_entrypoint.sh`): on boot it fingerprints the baked
circuit's VK + DB schema against the instance recorded on its volume, and
on mismatch deploys fresh tUST/oracle/rollup contracts, archives the old
DB, and records the new instance — so a circuit or schema change needs no
manual re-bootstrap. The wallet picks up the new contract ids at runtime
from `GET /params`. (The abandoned instance's queued deposits remain
reclaimable via its permissionless `refund_deposit` after the 24h timeout.)

## Privacy

On L1 you can see: total XLM/tUST escrowed, state roots, DA commitments, and
the batch cadence. You cannot see who repo'd with whom, sizes, rates,
haircuts, or maturities — those live in the off-chain DA blob and the
position tree. The DA blob is served by the sequencer (`GET /da/:batch_num`)
and bound by the proven `da_commitment` (fold over close messages,
default/liquidation records, open records, and payment messages, in
application order). Intent listings are filtered to the named counterparty
AND require a signed read-auth challenge proving control of the queried key
(issue #1 L12; the sequencer still sees everything by construction).

One caveat for proof-observers: the deployed flavor is **non-ZK** UltraHonk,
which does not blind the witness. The privacy statements above are heuristic
against someone holding the proof bytes themselves — extraction from a
2^17-row trace is unanalyzed, not cryptographically impossible. The ZK
flavor was measured (issue #1 M6): `bb prove --zk` costs ~0.64s vs ~0.50s
non-ZK on the dev machine with equal memory — affordable — but it emits a
507-field (16,224-byte) proof that the pinned Soroban verifier
(456-field/14,592-byte, non-ZK only) cannot verify. Turning it on requires a
ZK-capable verifier crate, tracked as a production delta in DESIGN.md.

## Testing

```sh
just check              # nargo tests + Rust tests + wallet crypto/build
cargo test              # contracts + harness + sequencer
scripts/e2e_testnet.sh  # the full asserted story against testnet
```

The e2e deploys fresh contracts, boots the native sequencer, and asserts:
multi-asset deposits/transfers/withdrawals (with an exact L1 tUST payout),
per-asset balance isolation, a bilateral open via the intent flow, a close
whose interest is recomputed independently and matched **to the stroop**, a
watcher-driven default crediting the lender's collateral, a price-crash
liquidation, an under-collateralized open rejection, sequencer-root ==
on-chain-root at every stage, DA blob availability, and replay/gap-nonce
rejection.

The three-way hash contract (circuit ⇄ contract ⇄ harness ⇄ wallet) is
pinned by golden vectors in `fixtures/vectors.json`
(`cargo run -p harness -- vectors-json`); each stack's suite fails if any
layout drifts.

## Trust model & limitations

Every state transition is proven: both signatures are required to open, only
the borrower can close (and only before maturity), defaults/liquidations are
valid only when their condition holds at the bound timestamp/price, and value
is conserved per asset across accounts + positions + queues. Batch submission
is **operator-only** (the contract pins the sequencer address at deploy):
the circuit does not enforce `pk_x` uniqueness across account slots, so a
permissionless prover could otherwise route a queued deposit to a duplicate
slot and replay published signatures against it (issue #1 H1). Within that
single-operator model the proofs make state validity trustless; removing the
operator pin safely requires an in-circuit uniqueness/nullifier tree. Data
availability is **trusted to the sequencer operator**: withheld blobs freeze
the system (funds can't be stolen, but exits need the operator). The mock
oracle is admin-set — margining is only as honest as its price feed.

Known deltas tracked for a production version (also in `DESIGN.md` /
`PLAN.md` §4): single-operator sequencer, no forced exits, no DAC, no
rehypothecation, full (not partial) liquidation with no margin top-up,
immutable VK per instance, localStorage key custody, 256 accounts / 256
open positions, unaudited verifier crate, and the 60s/5-min timestamp/price
windows documented in DESIGN.md. Also: accounts are never evicted, so a
deposit to a fresh `pk_x` while the 256-slot tree is full can never be
consumed. Since issue #1 M5's remediation the jam is bounded, not permanent:
once the queue head has sat unconsumed for 24h, anyone may call
`refund_deposit` to return it to the original depositor and unblock the
FIFO behind it (production would still want deposit gating or zero-balance
eviction so honest deposits don't wait out the timeout).
