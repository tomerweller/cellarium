# Soribium — Design Spec

Soribium is a multi-asset ZK-rollup operating as a **validium** on Stellar
testnet — being extended into a private bilateral repo venue (PLAN.md): batch
transaction data lives off-chain (served by the sequencer's DA endpoint) and
is bound on-chain by a proven commitment.

**Assets** (ids used in hashes as Field, in envelopes as u32):

| Asset id | Leg | Token | Base unit |
|---|---|---|---|
| 0 | cash | native XLM SAC | stroop |
| 1 | collateral | mock tUST (contracts/tust, pure Soroban SEP-41) | 1e-7 tUST |

Each custody token's total supply must be ≤ u64::MAX base units (XLM
natively; tUST enforces the cap in its mint).

Single source of truth for hash layouts, domains, and message formats shared by
the Noir circuits, the Soroban contract, and the Rust harness. If a constant
here changes, all three must change together (CI-less spike: grep for the
domain name).

## Toolchain (pinned)

| Tool | Version |
|---|---|
| nargo | 1.0.0-beta.11 |
| bb (Barretenberg) | 0.87.0 |
| soroban-sdk / soroban-poseidon | 26.0.0 |
| ultrahonk-soroban-verifier | NethermindEth/rs-soroban-ultrahonk @ `661db07` |
| rust | 1.88.0 (wasm32v1-none) |
| Proof flavor | UltraHonk, BN254, **Keccak transcript** (`--oracle_hash keccak` on prove AND write_vk), non-ZK, non-recursive |

Verifier invariants: proof = 456 fields = 14,592 bytes; VK = 1760 packed bytes;
public inputs = 32-byte BE canonical Fr words, count = `vk.public_inputs_size − 16`.

## Hashing

All hashes are Poseidon2 over BN254 Fr (noir-lang/poseidon v0.2.0 in-circuit ≡
`soroban_poseidon::poseidon2_hash::<4, BnScalar>` on-chain ≡ harness via `Env`).

Domain separators (Fr constants):

| Domain | Value | Use |
|---|---|---|
| `DOMAIN_LEAF` | 1 | account leaf hash |
| `DOMAIN_TX` | 2 | L2 transaction signing message |
| `DOMAIN_SIG` | 3 | Schnorr challenge |
| `DOMAIN_DEP` | 4 | *(retired in M1; replaced by DOMAIN_DEP2)* |
| `DOMAIN_WD` | 5 | *(retired in M1; replaced by DOMAIN_WD2)* |
| `DOMAIN_ADDR` | 6 | address_to_field |
| `DOMAIN_DA` | 7 | DA-blob commitment fold (validium) |
| `DOMAIN_POS` | 8 | position leaf (M2) |
| `DOMAIN_OPEN` | 9 | repo-open signing message (M2) |
| `DOMAIN_CLOSE` | 10 | repo-close signing message (M3) |
| `DOMAIN_DEP2` | 11 | deposit fold, asset-bound (M1) |
| `DOMAIN_WD2` | 12 | withdrawal fold, asset-bound (M1) |

## State

Since M2 the contract stores ONE combined root:

```
state_root = Poseidon2([account_root, position_root])
```

Genesis = both trees empty (`cargo run -p sequencer -- genesis-root`).

### Position tree (M2)

Depth 8 (256 open positions), same node/empty conventions as the account
tree. Record `{borrower_pk_x, lender_pk_x, cash u64, coll u64, rate_bps u32,
haircut_bps u32, open_ts u64, maturity_ts u64}`:

```
term_hash = Poseidon2([rate_bps, haircut_bps, open_ts, maturity_ts])
amt_hash  = Poseidon2([cash, coll])
pos_leaf  = Poseidon2([DOMAIN_POS, borrower_pk_x, lender_pk_x, Poseidon2([term_hash, amt_hash])])
```

Slot allocation is find-first-free (prover-supplied index; the circuit proves
the old leaf is 0 under the RUNNING position root, which structurally
prevents in-batch slot collisions). Closing zeroes the leaf.

### Repo close / default / liquidation (M3-M4)

Close (repay) is borrower-signed; the message binds the slot, the position
leaf (hence every term), and the borrower nonce:

```
close_msg = Poseidon2([DOMAIN_CLOSE, pos_index, pos_leaf, borrower_nonce])
```

Requires `batch_ts <= maturity_ts`. Interest is annualized ACT/360 on
seconds, floor division constrained in-circuit by product + remainder range
checks (settle.nr; the harness mirrors it in u128 and interest unit vectors
are pinned in circuit + wallet suites):

```
interest = floor(cash * rate_bps * (batch_ts - open_ts) / (10^4 * 360 * 86400))
```

Effects: borrower.cash -= cash+interest (nonce +1), lender.cash +=
cash+interest (no signature, nonce unchanged), borrower.coll += coll,
position zeroed.

Default / liquidation is PERMISSIONLESS (no signature — validity comes solely
from the condition holding at the bound batch_ts/price; the sequencer's
watcher enqueues them):

- default: `batch_ts > maturity_ts`
- liquidation: margin breach at half the initial haircut, division-free:
  `coll * price * 2*10^4 < cash * (2*10^4 + haircut_bps) * 10^7`

Effects: lender.coll += coll (title transfer), borrower keeps the cash,
position zeroed, no nonces move.

Open additionally enforces (from the same circuit revision):
`maturity_ts > batch_ts` and the open-time adequacy
`coll * price * 10^4 >= cash * (10^4 + haircut_bps) * 10^7`.

Batch application order: deposits -> closes -> defaults/liquidations ->
opens -> payments.

### Repo open (M2)

Bilateral: both parties sign

```
open_msg = Poseidon2([DOMAIN_OPEN, borrower_pk_x, lender_pk_x,
                      Poseidon2([term_hash, amt_hash, borrower_nonce, lender_nonce])])
```

`open_ts` is signer-agreed (not the batch timestamp) — every signed field is
known at signing time; bilateral consent makes arbitrary values safe. Effects:
lender.cash −= cash, borrower.cash += cash, borrower.coll −= coll, both
nonces increment, position leaf written. Collateral sits in the position
(title-transfer analog). Both signatures use the payment Schnorr scheme and
defenses (even-y, range-checked s, on-curve, PAD blacklist in both roles).
Batch order: deposits → opens → payments.

## Account tree

- Fixed depth **8** (256 accounts), parameterized in circuits and harness.
- `bal_hash = Poseidon2([cash, coll])` — cash in stroops, coll in tUST base
  units, both range-constrained to u64 in-circuit.
- Leaf = `Poseidon2([DOMAIN_LEAF, pk_x, bal_hash, nonce])`.
- Node = `Poseidon2([left, right])`.
- Empty: `zero[0] = 0`, `zero[i+1] = Poseidon2([zero[i], zero[i]])`; empty leaf = 0.
- Account key: Grumpkin public-key x-coordinate (`pk_x`). Active spends require
  **even-y** public keys (`pk_y` LSB clear): keygen flips `sk → -sk` when the
  raw point has odd y (harness `Keypair::from_sk`, wallet `canonicalizeSk`).
  This binds y-parity for spend authorization without enlarging the leaf.
- Balance range `[0, 2^64)` enforced in-circuit per asset; `i128` on-chain.
  Overflow of an L2 balance (an unprovable FIFO queue head) is prevented by a
  **deployment invariant** rather than per-key tracking: each custody token's
  total supply must be ≤ `u64::MAX` base units (native XLM: ~1.05e18 stroops,
  ~17× under; tUST enforces the cap in mint). The circuit conserves value per
  asset, so every balance ≤ escrow ≤ supply.

## L2 transaction

Signing message (asset-bound since M1):
`msg = Poseidon2([DOMAIN_TX, from_pk_x, to_field, asset, amount, nonce, is_withdraw])`
where `to_field` = recipient `pk_x` (transfer) or `address_to_field(dest)`
(withdrawal), and `asset` selects which of the two balances moves.

Schnorr over Grumpkin (hand-rolled; std::schnorr no longer exists):
- keys: `pk = sk·G` (G = Grumpkin generator via `fixed_base_scalar_mul`), even-y
- sign: nonce `k`, `R = k·G`, `e = Poseidon2([DOMAIN_SIG, R.x, pk_x, msg])`,
  `s = k + e·sk (mod Fq_grumpkin)`
- verify (circuit): `s·G == R + e·pk`, with defenses:
  - `s_lo`, `s_hi` range-checked to 128 bits; `s ≠ 0`
  - `pk` and `R` on-curve (`y^2 = x^3 - 17`) and non-infinity
  - `e` lifted via `EmbeddedCurveScalar::from_field` (safe: BN254 Fr < Grumpkin
    scalar modulus)
- **Padding keypair** (`sk=7`, published `PAD_PK_*`): used only for inactive
  batch slots. Active deposits/transfers **blacklist** `PAD_PK_X` (secret is
  public — crediting it would make funds drainable by anyone).

## Batch circuit public interface (batch_repo: D=4 C=2 L=2 O=2 T=4)

```
main(old_state_root: pub, new_state_root: pub,
     deposit_hash: pub, withdraw_hash: pub, da_commitment: pub,
     batch_ts: pub, price: pub,
     old_acct_root, old_pos_root,           // private openings of state_root
     deposits: [DepositWitness; D], closes: [CloseWitness; C],
     liqs: [LiqWitness; L], opens: [OpenWitness; O], txs: [TxWitness; T])
```

Exactly 7 public inputs (224-byte PI blob):

- `old_state_root` — contract storage.
- `new_state_root` — envelope, becomes storage after verification.
- `batch_ts` — claimed timestamp from the envelope; the contract enforces the
  one-sided window `claimed <= ledger.timestamp() <= claimed + 60` (PLAN.md
  6.1.3). Bound from M2, constrained by op logic from M3.
- `price` — tUST/XLM as XLM-per-tUST × 1e7, read by submit_batch from the
  oracle inside the same invocation; staleness > 300s rejects the batch.
  Bound from M2, constrained by margin logic from M4.
- `deposit_hash` — fold over the batch's FIFO deposit-queue prefixes, **cash
  queue first, then coll queue** (two on-chain queues since M1):
  `acc' = Poseidon2([DOMAIN_DEP2, acc, Poseidon2([pk_x, asset, amount])])`,
  `acc₀ = 0`; the envelope pins `(deposit_count_cash, deposit_count_coll)` and
  the contract recomputes over exactly those prefixes (queue-race prevention).
- `withdraw_hash` — same fold shape with `DOMAIN_WD2` over
  `Poseidon2([address_to_field(dest), asset, amount])` entries from the
  envelope.
- `da_commitment` — fold over each **active** off-chain-originated op in
  application order: closes contribute `close_msg`, defaults/liquidations
  contribute `P2([pos_index, is_liquidation])`, repo opens contribute
  `P2([open_msg, pos_index])` (binding the slot), payments contribute their
  signing message:
  `acc' = Poseidon2([DOMAIN_DA, acc, rec])` (3-input), `acc₀ = 0`. Deposits
  stay out of the fold — their data is on-chain in the queues and pinned by
  `deposit_hash`. Verifiers fetch the blob from `GET /da/:batch_num` and
  re-fold. Signatures ship in the blob as audit data but are NOT
  commitment-bound (authorization is already established by the proof).

`address_to_field` = Poseidon2 over the 56-byte strkey split into two 28-byte
limbs with `DOMAIN_ADDR` (ported from OZ confidential storage.rs).

Padding: `is_active = 0` entries freeze both the running root and the fold
accumulators. Active entries require `amount > 0`.

## Envelope (submit_batch argument)

`{ new_root: BytesN<32>, batch_ts: u64, deposit_count_cash: u32, deposit_count_coll: u32, withdrawals: Vec<Withdrawal>, da_commitment: BytesN<32>, proof: Bytes }`

`Withdrawal = { dest: Address, asset: u32, amount: i128 }`; payouts draw from
the matching custody token.

- The tx blob itself never touches the chain (validium): it is stored in the
  sequencer's SQLite and served at `GET /da/:batch_num`, bound by
  `da_commitment` (see above).
- Withdrawals executed inline, capped ≤ 8/batch.

## Batching cadence

The sequencer batches **eagerly**: on each tick (`TICK_SECS`) it fetches the
oracle price, runs the maturity/margin watcher over open positions
(enqueueing defaults/liquidations idempotently per slot), and if more than
one op (payment/open/close) is pending — or ANY default/liquidation is due —
builds+proves+submits immediately; deposit-queue-full and the
`BATCH_MAX_WAIT_SECS` timer remain as fallbacks so lone ops still settle.
The claimed `batch_ts` is set slightly behind wall-clock at build time so it
always satisfies the contract's one-sided window despite proving latency.
**Production requirement:** the pipeline must sustain Stellar's ~5s ledger
cadence — prover hardware is provisioned such that bb prove(batch_repo)
≤ ~3.5s (measured 0.80s on an M-series laptop; see REPORT.md).

## Validium trust model

Validity is trustless (every root advance is proven; PLAN §3's invariants —
bilateral opens, borrower-only closes, condition-gated defaults/liquidations,
exact interest, per-asset conservation — are all circuit-enforced). Data
availability is trusted to the sequencer operator: if the operator withholds
a blob, users cannot recompute Merkle paths for newer roots and the system
freezes (funds cannot be stolen). The mock oracle is admin-set: margining is
only as honest as its feed. Intent listings are counterparty-filtered but
unauthenticated (PLAN 6.2). Production hardening path: DAC signatures over
`da_commitment`, a real oracle (Reflector), forced exits.

## Known spike caveats (production deltas)

Tracked for REPORT.md: forced exits / censorship resistance; DA committee
over `da_commitment`; circuit-level `pk_x` uniqueness (honest builder +
harness enforce find-first; a malicious prover could still open a second slot
with the same `pk_x` without a sparse/nullifier tree); VK rotation/upgrade
path; sequencer decentralization; SAC clawback/auth-flag vetting for the
custody asset (including that it cannot mint past `u64::MAX` base units —
the balance-overflow safety argument depends on it); cross-instance proof
replay (no `addr_f` binding — old_root match makes replay a non-issue within
an instance).
