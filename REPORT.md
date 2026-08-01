# Feasibility Spike Report: Payments ZK-Rollup on Stellar (Noir + UltraHonk)

**Date:** 2026-07-03 · **Verdict: GO on all three questions.**

A minimal but honest payments rollup — SEP-41 custody, Poseidon2 account tree,
Grumpkin-Schnorr-signed L2 transfers, one UltraHonk proof per batch verified
on-chain via Protocol 25/26 BN254 host functions — runs end-to-end on a
Protocol 26 localnet and on **testnet** (Protocol 27):

- Batch on testnet: [`c018a0f5…`](https://stellar.expert/explorer/testnet/tx/c018a0f5786d0a7cf25356d8890197f368dfe532acc131800a4eccc40b1e9571)
  (2 deposits consumed, 1 L2 transfer, 1 L2 withdrawal paid out on L1).

## 1. Does a rollup-shaped circuit verify on-chain within budget? — YES, with huge headroom

| circuit | gates (log2) | ACIR opcodes | bb prove (M-series laptop, 12 threads) | peak RSS | on-chain verify (declared insns) | % of 400M cap |
|---|---|---|---|---|---|---|
| trivial (Poseidon2 preimage) | 2^12 | ~30 | <0.1 s | — | 78,720,984 | 19.7% |
| batch_n4 (D=2, N=4) | 2^16 | 2,250 | 0.30 s | 171 MB | 86,702,028 | 21.7% |
| batch_n16 (D=4, N=16) | 2^18 | 8,018 | 0.78 s | 747 MB | 90,511,011 | 22.6% |

Verification cost is **logarithmic in circuit size**: ~+2M instructions per
doubling. Extrapolated, even a 2^24-gate circuit (~1,000+ payments/batch)
verifies at ~103M instructions — **on-chain verification never becomes the
binding constraint** under the Protocol 26 400M cap.

Full `submit_batch` (verify + on-chain Poseidon2 fold recomputation + queue +
1 withdrawal transfer) for batch_n4: **100.5M declared instructions**, 2,600
write bytes, 7 footprint entries. Caveat: the Rust test env (native
execution) reports 67.4M for the same call — wasm metering is ~1.5× that;
always measure via simulateTransaction.

## 2. Does the single-SEP-41-token custody loop work? — YES

Deposits escrow via `token.transfer(from, contract)` + FIFO queue; the batch
proof must consume an exact queue prefix (`deposit_count` pins it — no
queue races); withdrawals are authorized solely by the proof (the contract
recomputes `withdraw_hash` from the envelope's `(dest, amount)` list via
`address_to_field`, so redirecting or reamounting a payout breaks
verification — covered by negative tests); root advances atomically.
Verified in unit tests (15 tests incl. real-proof positive + 8 adversarial
negatives) and live on localnet + testnet.

## 3. Economics — viable; the value proposition is throughput/features, not fee arbitrage

Measured on testnet (native-asset SAC):

| op | unsigned tx bytes | min resource fee | actually charged |
|---|---|---|---|
| deposit | 244 B | 0.1318 XLM | ~0.13 XLM (incl. persistent-entry rent) |
| submit_batch (n4) | 15,076 B (11.4% of the 132,096 B cap) | 0.1362 XLM | **0.1195 XLM** |

Per-batch cost is ~fixed (proof = 14,592 B of the tx; verification CPU nearly
flat), so **cost per payment ≈ 0.12 XLM / N**:

| batch size | est. fee/payment |
|---|---|
| 4 | ~0.030 XLM |
| 16 | ~0.0078 XLM |
| 256 | ~0.0005 XLM |
| ~4,000 (tx-size ceiling with ~28 B/payment DA blob) | ~0.00004 XLM |

**Honest framing:** Stellar L1 payments cost ~0.00001 XLM base fee. A rollup
on Stellar does not win on per-payment fees until batches reach thousands of
payments — the rollup's actual value is (a) throughput beyond ledger TPS
limits (~4,000 payments per submit_batch tx at the byte ceiling; the
per-ledger write budget admits ~2 such txs → order 1,000+ payments/sec), and
(b) as a substrate for features L1 can't do (privacy, custom execution).

**Which constraint binds:** neither CPU (never) nor per-tx bytes (up to
~4,000 payments). The practical scale limiter is the **prover** (memory grows
~linearly: est. several GB at 2^22 gates / ~256 payments — still
laptop-feasible) and, at high cadence, the **ledger-wide** Soroban byte/CPU
budgets shared with all other traffic.

## Toolchain verdict

nargo 1.0.0-beta.11 + bb 0.87.0 + NethermindEth/rs-soroban-ultrahonk @
`661db07` worked **without version bisection**. Notes:
- `--oracle_hash keccak` required on both `bb prove` and `bb write_vk`; the
  keccak-oracle VK is already the packed 1760-byte layout (the 1764→1760
  strip in OZ's pipeline applies only to the default oracle).
- Quickstart's `--limits testnet` preset still caps CPU at the pre-P26 100M
  and rejects submit_batch (100.5M); use `--limits unlimited` locally. Real
  testnet accepted everything.
- The verifier crate is pre-release and unaudited (pin the rev).

## Production deltas (out of spike scope, tracked)

1. **DA binding**: `txs_blob` is carried but not committed in-circuit
   (~1 Poseidon2 absorb/payment to add) — required for trustless state
   reconstruction.
2. **Forced exits / censorship resistance** (L1 escape hatch), sequencer
   permissioning/decentralization.
3. pk_x y-parity binding; deposit-overflow queue jam (a deposit pushing an L2
   balance past 2^64 can never be consumed → cap per-account deposits
   on-chain); VK rotation/upgrade path; instance-storage TTL management.
4. SAC clawback/auth-flag vetting for the custody asset.
5. Real sequencer service (mempool, persistence, recovery) — the spike
   harness is CLI-driven.
6. Third-party audit of the verifier crate before any real funds.

---

# Repo extension (Cellarium) — measurements & verdict

**Date:** 2026-07-31 · The payments validium above was extended into a
**private bilateral repo venue** (PLAN.md): multi-asset accounts (XLM cash /
tUST collateral), a position tree, bilateral opens, borrower closes with
in-circuit ACT/360 interest, permissionless maturity defaults, and
oracle-price liquidations — all inside one Noir circuit, 7 public inputs,
still one UltraHonk proof per batch. All milestones' e2e suites pass on
testnet (Protocol 27).

## Circuit cost (batch_repo, M-series laptop, 12 threads)

| circuit | shape | circuit size (gates) | ACIR opcodes | bb prove | peak RSS |
|---|---|---|---|---|---|
| batch_repo @M2 | D=4 O=2 T=4 | 90,334 (2^17 domain) | — | 0.54 s | ~380 MB |
| batch_repo @M3+ | D=4 C=2 L=2 O=2 T=4 | 132,327 (2^18 domain) | 23,644 | 0.80 s | 752 MB |
| batch_repo @issue-1 remediation | D=4 C=2 L=2 O=2 T=4 + 8th PI (instance_id) + L8/L9 range checks | 133,535 (2^18 domain) | 24,572 | 0.50 s (18 threads) | 754 MB |
| batch_repo, ZK flavor (measured for issue #1 M6; NOT deployable) | same | same | same | 0.64 s (18 threads) | 773 MB |

The ZK-flavor row exists to answer M6: proving cost is affordable (+~30%
wall, +2% RSS), but `--zk` emits a 507-field / 16,224-byte proof the pinned
ultrahonk-soroban-verifier (456 fields / 14,592 bytes, non-ZK only) cannot
verify — flipping the flavor is blocked on a ZK-capable verifier crate, not
on proving cost.

Sig-verifications dominate: T + 2·O + C = 10 Grumpkin MSM pairs per batch,
plus ~34 Merkle path updates across two depth-8 trees. Prove time stays ~4×
under the 3.5 s cadence budget; the batch sizes are const-generic parameters
and have plenty of headroom to grow (extrapolating the payments table above,
even 4× larger shapes stay within budget on deployment-class hardware).

## On-chain cost (testnet, Protocol 27)

| metric | value |
|---|---|
| submit_batch declared instructions | **108,041,218** (27% of the 400M cap) |
| native test-env measurement | 71.5M cpu insns (wasm ≈ 1.5× — matches) |
| submit_batch fee charged | **0.0248 XLM** (proof 14,592 B; write 3,152 B) |
| verify-only (native env) | ~66M insns — verification is still logarithmic |

The 7-PI upgrade (2 extra field bindings + oracle cross-contract read +
timestamp checks + second token/queue) added ~8M declared instructions over
the payments-era submit_batch. CPU remains a non-issue; the practical limits
are unchanged from the spike (prover throughput, ledger-wide budgets).

Per-op cost at the demo shape (1 open + 1 close/liq + 4 payments + 4
deposits per batch ≈ 10 ops): **~0.0025 XLM/op**, dominated by the fixed
proof bytes. As with payments, the win is privacy and features, not fees.

## What the repo e2e proves on every run (scripts/e2e_testnet.sh)

deposits/transfers/withdrawals in both assets with exact L1 payouts →
bilateral open via the counterparty-filtered intent flow → close with
interest recomputed independently and asserted **to the stroop** → maturity
watcher default crediting the lender's collateral → admin price crash →
margin watcher liquidation → under-collateralized open evicted — with
sequencer-state-root == on-chain-root asserted after every phase, DA blob
re-foldable, and replay/gap-nonce rejection.

## Security invariants (PLAN.md §3) — where each is enforced/tested

| invariant | enforcement | test |
|---|---|---|
| value conservation per asset | circuit (all ops balance) | harness prop-tests + e2e balance sums |
| no position slot collision | empty-leaf proof under the running pos root | `open_occupied_slot` circuit negative |
| both signatures to open | two verify_sig calls | `open_single_sig`, `open_terms_not_signed` |
| close only borrower, only ≤ maturity | sig + maturity range check | `close_wrong_signer`, `close_after_maturity` |
| default only past maturity | strict range check, no signature | `default_at_maturity` |
| liquidation only on breach at bound price | cross-multiplied comparison | `liquidation_fixture` healthy-price negative |
| exact interest | floor-division gadget | interest unit vectors in circuit+wallet, e2e stroop assert |
| withdrawal can't be redirected/re-amounted/re-asseted | DOMAIN_WD2 fold binds (dest, asset, amount) | contract negatives |
| fresh price required for every batch | contract staleness check (5 min) | `stale_price_rejected` |
| replay | old_state_root binding | contract replay negative + e2e |
| padding key blacklisted in every role | circuit asserts | pad negatives (both roles) |

## Verdict

The repo venue works end-to-end on testnet with the same toolchain pins as
the payments spike (no version bisection needed) and comfortable margins on
every budget. The economics conclusion from the spike stands, sharpened:
this design pays a fixed ~0.025 XLM per batch for **complete counterparty/
price/size privacy** on a public ledger — something L1 cannot offer at any
fee.
