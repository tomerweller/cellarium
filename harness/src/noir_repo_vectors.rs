//! Generates `circuits/lib/src/repo_vectors.nr`: witness data for the repo
//! open circuit tests (repo_test.nr) — real Merkle paths over BOTH trees and
//! real bilateral Grumpkin Schnorr signatures.
//!
//! Regenerate: `cargo run -p harness -- noir-repo-vectors` (deterministic).

use crate::batch::{tx_message, DepositRequest, SignedTx};
use crate::keys::{sign_with_nonce, Keypair, Signature};
use crate::poseidon::{to_hex, Fr, Hasher, FR_ZERO};
use crate::repo::{
    build_repo_batch, open_message, pos_leaf, L2State, OpenEntry, OpenRequest, PosTree, Position,
};
use crate::settle::{close_message, interest, CloseEntry, CloseRequest, LiqEntry, LiqRequest};
use crate::tree::{Account, Asset, Tree, DEPTH};
use ark_grumpkin::Fr as Scalar;
use std::fmt::Write as _;

fn sibs(s: &[Fr; DEPTH]) -> String {
    let inner: Vec<String> = s.iter().map(to_hex).collect();
    format!("[{}]", inner.join(", "))
}

fn sig_lit(sig: &Signature) -> String {
    let (lo, hi) = sig.s_limbs();
    format!(
        "Signature {{ r_x: {}, r_y: {}, s_lo: {}, s_hi: {} }}",
        to_hex(&sig.r_x),
        to_hex(&sig.r_y),
        to_hex(&lo),
        to_hex(&hi)
    )
}

fn open_lit(o: &OpenEntry) -> String {
    format!(
        "OpenWitness {{\n        borrower_pk_x: {}, borrower_pk_y: {}, borrower_index: {}, borrower_cash: {}, borrower_coll: {}, borrower_nonce: {},\n        borrower_siblings: {},\n        lender_pk_x: {}, lender_pk_y: {}, lender_index: {}, lender_cash: {}, lender_coll: {}, lender_nonce: {},\n        lender_siblings: {},\n        cash: {}, coll: {}, rate_bps: {}, haircut_bps: {}, open_ts: {}, maturity_ts: {},\n        pos_index: {}, pos_old_leaf: {},\n        pos_siblings: {},\n        borrower_sig: {},\n        lender_sig: {},\n        is_active: {},\n    }}",
        to_hex(&o.borrower_pk_x), to_hex(&o.borrower_pk_y), o.borrower_index, o.borrower_cash, o.borrower_coll, o.borrower_nonce,
        sibs(&o.borrower_siblings),
        to_hex(&o.lender_pk_x), to_hex(&o.lender_pk_y), o.lender_index, o.lender_cash, o.lender_coll, o.lender_nonce,
        sibs(&o.lender_siblings),
        o.cash, o.coll, o.rate_bps, o.haircut_bps, o.open_ts, o.maturity_ts,
        o.pos_index, to_hex(&o.pos_old_leaf),
        sibs(&o.pos_siblings),
        sig_lit(&o.borrower_sig), sig_lit(&o.lender_sig),
        o.is_active as u8
    )
}

fn close_lit(c: &CloseEntry) -> String {
    let p = &c.position;
    format!(
        "CloseWitness {{\n        borrower_pk_x: {}, borrower_pk_y: {}, lender_pk_x: {},\n        cash: {}, coll: {}, rate_bps: {}, haircut_bps: {}, open_ts: {}, maturity_ts: {},\n        pos_index: {}, pos_old_leaf: {},\n        pos_siblings: {},\n        borrower_index: {}, borrower_cash: {}, borrower_coll: {}, borrower_nonce: {},\n        borrower_siblings: {},\n        lender_index: {}, lender_cash: {}, lender_coll: {}, lender_nonce: {},\n        lender_siblings: {},\n        interest: {},\n        borrower_sig: {},\n        is_active: {},\n    }}",
        to_hex(&p.borrower_pk_x), to_hex(&c.borrower_pk_y), to_hex(&p.lender_pk_x),
        p.cash, p.coll, p.rate_bps, p.haircut_bps, p.open_ts, p.maturity_ts,
        c.pos_index, to_hex(&c.pos_old_leaf), sibs(&c.pos_siblings),
        c.borrower_index, c.borrower_cash, c.borrower_coll, c.borrower_nonce,
        sibs(&c.borrower_siblings),
        c.lender_index, c.lender_cash, c.lender_coll, c.lender_nonce,
        sibs(&c.lender_siblings),
        c.interest, sig_lit(&c.sig), c.is_active as u8
    )
}

fn liq_lit(l: &LiqEntry) -> String {
    let p = &l.position;
    format!(
        "LiqWitness {{\n        borrower_pk_x: {}, lender_pk_x: {},\n        cash: {}, coll: {}, rate_bps: {}, haircut_bps: {}, open_ts: {}, maturity_ts: {},\n        pos_index: {}, pos_old_leaf: {},\n        pos_siblings: {},\n        lender_index: {}, lender_cash: {}, lender_coll: {}, lender_nonce: {},\n        lender_siblings: {},\n        is_liquidation: {}, is_active: {},\n    }}",
        to_hex(&p.borrower_pk_x), to_hex(&p.lender_pk_x),
        p.cash, p.coll, p.rate_bps, p.haircut_bps, p.open_ts, p.maturity_ts,
        l.pos_index, to_hex(&l.pos_old_leaf), sibs(&l.pos_siblings),
        l.lender_index, l.lender_cash, l.lender_coll, l.lender_nonce,
        sibs(&l.lender_siblings),
        l.is_liquidation as u8, l.is_active as u8
    )
}

/// Standard bilateral pair: alice (sk=101) lends cash, bob (sk=202) borrows
/// against coll. Terms per PLAN's flavor: 4.30% (430 bps), 2% haircut.
fn parties() -> (Keypair, Keypair) {
    (
        Keypair::from_sk(Scalar::from(101u64)),
        Keypair::from_sk(Scalar::from(202u64)),
    )
}

fn demo_position(borrower: &Keypair, lender: &Keypair) -> Position {
    Position {
        borrower_pk_x: borrower.pk_x(),
        lender_pk_x: lender.pk_x(),
        cash: 1_000_000,
        coll: 3_000_000,
        rate_bps: 430,
        haircut_bps: 200,
        open_ts: 1_700_000_000,
        maturity_ts: 1_700_000_000 + 86_400,
    }
}

#[allow(clippy::too_many_arguments)]
fn signed_open(
    hasher: &Hasher,
    p: &Position,
    borrower: &Keypair,
    lender: &Keypair,
    b_nonce: u64,
    l_nonce: u64,
    kb: u64,
    kl: u64,
) -> OpenRequest {
    let msg = open_message(hasher, p, b_nonce, l_nonce);
    OpenRequest {
        position: p.clone(),
        borrower_pk_y: borrower.pk_y(),
        lender_pk_y: lender.pk_y(),
        borrower_nonce: b_nonce,
        lender_nonce: l_nonce,
        borrower_sig: sign_with_nonce(hasher, borrower, msg, Scalar::from(kb)),
        lender_sig: sign_with_nonce(hasher, lender, msg, Scalar::from(kl)),
    }
}

pub fn emit() -> String {
    let hasher = Hasher::new();
    let mut out = String::new();
    let (lender, borrower) = parties(); // alice lends, bob borrows

    writeln!(
        out,
        "// GENERATED by `cargo run -p harness -- noir-repo-vectors` - DO NOT EDIT."
    )
    .unwrap();
    writeln!(
        out,
        "// Repo-open witness fixtures for repo_test.nr; bilateral signatures and"
    )
    .unwrap();
    writeln!(
        out,
        "// two-tree Merkle paths come from the harness (vector-gated)."
    )
    .unwrap();
    writeln!(out, "use crate::repo::OpenWitness;").unwrap();
    writeln!(out, "use crate::schnorr::Signature;").unwrap();
    writeln!(out, "use crate::settle::{{CloseWitness, LiqWitness}};").unwrap();
    writeln!(out, "use crate::tx::{{DepositWitness, TxWitness}};\n").unwrap();

    // --- Scenario R: full batch_repo<2,1,2> over a fresh state ---
    // deposits: lender 10_000_000 cash, borrower 5_000_000 coll;
    // open: 1_000_000 cash vs 3_000_000 coll @430bps, 2% haircut, 1 day;
    // payments: lender -> borrower 250_000 cash (nonce 1, post-open),
    //           borrower coll withdrawal 100_000 (nonce 1, post-open).
    {
        let mut state = L2State::new();
        let deposits = vec![
            DepositRequest {
                pk_x: lender.pk_x(),
                asset: Asset::Cash,
                amount: 10_000_000,
            },
            DepositRequest {
                pk_x: borrower.pk_x(),
                asset: Asset::Coll,
                amount: 5_000_000,
            },
        ];
        let p = demo_position(&borrower, &lender);
        let open = signed_open(&hasher, &p, &borrower, &lender, 0, 0, 2101, 2102);
        let wd_field = crate::poseidon::fr_from_u64(770_007);
        let txs = vec![
            {
                let msg = tx_message(
                    &hasher,
                    lender.pk_x(),
                    borrower.pk_x(),
                    Asset::Cash,
                    250_000,
                    1,
                    false,
                );
                SignedTx {
                    from_pk_x: lender.pk_x(),
                    from_pk_y: lender.pk_y(),
                    to_field: borrower.pk_x(),
                    asset: Asset::Cash,
                    amount: 250_000,
                    nonce: 1,
                    is_withdraw: false,
                    sig: sign_with_nonce(&hasher, &lender, msg, Scalar::from(2103u64)),
                }
            },
            {
                let msg = tx_message(
                    &hasher,
                    borrower.pk_x(),
                    wd_field,
                    Asset::Coll,
                    100_000,
                    1,
                    true,
                );
                SignedTx {
                    from_pk_x: borrower.pk_x(),
                    from_pk_y: borrower.pk_y(),
                    to_field: wd_field,
                    asset: Asset::Coll,
                    amount: 100_000,
                    nonce: 1,
                    is_withdraw: true,
                    sig: sign_with_nonce(&hasher, &borrower, msg, Scalar::from(2104u64)),
                }
            },
        ];
        let w = build_repo_batch(
            &hasher,
            &mut state,
            (2, 1, 1, 1, 2),
            &deposits,
            &[],
            &[],
            &[open],
            &txs,
            1_700_000_100,
            250_000_000,
        )
        .expect("scenario R must build");

        writeln!(
            out,
            "/// Scenario R: deposits (lender cash, borrower coll), one bilateral open,"
        )
        .unwrap();
        writeln!(
            out,
            "/// then a cash transfer + coll withdrawal. Returns the 7 public inputs,"
        )
        .unwrap();
        writeln!(
            out,
            "/// the private root openings, then the witness arrays."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn batch_r() -> ([Field; 7], [Field; 2], [DepositWitness; 2], [CloseWitness; 1], [LiqWitness; 1], [OpenWitness; 1], [TxWitness; 2]) {{\n    let pis = [{}, {}, {}, {}, {}, {}, {}];\n    let roots = [{}, {}];",
            to_hex(&w.old_state_root),
            to_hex(&w.new_state_root),
            to_hex(&w.deposit_hash),
            to_hex(&w.withdraw_hash),
            to_hex(&w.da_commitment),
            w.batch_ts,
            w.price,
            to_hex(&w.old_acct_root),
            to_hex(&w.old_pos_root),
        )
        .unwrap();
        let deps: Vec<String> = w
            .deposits
            .iter()
            .map(|d| {
                format!(
                    "DepositWitness {{\n        pk_x: {}, asset: {}, amount: {}, index: {}, old_pk_x: {}, old_cash: {}, old_coll: {}, old_nonce: {},\n        siblings: {},\n        is_active: {},\n    }}",
                    to_hex(&d.pk_x), d.asset as u32, d.amount, d.index, to_hex(&d.old_pk_x), d.old_cash, d.old_coll, d.old_nonce, sibs(&d.siblings), d.is_active as u8
                )
            })
            .collect();
        writeln!(out, "    let deps = [{}];", deps.join(", ")).unwrap();
        let closes: Vec<String> = w.closes.iter().map(close_lit).collect();
        writeln!(out, "    let closes = [{}];", closes.join(", ")).unwrap();
        let liqs: Vec<String> = w.liqs.iter().map(liq_lit).collect();
        writeln!(out, "    let liqs = [{}];", liqs.join(", ")).unwrap();
        let opens: Vec<String> = w.opens.iter().map(open_lit).collect();
        writeln!(out, "    let opens = [{}];", opens.join(", ")).unwrap();
        let txs_lit: Vec<String> = w
            .txs
            .iter()
            .map(|t| {
                format!(
                    "TxWitness {{\n        from_pk_x: {}, from_pk_y: {}, from_index: {}, from_cash: {}, from_coll: {}, from_nonce: {},\n        from_siblings: {},\n        to_field: {}, to_index: {}, to_cash: {}, to_coll: {}, to_nonce: {},\n        to_siblings: {},\n        asset: {}, amount: {}, is_withdraw: {}, is_active: {},\n        sig: {},\n    }}",
                    to_hex(&t.from_pk_x), to_hex(&t.from_pk_y), t.from_index, t.from_cash, t.from_coll, t.from_nonce,
                    sibs(&t.from_siblings),
                    to_hex(&t.to_field), t.to_index, to_hex(&t.to_cash_or_leaf), t.to_coll, t.to_nonce,
                    sibs(&t.to_siblings),
                    t.asset as u32, t.amount, t.is_withdraw as u8, t.is_active as u8, sig_lit(&t.sig)
                )
            })
            .collect();
        writeln!(out, "    let txs = [{}];", txs_lit.join(", ")).unwrap();
        writeln!(
            out,
            "    (pis, roots, deps, closes, liqs, opens, txs)\n}}\n"
        )
        .unwrap();
    }

    // --- Adversarial open fixtures over a funded 2-account state ---
    // Each returns (acct_root, pos_root, OpenWitness); all constraints hold
    // EXCEPT the named guard.
    let funded_state = || {
        let mut s = L2State::new();
        s.accounts.set(
            0,
            Account {
                pk_x: lender.pk_x(),
                cash: 10_000_000,
                coll: 0,
                nonce: 0,
            },
        );
        s.accounts.set(
            1,
            Account {
                pk_x: borrower.pk_x(),
                cash: 0,
                coll: 5_000_000,
                nonce: 0,
            },
        );
        s
    };

    // Helper to hand-build an OpenWitness against a state without mutating it.
    let manual_entry = |state: &L2State,
                        p: &Position,
                        req: &OpenRequest,
                        pos_index: u32,
                        pos_old_leaf: Fr|
     -> OpenEntry {
        let b_idx = state.accounts.find(&p.borrower_pk_x).unwrap();
        let l_idx = state.accounts.find(&p.lender_pk_x).unwrap();
        let b = state.accounts.get(b_idx).cloned().unwrap();
        let l = state.accounts.get(l_idx).cloned().unwrap();
        let (b_sibs, _) = state.accounts.path(&hasher, b_idx);
        // Lender witness must be against the POST-borrower-update tree.
        let mut mid = L2State {
            accounts: crate::tree::Tree {
                leaves: state.accounts.leaves.clone(),
            },
            positions: PosTree {
                slots: state.positions.slots.clone(),
            },
        };
        mid.accounts.set(
            b_idx,
            Account {
                pk_x: p.borrower_pk_x,
                cash: b.cash + p.cash,
                coll: b.coll.wrapping_sub(p.coll),
                nonce: b.nonce + 1,
            },
        );
        let (l_sibs, _) = mid.accounts.path(&hasher, l_idx);
        let pos_sibs = state.positions.path(&hasher, pos_index);
        OpenEntry {
            borrower_pk_x: p.borrower_pk_x,
            borrower_pk_y: req.borrower_pk_y,
            borrower_index: b_idx,
            borrower_cash: b.cash,
            borrower_coll: b.coll,
            borrower_nonce: req.borrower_nonce,
            borrower_siblings: b_sibs,
            lender_pk_x: p.lender_pk_x,
            lender_pk_y: req.lender_pk_y,
            lender_index: l_idx,
            lender_cash: l.cash,
            lender_coll: l.coll,
            lender_nonce: req.lender_nonce,
            lender_siblings: l_sibs,
            cash: p.cash,
            coll: p.coll,
            rate_bps: p.rate_bps,
            haircut_bps: p.haircut_bps,
            open_ts: p.open_ts,
            maturity_ts: p.maturity_ts,
            pos_index,
            pos_old_leaf,
            pos_siblings: pos_sibs,
            borrower_sig: req.borrower_sig.clone(),
            lender_sig: req.lender_sig.clone(),
            is_active: true,
        }
    };

    // (1) Single signature: lender countersign missing (borrower's sig in
    // both slots). Everything else valid.
    {
        let state = funded_state();
        let p = demo_position(&borrower, &lender);
        let mut req = signed_open(&hasher, &p, &borrower, &lender, 0, 0, 3101, 3102);
        req.lender_sig = req.borrower_sig.clone();
        let e = manual_entry(&state, &p, &req, 0, FR_ZERO);
        writeln!(
            out,
            "/// Open with the borrower's signature in BOTH slots (lender never"
        )
        .unwrap();
        writeln!(
            out,
            "/// countersigned): only the lender signature check rejects."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn open_single_sig() -> (Field, Field, OpenWitness) {{\n    let w = {};\n    ({}, {}, w)\n}}\n",
            open_lit(&e),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (2) Occupied slot: slot 0 already holds a position; witness honestly
    // carries its leaf (inclusion passes) — only the emptiness guard rejects.
    {
        let mut state = funded_state();
        let existing = Position {
            borrower_pk_x: borrower.pk_x(),
            lender_pk_x: lender.pk_x(),
            cash: 7,
            coll: 8,
            rate_bps: 1,
            haircut_bps: 1,
            open_ts: 1,
            maturity_ts: 2,
        };
        state.positions.set(0, existing.clone());
        let p = demo_position(&borrower, &lender);
        let req = signed_open(&hasher, &p, &borrower, &lender, 0, 0, 3201, 3202);
        let e = manual_entry(&state, &p, &req, 0, pos_leaf(&hasher, &existing));
        writeln!(
            out,
            "/// Open targeting an OCCUPIED slot with an honest inclusion proof of the"
        )
        .unwrap();
        writeln!(
            out,
            "/// existing leaf: only the pos_old_leaf == 0 guard rejects."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn open_occupied_slot() -> (Field, Field, OpenWitness) {{\n    let w = {};\n    ({}, {}, w)\n}}\n",
            open_lit(&e),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (3) Lender cash overdraft: cash amount exceeds lender balance; both
    // signatures valid, only the u64 range check on the debit rejects.
    {
        let state = funded_state();
        let mut p = demo_position(&borrower, &lender);
        p.cash = 20_000_000; // lender has 10_000_000
        let req = signed_open(&hasher, &p, &borrower, &lender, 0, 0, 3301, 3302);
        let e = manual_entry(&state, &p, &req, 0, FR_ZERO);
        writeln!(
            out,
            "/// Open whose cash leg exceeds the lender's balance (signed by both!):"
        )
        .unwrap();
        writeln!(
            out,
            "/// only the 64-bit range check on the lender debit rejects."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn open_lender_overdraft() -> (Field, Field, OpenWitness) {{\n    let w = {};\n    ({}, {}, w)\n}}\n",
            open_lit(&e),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (4) Borrower coll overdraft.
    {
        let state = funded_state();
        let mut p = demo_position(&borrower, &lender);
        p.coll = 6_000_000; // borrower has 5_000_000
        let req = signed_open(&hasher, &p, &borrower, &lender, 0, 0, 3401, 3402);
        let e = manual_entry(&state, &p, &req, 0, FR_ZERO);
        writeln!(
            out,
            "/// Open whose coll leg exceeds the borrower's balance: only the 64-bit"
        )
        .unwrap();
        writeln!(out, "/// range check on the collateral debit rejects.").unwrap();
        writeln!(
            out,
            "pub fn open_coll_overdraft() -> (Field, Field, OpenWitness) {{\n    let w = {};\n    ({}, {}, w)\n}}\n",
            open_lit(&e),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (5) Unsigned term mutation: signatures cover 430 bps; witness claims
    // 999 bps. Only the signature binding of term_hash rejects.
    {
        let state = funded_state();
        let p = demo_position(&borrower, &lender);
        let req = signed_open(&hasher, &p, &borrower, &lender, 0, 0, 3501, 3502);
        let mut p2 = p.clone();
        p2.rate_bps = 999;
        let e = manual_entry(&state, &p2, &req, 0, FR_ZERO);
        writeln!(
            out,
            "/// Witness rate_bps differs from the signed terms: the in-circuit"
        )
        .unwrap();
        writeln!(
            out,
            "/// open message diverges and both signature checks fail."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn open_terms_not_signed() -> (Field, Field, OpenWitness) {{\n    let w = {};\n    ({}, {}, w)\n}}\n",
            open_lit(&e),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (5b) Future-dated open_ts (issue #1 M4): both signatures valid over the
    // future terms, adequacy holds, maturity > both timestamps — only the
    // open_ts <= batch_ts guard rejects (batch_ts in tests is 1700000100).
    {
        let state = funded_state();
        let mut p = demo_position(&borrower, &lender);
        p.open_ts = 1_700_000_200;
        let req = signed_open(&hasher, &p, &borrower, &lender, 0, 0, 3551, 3552);
        let e = manual_entry(&state, &p, &req, 0, FR_ZERO);
        writeln!(
            out,
            "/// Open whose signed open_ts postdates the batch (issue #1 M4): only the"
        )
        .unwrap();
        writeln!(
            out,
            "/// open_ts <= batch_ts guard rejects (else the close-side elapsed underflows)."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn open_future_ts() -> (Field, Field, OpenWitness) {{\n    let w = {};\n    ({}, {}, w)\n}}\n",
            open_lit(&e),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (6) Inactive (padding) open over a state with one live position:
    // identity on both trees.
    {
        let mut state = funded_state();
        state.positions.set(0, demo_position(&borrower, &lender));
        let entry = {
            // Reuse the builder's padding shape via a zero-slot manual pad.
            let slot0 = state.accounts.get(0).cloned().unwrap();
            let (acct_sibs, _) = state.accounts.path(&hasher, 0);
            let pos_old_leaf = PosTree::leaf_value(&hasher, state.positions.get(0));
            let pos_sibs = state.positions.path(&hasher, 0);
            let pad_sig = crate::keys::pad_signature(&hasher);
            OpenEntry {
                borrower_pk_x: slot0.pk_x,
                borrower_pk_y: FR_ZERO,
                borrower_index: 0,
                borrower_cash: slot0.cash,
                borrower_coll: slot0.coll,
                borrower_nonce: slot0.nonce,
                borrower_siblings: acct_sibs,
                lender_pk_x: slot0.pk_x,
                lender_pk_y: FR_ZERO,
                lender_index: 0,
                lender_cash: slot0.cash,
                lender_coll: slot0.coll,
                lender_nonce: slot0.nonce,
                lender_siblings: acct_sibs,
                cash: 0,
                coll: 0,
                rate_bps: 0,
                haircut_bps: 0,
                open_ts: 0,
                maturity_ts: 0,
                pos_index: 0,
                pos_old_leaf,
                pos_siblings: pos_sibs,
                borrower_sig: pad_sig.clone(),
                lender_sig: pad_sig,
                is_active: false,
            }
        };
        writeln!(
            out,
            "/// Inactive (padding) open over a state with a live position at slot 0:"
        )
        .unwrap();
        writeln!(
            out,
            "/// apply_open must leave both roots and the DA accumulator unchanged."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn open_inactive() -> (Field, Field, OpenWitness) {{\n    let w = {};\n    ({}, {}, w)\n}}\n",
            open_lit(&entry),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    out
}

/// Generates `circuits/lib/src/settle_vectors.nr`: close/default/liquidation
/// fixtures + interest unit vectors (PLAN.md 1.4 / M3-M4).
pub fn emit_settle() -> String {
    let hasher = Hasher::new();
    let mut out = String::new();
    let (lender, borrower) = parties();

    writeln!(
        out,
        "// GENERATED by `cargo run -p harness -- noir-repo-vectors` - DO NOT EDIT."
    )
    .unwrap();
    writeln!(
        out,
        "// Close/default/liquidation fixtures for settle_test.nr."
    )
    .unwrap();
    writeln!(out, "use crate::repo::OpenWitness;").unwrap();
    writeln!(out, "use crate::schnorr::Signature;").unwrap();
    writeln!(out, "use crate::settle::{{CloseWitness, LiqWitness}};\n").unwrap();

    // A funded two-account state with the demo position live at slot 0.
    // Position: bob borrowed 1_000_000 cash from alice vs 3_000_000 coll,
    // 430 bps, 2% haircut, open 1_700_000_000, maturity +1 day.
    let base_state = || {
        let mut s = L2State::new();
        s.accounts.set(
            0,
            Account {
                pk_x: lender.pk_x(),
                cash: 9_000_000,
                coll: 0,
                nonce: 1,
            },
        );
        s.accounts.set(
            1,
            Account {
                pk_x: borrower.pk_x(),
                cash: 1_100_000,
                coll: 2_000_000,
                nonce: 1,
            },
        );
        s.positions.set(0, demo_position(&borrower, &lender));
        s
    };

    let clone_state = |s: &L2State| L2State {
        accounts: Tree {
            leaves: s.accounts.leaves.clone(),
        },
        positions: PosTree {
            slots: s.positions.slots.clone(),
        },
    };

    // Signed close request over the live position at slot 0 (nonce 1).
    let close_req = |k: u64| {
        let p = demo_position(&borrower, &lender);
        let msg = close_message(&hasher, 0, &p, 1);
        CloseRequest {
            pos_index: 0,
            borrower_pk_y: borrower.pk_y(),
            borrower_nonce: 1,
            sig: sign_with_nonce(&hasher, &borrower, msg, Scalar::from(k)),
        }
    };

    // (1) Happy close 6 hours in: expected roots computed by the harness.
    {
        let ts = 1_700_000_000 + 21_600;
        let mut state = base_state();
        let pre_acct = state.accounts.root(&hasher);
        let pre_pos = state.positions.root(&hasher);
        let mut da = FR_ZERO;
        let entry =
            crate::settle::apply_close(&hasher, &mut state, 0, &close_req(4101), ts, &mut da)
                .expect("happy close must apply");
        writeln!(
            out,
            "/// Happy close 6h in (interest = {} stroops on 1_000_000 at 430 bps).",
            entry.interest
        )
        .unwrap();
        writeln!(
            out,
            "/// Returns (pre_acct, pre_pos, batch_ts, post_acct, post_pos, w)."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn close_happy() -> (Field, Field, Field, Field, Field, CloseWitness) {{\n    let w = {};\n    ({}, {}, {}, {}, {}, w)\n}}\n",
            close_lit(&entry),
            to_hex(&pre_acct),
            to_hex(&pre_pos),
            ts,
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (2) Close after maturity: witness identical, batch_ts past maturity.
    // Only the maturity_ts - batch_ts range check can reject.
    {
        let ts = 1_700_086_400 + 61;
        let mut probe = base_state();
        let mut da = FR_ZERO;
        // Build the witness at a VALID ts, then present it with the late ts:
        // interest is recomputed for the late ts so the ONLY failing guard is
        // the time check.
        let entry = crate::settle::apply_close(
            &hasher,
            &mut probe,
            0,
            &close_req(4201),
            1_700_086_400,
            &mut da,
        )
        .expect("close at maturity applies");
        let mut entry_late = entry.clone();
        entry_late.interest = interest(1_000_000, 430, ts - 1_700_000_000).unwrap();
        let state = base_state();
        writeln!(
            out,
            "/// Close presented PAST maturity (interest consistent for the late ts,"
        )
        .unwrap();
        writeln!(
            out,
            "/// signature valid): only batch_ts <= maturity_ts rejects. NOTE: the"
        )
        .unwrap();
        writeln!(
            out,
            "/// close message binds the leaf, not batch_ts, so the sig still passes."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn close_after_maturity() -> (Field, Field, Field, CloseWitness) {{\n    let w = {};\n    ({}, {}, {}, w)\n}}\n",
            close_lit(&entry_late),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
            ts,
        )
        .unwrap();
    }

    // (3) Close signed by the LENDER (only the borrower may close).
    {
        let ts = 1_700_000_000 + 21_600;
        let p = demo_position(&borrower, &lender);
        let msg = close_message(&hasher, 0, &p, 1);
        let mut probe = base_state();
        let mut da = FR_ZERO;
        let mut entry =
            crate::settle::apply_close(&hasher, &mut probe, 0, &close_req(4301), ts, &mut da)
                .expect("template close applies");
        entry.sig = sign_with_nonce(&hasher, &lender, msg, Scalar::from(4302u64));
        // Keep borrower pk in the witness: the sig simply doesn't verify.
        let state = base_state();
        writeln!(
            out,
            "/// Close signed by the LENDER over the correct message: the borrower"
        )
        .unwrap();
        writeln!(out, "/// signature check is the only guard that rejects.").unwrap();
        writeln!(
            out,
            "pub fn close_wrong_signer() -> (Field, Field, Field, CloseWitness) {{\n    let w = {};\n    ({}, {}, {}, w)\n}}\n",
            close_lit(&entry),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
            ts,
        )
        .unwrap();
    }

    // (4) Interest off by one (floor-division constraint rejects); balances
    // adjusted consistently so ONLY the interest constraint fails.
    {
        let ts = 1_700_000_000 + 21_600;
        let mut probe = base_state();
        let mut da = FR_ZERO;
        let entry =
            crate::settle::apply_close(&hasher, &mut probe, 0, &close_req(4401), ts, &mut da)
                .expect("template close applies");
        let mut bad = entry.clone();
        bad.interest = entry.interest + 1;
        let state = base_state();
        writeln!(
            out,
            "/// Interest witness off by one: the floor-division remainder range"
        )
        .unwrap();
        writeln!(out, "/// check is the only guard that rejects.").unwrap();
        writeln!(
            out,
            "pub fn close_wrong_interest() -> (Field, Field, Field, CloseWitness) {{\n    let w = {};\n    ({}, {}, {}, w)\n}}\n",
            close_lit(&bad),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
            ts,
        )
        .unwrap();
    }

    // (5) Happy default (past maturity) with expected post-roots.
    {
        let ts = 1_700_086_400 + 61;
        let mut state = base_state();
        let pre_acct = state.accounts.root(&hasher);
        let pre_pos = state.positions.root(&hasher);
        let mut da = FR_ZERO;
        let entry = crate::settle::apply_liq(
            &hasher,
            &mut state,
            0,
            &LiqRequest {
                pos_index: 0,
                is_liquidation: false,
            },
            ts,
            250_000_000,
            &mut da,
        )
        .expect("default must apply");
        writeln!(
            out,
            "/// Happy default past maturity: lender takes the collateral."
        )
        .unwrap();
        writeln!(
            out,
            "/// Returns (pre_acct, pre_pos, batch_ts, post_acct, post_pos, w)."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn default_happy() -> (Field, Field, Field, Field, Field, LiqWitness) {{\n    let w = {};\n    ({}, {}, {}, {}, {}, w)\n}}\n",
            liq_lit(&entry),
            to_hex(&pre_acct),
            to_hex(&pre_pos),
            ts,
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (6) Default BEFORE maturity (same witness, early ts): time guard only.
    {
        let ts_late = 1_700_086_400 + 61;
        let ts_early = 1_700_086_400; // == maturity: default requires strictly past
        let mut probe = base_state();
        let mut da = FR_ZERO;
        let entry = crate::settle::apply_liq(
            &hasher,
            &mut probe,
            0,
            &LiqRequest {
                pos_index: 0,
                is_liquidation: false,
            },
            ts_late,
            250_000_000,
            &mut da,
        )
        .expect("template default applies");
        let state = base_state();
        writeln!(
            out,
            "/// Default presented AT maturity (must be strictly past): only the"
        )
        .unwrap();
        writeln!(out, "/// batch_ts > maturity_ts check rejects.").unwrap();
        writeln!(
            out,
            "pub fn default_at_maturity() -> (Field, Field, Field, LiqWitness) {{\n    let w = {};\n    ({}, {}, {}, w)\n}}\n",
            liq_lit(&entry),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
            ts_early,
        )
        .unwrap();
    }

    // (7) Liquidation on margin breach (price collapsed) + healthy negative.
    {
        let ts = 1_700_000_000 + 3_600; // well before maturity
                                        // Breach price: need coll*price*2e4 < cash*(2e4+200)*1e7
                                        //  3e6 * price * 2e4 < 1e6 * 20200 * 1e7  =>  price < 3.3667e6.
        let breach_price = 3_000_000u64;
        let healthy_price = 250_000_000u64;
        let mut state = base_state();
        let pre_acct = state.accounts.root(&hasher);
        let pre_pos = state.positions.root(&hasher);
        let mut da = FR_ZERO;
        let entry = crate::settle::apply_liq(
            &hasher,
            &mut state,
            0,
            &LiqRequest {
                pos_index: 0,
                is_liquidation: true,
            },
            ts,
            breach_price,
            &mut da,
        )
        .expect("liquidation must apply at the breach price");
        writeln!(
            out,
            "/// Liquidation at a collapsed price (margin breached) with expected"
        )
        .unwrap();
        writeln!(
            out,
            "/// post-roots; the same witness at the HEALTHY price must fail."
        )
        .unwrap();
        writeln!(out, "/// Returns (pre_acct, pre_pos, batch_ts, breach_price, healthy_price, post_acct, post_pos, w).").unwrap();
        writeln!(
            out,
            "pub fn liquidation_fixture() -> (Field, Field, Field, Field, Field, Field, Field, LiqWitness) {{\n    let w = {};\n    ({}, {}, {}, {}, {}, {}, {}, w)\n}}\n",
            liq_lit(&entry),
            to_hex(&pre_acct),
            to_hex(&pre_pos),
            ts,
            breach_price,
            healthy_price,
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
        )
        .unwrap();
    }

    // (8) Under-collateralized open (adequacy guard, M4): coll value at the
    // batch price below cash * (1 + haircut).
    {
        let state = {
            let mut s = L2State::new();
            s.accounts.set(
                0,
                Account {
                    pk_x: lender.pk_x(),
                    cash: 10_000_000,
                    coll: 0,
                    nonce: 0,
                },
            );
            s.accounts.set(
                1,
                Account {
                    pk_x: borrower.pk_x(),
                    cash: 0,
                    coll: 5_000_000,
                    nonce: 0,
                },
            );
            s
        };
        let p = demo_position(&borrower, &lender);
        let req = signed_open(&hasher, &p, &borrower, &lender, 0, 0, 4801, 4802);
        // price such that 3e6 * price * 1e4 < 1e6 * 10200 * 1e7 => price < 3.4e6.
        let low_price = 3_000_000u64;
        // Build the full witness by hand against the state (sigs valid, slot
        // empty) - only the adequacy check can reject at low_price.
        let b_idx = 1u32;
        let l_idx = 0u32;
        let b = state.accounts.get(b_idx).cloned().unwrap();
        let l = state.accounts.get(l_idx).cloned().unwrap();
        let (b_sibs, _) = state.accounts.path(&hasher, b_idx);
        let mut mid = clone_state(&state);
        mid.accounts.set(
            b_idx,
            Account {
                pk_x: p.borrower_pk_x,
                cash: b.cash + p.cash,
                coll: b.coll - p.coll,
                nonce: b.nonce + 1,
            },
        );
        let (l_sibs, _) = mid.accounts.path(&hasher, l_idx);
        let pos_sibs = state.positions.path(&hasher, 0);
        let entry = OpenEntry {
            borrower_pk_x: p.borrower_pk_x,
            borrower_pk_y: req.borrower_pk_y,
            borrower_index: b_idx,
            borrower_cash: b.cash,
            borrower_coll: b.coll,
            borrower_nonce: 0,
            borrower_siblings: b_sibs,
            lender_pk_x: p.lender_pk_x,
            lender_pk_y: req.lender_pk_y,
            lender_index: l_idx,
            lender_cash: l.cash,
            lender_coll: l.coll,
            lender_nonce: 0,
            lender_siblings: l_sibs,
            cash: p.cash,
            coll: p.coll,
            rate_bps: p.rate_bps,
            haircut_bps: p.haircut_bps,
            open_ts: p.open_ts,
            maturity_ts: p.maturity_ts,
            pos_index: 0,
            pos_old_leaf: FR_ZERO,
            pos_siblings: pos_sibs,
            borrower_sig: req.borrower_sig.clone(),
            lender_sig: req.lender_sig.clone(),
            is_active: true,
        };
        writeln!(
            out,
            "/// Fully signed open that is UNDER-collateralized at the low price and"
        )
        .unwrap();
        writeln!(
            out,
            "/// adequately collateralized at the high price (adequacy guard, M4)."
        )
        .unwrap();
        writeln!(
            out,
            "/// Returns (acct_root, pos_root, batch_ts, low_price, ok_price, w)."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn open_undercollateralized() -> (Field, Field, Field, Field, Field, OpenWitness) {{\n    let w = {};\n    ({}, {}, {}, {}, {}, w)\n}}\n",
            open_lit(&entry),
            to_hex(&state.accounts.root(&hasher)),
            to_hex(&state.positions.root(&hasher)),
            1_700_000_100u64,
            low_price,
            250_000_000u64,
        )
        .unwrap();
    }

    // (9) Interest unit vectors (PLAN.md 1.4): zero-elapsed; one day at
    // 4.30% on a $10M-equivalent cash leg (1e14 stroops at $0.10/XLM);
    // max-term boundary (365 days).
    {
        let cases: Vec<(u64, u32, u64)> = vec![
            (1_000_000, 430, 0),
            (100_000_000_000_000, 430, 86_400),
            (1_000_000_000, 1_250, 31_536_000),
            (1, 1, 1),
        ];
        writeln!(
            out,
            "/// Interest unit vectors: (cash, rate_bps, elapsed, expected_interest)."
        )
        .unwrap();
        writeln!(
            out,
            "pub fn interest_vectors() -> [(Field, Field, Field, Field); {}] {{",
            cases.len()
        )
        .unwrap();
        let lits: Vec<String> = cases
            .iter()
            .map(|(c, r, e)| format!("({}, {}, {}, {})", c, r, e, interest(*c, *r, *e).unwrap()))
            .collect();
        writeln!(out, "    [{}]", lits.join(", ")).unwrap();
        writeln!(out, "}}").unwrap();
    }

    out
}
