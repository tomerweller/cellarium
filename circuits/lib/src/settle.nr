// Repo settlement ops (M3/M4): borrower-signed CLOSE (repay with interest)
// and permissionless DEFAULT / LIQUIDATION (mode flag), plus the interest
// floor-division gadget (PLAN.md 1.3-1.4).
//
// Close (repay), borrower-signed. Message binds the slot, the position leaf
// (hence every term), and the borrower nonce:
//   close_msg = P2([DOMAIN_CLOSE, pos_index, pos_leaf, borrower_nonce], 4)
// Requires batch_ts <= maturity_ts. Interest is ACT/360 on seconds:
//   interest = floor(cash * rate_bps * (batch_ts - open_ts) / DENOM),
//   DENOM = 10^4 * 360 * 86400
// Effects: borrower.cash -= cash+interest, borrower.coll += coll, borrower
// nonce += 1; lender.cash += cash+interest (no lender signature: they only
// gain, and their nonce does NOT move); position zeroed.
//
// Default/liquidation, permissionless (no signature; the sequencer includes
// it when the condition holds at the bound batch_ts/price):
//   default (is_liquidation = 0):  batch_ts > maturity_ts
//   liquidation (is_liquidation = 1): margin breach at half the initial
//   haircut, division-free (PLAN.md 6.1.1):
//     coll * price * 2*10^4  <  cash * (2*10^4 + haircut_bps) * 10^7
// Effects: lender.coll += coll (title transfer of the collateral), borrower
// keeps the cash, position zeroed. No nonces move (no signatures).
use crate::account::{leaf_value, Account};
use crate::merkle::{update_root, DEPTH};
use crate::repo::{amt_hash, pos_leaf, term_hash, DOMAIN_CLOSE};
use crate::schnorr::{is_even_y, verify_sig, Signature};
use crate::tx::{
    assert_u64, select, DOMAIN_DA, PAD_MSG, PAD_PK_X, PAD_PK_Y, PAD_R_X, PAD_R_Y, PAD_S_HI,
    PAD_S_LO,
};
use dep::poseidon::poseidon2::Poseidon2;

// 10^4 * 360 * 86400 (bps scale x ACT/360 year in seconds).
pub global INTEREST_DENOM: Field = 311040000000;

fn assert_u32(v: Field) {
    let _: [u1; 32] = v.to_le_bits();
}

fn assert_u39(v: Field) {
    let _: [u1; 39] = v.to_le_bits();
}

/// Range-check helper for the margin comparison: values < 2^144.
fn assert_u144(v: Field) {
    let _: [u1; 144] = v.to_le_bits();
}

/// Constrain `interest = floor(cash * rate_bps * elapsed / INTEREST_DENOM)`.
/// All inputs already range-checked (cash u64, rate u32, elapsed u64), so the
/// product fits 160 bits << Fr. The witness supplies interest; we bind it
/// with product + remainder range checks (remainder < DENOM < 2^39).
pub fn constrain_interest(cash: Field, rate_bps: Field, elapsed: Field, interest: Field) {
    assert_u64(interest);
    let product = cash * rate_bps * elapsed;
    let remainder = product - interest * INTEREST_DENOM;
    assert_u39(remainder);
    // remainder < DENOM (u39 alone allows up to 2^39-1 > DENOM-1).
    assert_u39(INTEREST_DENOM - 1 - remainder);
}

pub struct CloseWitness {
    // The open position being repaid (full record; leaf recomputed).
    pub borrower_pk_x: Field,
    pub borrower_pk_y: Field,
    pub lender_pk_x: Field,
    pub cash: Field,
    pub coll: Field,
    pub rate_bps: Field,
    pub haircut_bps: Field,
    pub open_ts: Field,
    pub maturity_ts: Field,
    pub pos_index: Field,
    // Raw old leaf at pos_index for INACTIVE entries (identity update);
    // active entries must open the recomputed position leaf.
    pub pos_old_leaf: Field,
    pub pos_siblings: [Field; DEPTH],
    // Borrower account pre-state + proof.
    pub borrower_index: Field,
    pub borrower_cash: Field,
    pub borrower_coll: Field,
    pub borrower_nonce: Field,
    pub borrower_siblings: [Field; DEPTH],
    // Lender account pre-state + proof (post-borrower-update tree).
    pub lender_index: Field,
    pub lender_cash: Field,
    pub lender_coll: Field,
    pub lender_nonce: Field,
    pub lender_siblings: [Field; DEPTH],
    // Prover-supplied interest, constrained by constrain_interest.
    pub interest: Field,
    pub borrower_sig: Signature,
    pub is_active: Field,
}

fn pad_or(active: Field, sig: Signature) -> Signature {
    Signature {
        r_x: select(active, sig.r_x, PAD_R_X),
        r_y: select(active, sig.r_y, PAD_R_Y),
        s_lo: select(active, sig.s_lo, PAD_S_LO),
        s_hi: select(active, sig.s_hi, PAD_S_HI),
    }
}

/// Apply one close; returns (acct_root, pos_root, da_acc) updated.
pub fn apply_close(
    acct_root: Field,
    pos_root: Field,
    da_acc: Field,
    batch_ts: Field,
    c: CloseWitness,
) -> (Field, Field, Field) {
    assert(c.is_active * (1 - c.is_active) == 0);
    assert_u64(c.cash);
    assert_u64(c.coll);
    assert_u32(c.rate_bps);
    assert_u32(c.haircut_bps);
    assert_u64(c.open_ts);
    assert_u64(c.maturity_ts);

    let term = term_hash(c.rate_bps, c.haircut_bps, c.open_ts, c.maturity_ts);
    let amt = amt_hash(c.cash, c.coll);
    let leaf = pos_leaf(c.borrower_pk_x, c.lender_pk_x, term, amt);
    let msg = Poseidon2::hash([DOMAIN_CLOSE, c.pos_index, leaf, c.borrower_nonce], 4);

    // --- borrower signature (close only by borrower; PLAN.md 3) ---
    let sig_msg = select(c.is_active, msg, PAD_MSG);
    let pk_x = select(c.is_active, c.borrower_pk_x, PAD_PK_X);
    let pk_y = select(c.is_active, c.borrower_pk_y, PAD_PK_Y);
    verify_sig(pk_x, pk_y, sig_msg, pad_or(c.is_active, c.borrower_sig));

    // --- time + interest (only enforced when active) ---
    // batch_ts <= maturity_ts, elapsed = batch_ts - open_ts >= 0.
    let elapsed = batch_ts - c.open_ts;
    if c.is_active == 1 {
        assert(is_even_y(c.borrower_pk_y));
        assert(c.borrower_pk_x != PAD_PK_X);
        assert_u64(c.maturity_ts - batch_ts);
        assert_u64(elapsed);
        // Issue #1 L9: the incremented borrower nonce must stay in u64.
        assert_u64(c.borrower_nonce);
        constrain_interest(c.cash, c.rate_bps, elapsed, c.interest);
    }
    let repay = c.cash + select(c.is_active, c.interest, 0);
    assert_u64(select(c.is_active, repay, 0));

    // --- borrower: cash -= repay, coll += coll, nonce += 1 ---
    let borrower_old = leaf_value(Account {
        pk_x: c.borrower_pk_x,
        cash: c.borrower_cash,
        coll: c.borrower_coll,
        nonce: c.borrower_nonce,
    });
    let b_new_cash = c.borrower_cash - repay;
    let b_new_coll = c.borrower_coll + c.coll;
    assert_u64(select(c.is_active, b_new_cash, 0)); // wraps on overdraft
    assert_u64(select(c.is_active, b_new_coll, 0));
    let borrower_new = leaf_value(Account {
        pk_x: c.borrower_pk_x,
        cash: b_new_cash,
        coll: b_new_coll,
        nonce: c.borrower_nonce + 1,
    });
    let b_leaf = select(c.is_active, borrower_new, borrower_old);
    let acct_root1 =
        update_root(borrower_old, b_leaf, c.borrower_index, c.borrower_siblings, acct_root);

    // --- lender: cash += repay (no signature, no nonce change) ---
    let lender_old = leaf_value(Account {
        pk_x: c.lender_pk_x,
        cash: c.lender_cash,
        coll: c.lender_coll,
        nonce: c.lender_nonce,
    });
    let l_new_cash = c.lender_cash + repay;
    assert_u64(select(c.is_active, l_new_cash, 0));
    let lender_new = leaf_value(Account {
        pk_x: c.lender_pk_x,
        cash: l_new_cash,
        coll: c.lender_coll,
        nonce: c.lender_nonce,
    });
    let l_leaf = select(c.is_active, lender_new, lender_old);
    let acct_root2 = update_root(lender_old, l_leaf, c.lender_index, c.lender_siblings, acct_root1);

    // --- position: prove the claimed record is at pos_index, zero it ---
    // Inactive: identity update of whatever leaf the witness points at.
    let old_pos = select(c.is_active, leaf, c.pos_old_leaf);
    let new_pos = select(c.is_active, 0, c.pos_old_leaf);
    let pos_root1 = update_root(old_pos, new_pos, c.pos_index, c.pos_siblings, pos_root);

    // --- DA fold: the close message binds slot + leaf + nonce ---
    let da_folded = Poseidon2::hash([DOMAIN_DA, da_acc, msg], 3);
    let new_da_acc = select(c.is_active, da_folded, da_acc);

    (acct_root2, pos_root1, new_da_acc)
}

pub struct LiqWitness {
    // The position being defaulted/liquidated (full record).
    pub borrower_pk_x: Field,
    pub lender_pk_x: Field,
    pub cash: Field,
    pub coll: Field,
    pub rate_bps: Field,
    pub haircut_bps: Field,
    pub open_ts: Field,
    pub maturity_ts: Field,
    pub pos_index: Field,
    // Raw old leaf at pos_index for INACTIVE entries (identity update).
    pub pos_old_leaf: Field,
    pub pos_siblings: [Field; DEPTH],
    // Lender account pre-state + proof (receives the collateral).
    pub lender_index: Field,
    pub lender_cash: Field,
    pub lender_coll: Field,
    pub lender_nonce: Field,
    pub lender_siblings: [Field; DEPTH],
    // 0 = default (maturity passed), 1 = liquidation (margin breach).
    pub is_liquidation: Field,
    pub is_active: Field,
}

/// Apply one default/liquidation; returns (acct_root, pos_root, da_acc).
/// Permissionless: NO signature - validity comes solely from the condition
/// holding at the bound batch_ts/price (PLAN.md 3).
pub fn apply_liq(
    acct_root: Field,
    pos_root: Field,
    da_acc: Field,
    batch_ts: Field,
    price: Field,
    l: LiqWitness,
) -> (Field, Field, Field) {
    assert(l.is_active * (1 - l.is_active) == 0);
    assert(l.is_liquidation * (1 - l.is_liquidation) == 0);
    assert_u64(l.cash);
    assert_u64(l.coll);
    assert_u32(l.rate_bps);
    assert_u32(l.haircut_bps);
    assert_u64(l.open_ts);
    assert_u64(l.maturity_ts);

    if l.is_active == 1 {
        if l.is_liquidation == 0 {
            // Default: strictly past maturity at the bound batch_ts.
            assert_u64(batch_ts - l.maturity_ts - 1);
        } else {
            // Margin breach at half the initial haircut, division-free
            // cross-multiplication (PLAN.md 6.1.1):
            //   coll * price * 2e4 < cash * (2e4 + haircut_bps) * 1e7
            // price is a u64-bounded PI (contract enforces < 2^64).
            assert_u64(price);
            let lhs = l.coll * price * 20000;
            let rhs = l.cash * (20000 + l.haircut_bps) * 10000000;
            // lhs < 2^64 * 2^64 * 2^15 = 2^143; rhs < 2^64+2^15+2^24 = 2^103.
            // Both < 2^144, so rhs - lhs - 1 in [0, 2^144) iff lhs < rhs.
            assert_u144(rhs - lhs - 1);
        }
    }

    let term = term_hash(l.rate_bps, l.haircut_bps, l.open_ts, l.maturity_ts);
    let amt = amt_hash(l.cash, l.coll);
    let leaf = pos_leaf(l.borrower_pk_x, l.lender_pk_x, term, amt);

    // --- lender: coll += coll (title transfer; borrower keeps the cash) ---
    let lender_old = leaf_value(Account {
        pk_x: l.lender_pk_x,
        cash: l.lender_cash,
        coll: l.lender_coll,
        nonce: l.lender_nonce,
    });
    let l_new_coll = l.lender_coll + l.coll;
    assert_u64(select(l.is_active, l_new_coll, 0));
    let lender_new = leaf_value(Account {
        pk_x: l.lender_pk_x,
        cash: l.lender_cash,
        coll: l_new_coll,
        nonce: l.lender_nonce,
    });
    let l_leaf = select(l.is_active, lender_new, lender_old);
    let acct_root1 = update_root(lender_old, l_leaf, l.lender_index, l.lender_siblings, acct_root);

    // --- position: prove + zero (inactive: identity update) ---
    let old_pos = select(l.is_active, leaf, l.pos_old_leaf);
    let new_pos = select(l.is_active, 0, l.pos_old_leaf);
    let pos_root1 = update_root(old_pos, new_pos, l.pos_index, l.pos_siblings, pos_root);

    // --- DA fold: record binds the slot and the mode ---
    let rec = Poseidon2::hash([l.pos_index, l.is_liquidation], 2);
    let da_folded = Poseidon2::hash([DOMAIN_DA, da_acc, rec], 3);
    let new_da_acc = select(l.is_active, da_folded, da_acc);

    (acct_root1, pos_root1, new_da_acc)
}
