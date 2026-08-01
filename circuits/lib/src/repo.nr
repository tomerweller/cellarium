// Repo position tree + bilateral open op (PLAN.md 1.1-1.3, M2).
//
// Position record (leaf layout, DESIGN.md):
//   term_hash = P2([rate_bps, haircut_bps, open_ts, maturity_ts], 4)
//   amt_hash  = P2([cash, coll], 2)
//   pos_leaf  = P2([DOMAIN_POS, borrower_pk_x, lender_pk_x, P2([term_hash, amt_hash], 2)], 4)
// Empty slot = 0. The position tree shares the account tree's depth/node/
// empty conventions (merkle.nr).
//
// Open is bilateral: BOTH parties sign
//   open_msg = P2([DOMAIN_OPEN, borrower_pk_x, lender_pk_x,
//                  P2([term_hash, amt_hash, borrower_nonce, lender_nonce], 4)], 4)
// binding the full term sheet (open_ts is signer-agreed, not the batch ts -
// PLAN.md 6.3) and both account nonces. Effects: lender.cash -= cash,
// borrower.cash += cash, borrower.coll -= coll; the collateral sits in the
// position (title-transfer analog); position leaf written to a slot whose
// old leaf is proven 0 under the RUNNING position root (which makes in-batch
// slot collisions structurally impossible).
//
// Padding follows tx.nr exactly: inactive entries carry identity Merkle
// proofs and the PAD signature; is_active gates only the fold accumulators.
use crate::account::{leaf_value, Account};
use crate::merkle::{update_root, DEPTH};
use crate::schnorr::{is_even_y, verify_sig, Signature};
use crate::tx::{assert_u64, select, DOMAIN_DA, PAD_MSG, PAD_PK_X, PAD_PK_Y, PAD_R_X, PAD_R_Y, PAD_S_HI, PAD_S_LO};
use dep::poseidon::poseidon2::Poseidon2;

pub global DOMAIN_POS: Field = 8;
pub global DOMAIN_OPEN: Field = 9;
pub global DOMAIN_CLOSE: Field = 10;

fn assert_u32(v: Field) {
    let _: [u1; 32] = v.to_le_bits();
}

pub fn term_hash(rate_bps: Field, haircut_bps: Field, open_ts: Field, maturity_ts: Field) -> Field {
    Poseidon2::hash([rate_bps, haircut_bps, open_ts, maturity_ts], 4)
}

pub fn amt_hash(cash: Field, coll: Field) -> Field {
    Poseidon2::hash([cash, coll], 2)
}

pub fn pos_leaf(
    borrower_pk_x: Field,
    lender_pk_x: Field,
    term: Field,
    amt: Field,
) -> Field {
    Poseidon2::hash([DOMAIN_POS, borrower_pk_x, lender_pk_x, Poseidon2::hash([term, amt], 2)], 4)
}

pub fn open_message(
    borrower_pk_x: Field,
    lender_pk_x: Field,
    term: Field,
    amt: Field,
    borrower_nonce: Field,
    lender_nonce: Field,
) -> Field {
    Poseidon2::hash(
        [
            DOMAIN_OPEN,
            borrower_pk_x,
            lender_pk_x,
            Poseidon2::hash([term, amt, borrower_nonce, lender_nonce], 4),
        ],
        4,
    )
}

pub struct OpenWitness {
    // Borrower account pre-state + inclusion proof.
    pub borrower_pk_x: Field,
    pub borrower_pk_y: Field,
    pub borrower_index: Field,
    pub borrower_cash: Field,
    pub borrower_coll: Field,
    pub borrower_nonce: Field,
    pub borrower_siblings: [Field; DEPTH],
    // Lender account pre-state + inclusion proof (post-borrower-update tree).
    pub lender_pk_x: Field,
    pub lender_pk_y: Field,
    pub lender_index: Field,
    pub lender_cash: Field,
    pub lender_coll: Field,
    pub lender_nonce: Field,
    pub lender_siblings: [Field; DEPTH],
    // Term sheet.
    pub cash: Field,
    pub coll: Field,
    pub rate_bps: Field,
    pub haircut_bps: Field,
    pub open_ts: Field,
    pub maturity_ts: Field,
    // Position slot: raw old leaf at pos_index (must be 0 when active;
    // inactive entries do an identity update of whatever is there, so
    // padding never depends on an empty slot existing).
    pub pos_index: Field,
    pub pos_old_leaf: Field,
    pub pos_siblings: [Field; DEPTH],
    pub borrower_sig: Signature,
    pub lender_sig: Signature,
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

/// Range-check helper for the adequacy comparison: values < 2^144.
fn assert_u144(v: Field) {
    let _: [u1; 144] = v.to_le_bits();
}

/// Apply one repo open against the running (account_root, pos_root, da_acc);
/// returns the updated triple. Enforces maturity_ts > batch_ts (M3) and the
/// open-time collateral adequacy at the batch price (M4, PLAN.md 6.1.1):
///   coll * price * 10^4  >=  cash * (10^4 + haircut_bps) * 10^7
pub fn apply_open(
    acct_root: Field,
    pos_root: Field,
    da_acc: Field,
    batch_ts: Field,
    price: Field,
    o: OpenWitness,
) -> (Field, Field, Field) {
    assert(o.is_active * (1 - o.is_active) == 0);
    assert_u64(o.cash);
    assert_u64(o.coll);
    assert_u32(o.rate_bps);
    assert_u32(o.haircut_bps);
    assert_u64(o.open_ts);
    assert_u64(o.maturity_ts);

    let term = term_hash(o.rate_bps, o.haircut_bps, o.open_ts, o.maturity_ts);
    let amt = amt_hash(o.cash, o.coll);
    let msg = open_message(
        o.borrower_pk_x,
        o.lender_pk_x,
        term,
        amt,
        o.borrower_nonce,
        o.lender_nonce,
    );

    // --- both signatures (PAD when inactive, as in tx.nr) ---
    let sig_msg = select(o.is_active, msg, PAD_MSG);
    let b_pk_x = select(o.is_active, o.borrower_pk_x, PAD_PK_X);
    let b_pk_y = select(o.is_active, o.borrower_pk_y, PAD_PK_Y);
    verify_sig(b_pk_x, b_pk_y, sig_msg, pad_or(o.is_active, o.borrower_sig));
    let l_pk_x = select(o.is_active, o.lender_pk_x, PAD_PK_X);
    let l_pk_y = select(o.is_active, o.lender_pk_y, PAD_PK_Y);
    verify_sig(l_pk_x, l_pk_y, sig_msg, pad_or(o.is_active, o.lender_sig));

    if o.is_active == 1 {
        assert(o.cash != 0);
        assert(o.coll != 0);
        assert(o.borrower_pk_x != 0);
        assert(o.lender_pk_x != 0);
        // Neither party may be bound unilaterally; identical parties would
        // also break the two sequential account updates below.
        assert(o.borrower_pk_x != o.lender_pk_x);
        // Padding keypair blacklisted in both roles (secret is public).
        assert(o.borrower_pk_x != PAD_PK_X);
        assert(o.lender_pk_x != PAD_PK_X);
        // Canonical y-parity for both signers.
        assert(is_even_y(o.borrower_pk_y));
        assert(is_even_y(o.lender_pk_y));
        // Issue #1 L9: incremented nonces must stay in u64 (no wrap to 0).
        assert_u64(o.borrower_nonce);
        assert_u64(o.lender_nonce);
        // Terms must be internally consistent even before M3 binds batch_ts.
        assert_u64(o.maturity_ts - 1 - o.open_ts); // maturity_ts > open_ts
        // M3: cannot open a repo that is already past maturity.
        assert_u64(o.maturity_ts - 1 - batch_ts); // maturity_ts > batch_ts
        // Issue #1 M4: open_ts may not postdate the batch. Otherwise the
        // close-side elapsed = batch_ts - open_ts (settle.nr) underflows and
        // the position is unprovable (hence unclosable) until maturity.
        assert_u64(batch_ts - o.open_ts); // open_ts <= batch_ts
        // M4: open-time collateral adequacy at the batch price. price is a
        // u64-bounded public input (contract enforces < 2^64), so both sides
        // fit 2^144 and the difference range check is sound.
        assert_u64(price);
        let coll_value = o.coll * price * 10000;
        let required = o.cash * (10000 + o.haircut_bps) * 10000000;
        assert_u144(coll_value - required); // coll_value >= required
    }

    // --- borrower: coll -= coll, cash += cash, nonce += 1 ---
    let borrower_old = leaf_value(Account {
        pk_x: o.borrower_pk_x,
        cash: o.borrower_cash,
        coll: o.borrower_coll,
        nonce: o.borrower_nonce,
    });
    let b_new_cash = o.borrower_cash + o.cash;
    let b_new_coll = o.borrower_coll - o.coll;
    assert_u64(select(o.is_active, b_new_cash, 0));
    assert_u64(select(o.is_active, b_new_coll, 0)); // underflow wraps -> fails
    let borrower_new = leaf_value(Account {
        pk_x: o.borrower_pk_x,
        cash: b_new_cash,
        coll: b_new_coll,
        nonce: o.borrower_nonce + 1,
    });
    let b_leaf = select(o.is_active, borrower_new, borrower_old);
    let acct_root1 = update_root(borrower_old, b_leaf, o.borrower_index, o.borrower_siblings, acct_root);

    // --- lender: cash -= cash, nonce += 1 (witness against post-borrower tree) ---
    let lender_old = leaf_value(Account {
        pk_x: o.lender_pk_x,
        cash: o.lender_cash,
        coll: o.lender_coll,
        nonce: o.lender_nonce,
    });
    let l_new_cash = o.lender_cash - o.cash;
    assert_u64(select(o.is_active, l_new_cash, 0)); // lender.cash >= cash
    let lender_new = leaf_value(Account {
        pk_x: o.lender_pk_x,
        cash: l_new_cash,
        coll: o.lender_coll,
        nonce: o.lender_nonce + 1,
    });
    let l_leaf = select(o.is_active, lender_new, lender_old);
    let acct_root2 = update_root(lender_old, l_leaf, o.lender_index, o.lender_siblings, acct_root1);

    // --- position: slot must be empty under the running pos root ---
    if o.is_active == 1 {
        assert(o.pos_old_leaf == 0);
    }
    let new_pos_leaf_active = pos_leaf(o.borrower_pk_x, o.lender_pk_x, term, amt);
    // Inactive: identity update of whatever leaf the witness points at.
    let new_pos_leaf = select(o.is_active, new_pos_leaf_active, o.pos_old_leaf);
    let pos_root1 = update_root(o.pos_old_leaf, new_pos_leaf, o.pos_index, o.pos_siblings, pos_root);

    // --- DA fold: open record binds the message AND the slot index ---
    let open_rec = Poseidon2::hash([msg, o.pos_index], 2);
    let da_folded = Poseidon2::hash([DOMAIN_DA, da_acc, open_rec], 3);
    let new_da_acc = select(o.is_active, da_folded, da_acc);

    (acct_root2, pos_root1, new_da_acc)
}
