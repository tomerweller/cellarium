// Batch entry application. Padding strategy: EVERY constraint always runs on
// valid witness data - inactive entries carry a real identity Merkle proof
// (new leaf == old leaf, so the root can't move) and the fixed PAD signature
// below (a public constant; proving it leaks nothing and changes no state).
// This avoids predicated blackbox calls (MSM on garbage points) entirely.
// `is_active` then only gates the deposit/withdraw fold accumulators, which
// is what binds entries to the on-chain recomputed hashes.
//
// Multi-asset (PLAN.md 1.1-1.3): every deposit/transfer/withdrawal carries an
// asset id (0 = cash/XLM, 1 = collateral/tUST) that selects which of the two
// account balances moves. The asset id is bound into the tx signing message,
// the deposit fold (DOMAIN_DEP2) and the withdrawal fold (DOMAIN_WD2).
//
// Active-entry guards (security remediation):
// - amount > 0 (no free nonce burns / zero-credit deposits)
// - from_pk_x / deposit pk_x != PAD_PK_X (padding sk=7 is public; that
//   account must never hold funds or authorize spends)
// - active signer pk_y is even (canonical y-parity binding for pk_x accounts)
use crate::account::{leaf_value, Account};
use crate::merkle::{update_root, DEPTH};
use crate::schnorr::{is_even_y, verify_sig, Signature};
use dep::poseidon::poseidon2::Poseidon2;

pub global DOMAIN_TX: Field = 2;
pub global DOMAIN_DA: Field = 7;
pub global DOMAIN_DEP2: Field = 11;
pub global DOMAIN_WD2: Field = 12;

// Fixed padding signature: sk=7, k=13, msg=42 over Grumpkin (harness
// keys::pad_signature() regenerates; schnorr_test pins the same values).
// PUBLIC by design - only safe because active entries blacklist PAD_PK_X.
pub global PAD_PK_X: Field = 0x0e602b9dd6a3e8d039a17f069add3f9c2a187a8f629a1de60a33a8067b9b2842;
pub global PAD_PK_Y: Field = 0x14cc8e83df1b5cbb163bd2c94005cb0707fe570def5a165242b1c1419cb014cb;
pub global PAD_MSG: Field = 42;
pub global PAD_R_X: Field = 0x17e6386beac25fd11573fe37404e61d754a91ee7722dbd0c1c7fff157ed56573;
pub global PAD_R_Y: Field = 0x2be1ab9ccce96a8deeb82e85a35cc26804269db7ea57bc0e0afa3b835dfcff73;
pub global PAD_S_LO: Field = 0x000000000000000000000000000000008312af54a4f4b07d782dc23d06ef43f2;
pub global PAD_S_HI: Field = 0x000000000000000000000000000000002ed87ed8cf30832f5f7b93ee4d5afd52;

pub fn assert_u64(v: Field) {
    let _: [u1; 64] = v.to_le_bits();
}

pub fn select(cond: Field, if_true: Field, if_false: Field) -> Field {
    assert(cond * (1 - cond) == 0);
    cond * if_true + (1 - cond) * if_false
}

/// The L2 transaction signing message; binds the asset id (DESIGN.md).
pub fn tx_message(
    from_pk_x: Field,
    to_field: Field,
    asset: Field,
    amount: Field,
    nonce: Field,
    is_withdraw: Field,
) -> Field {
    Poseidon2::hash([DOMAIN_TX, from_pk_x, to_field, asset, amount, nonce, is_withdraw], 7)
}

pub struct DepositWitness {
    pub pk_x: Field,
    pub asset: Field,
    pub amount: Field,
    pub index: Field,
    // Pre-state of the target slot (pk_x == 0 means empty).
    pub old_pk_x: Field,
    pub old_cash: Field,
    pub old_coll: Field,
    pub old_nonce: Field,
    pub siblings: [Field; DEPTH],
    pub is_active: Field,
}

/// Apply one deposit; returns (new_root, new_deposit_fold).
pub fn apply_deposit(root: Field, dep_acc: Field, d: DepositWitness) -> (Field, Field) {
    assert(d.is_active * (1 - d.is_active) == 0);
    assert(d.asset * (1 - d.asset) == 0);
    assert_u64(d.amount);

    let old_leaf = leaf_value(Account {
        pk_x: d.old_pk_x,
        cash: d.old_cash,
        coll: d.old_coll,
        nonce: d.old_nonce,
    });

    // Empty slot: initialize. Occupied: pk must match, balance accrues.
    let is_empty = if d.old_pk_x == 0 { 1 } else { 0 };
    if d.is_active == 1 {
        assert(d.pk_x != 0);
        assert(d.amount != 0);
        // Padding keypair sk is public - never credit it.
        assert(d.pk_x != PAD_PK_X);
        if is_empty == 0 {
            assert(d.old_pk_x == d.pk_x);
        }
        // Empty-slot init: pre-state must be the canonical empty account
        // (pk_x already 0 via is_empty; pin balances/nonce so a non-zero
        // ghost state can't be smuggled under a zero leaf).
        if is_empty == 1 {
            assert(d.old_cash == 0);
            assert(d.old_coll == 0);
            assert(d.old_nonce == 0);
        }
    }
    let base_cash = select(is_empty, 0, d.old_cash);
    let base_coll = select(is_empty, 0, d.old_coll);
    let new_cash = base_cash + (1 - d.asset) * d.amount;
    let new_coll = base_coll + d.asset * d.amount;
    assert_u64(new_cash);
    assert_u64(new_coll);
    let new_nonce = select(is_empty, 0, d.old_nonce);
    let new_leaf_active =
        leaf_value(Account { pk_x: d.pk_x, cash: new_cash, coll: new_coll, nonce: new_nonce });

    // Inactive entries are identity updates: new leaf forced to old leaf.
    let new_leaf = select(d.is_active, new_leaf_active, old_leaf);
    let new_root = update_root(old_leaf, new_leaf, d.index, d.siblings, root);

    // Fold binds the asset id: acc' = P2([DOMAIN_DEP2, acc, P2([pk_x, asset, amount])]).
    let entry = Poseidon2::hash([d.pk_x, d.asset, d.amount], 3);
    let folded = Poseidon2::hash([DOMAIN_DEP2, dep_acc, entry], 3);
    let new_acc = select(d.is_active, folded, dep_acc);

    (new_root, new_acc)
}

pub struct TxWitness {
    pub from_pk_x: Field,
    pub from_pk_y: Field,
    pub from_index: Field,
    pub from_cash: Field,
    pub from_coll: Field,
    pub from_nonce: Field,
    pub from_siblings: [Field; DEPTH],
    // Transfer: recipient pk_x. Withdrawal: address_to_field(destination).
    pub to_field: Field,
    // Recipient pre-state (transfers only; ignored for withdrawals).
    pub to_index: Field,
    // Transfer: recipient cash balance. Otherwise: RAW leaf value at to_index.
    pub to_cash: Field,
    pub to_coll: Field,
    pub to_nonce: Field,
    pub to_siblings: [Field; DEPTH],
    pub asset: Field,
    pub amount: Field,
    pub is_withdraw: Field,
    pub is_active: Field,
    pub sig: Signature,
}

/// Apply one signed L2 transaction; returns (new_root, new_withdraw_fold,
/// new_da_fold). The DA fold binds the tx's signing message - which already
/// commits to (from_pk_x, to_field, asset, amount, nonce, is_withdraw), i.e.
/// everything needed to reconstruct state from the published blob.
/// Signatures ship in the blob as audit data but are not commitment-bound
/// (authorization is already established by this proof).
pub fn apply_tx(root: Field, wd_acc: Field, da_acc: Field, t: TxWitness) -> (Field, Field, Field) {
    assert(t.is_active * (1 - t.is_active) == 0);
    assert(t.is_withdraw * (1 - t.is_withdraw) == 0);
    assert(t.asset * (1 - t.asset) == 0);
    assert_u64(t.amount);

    // --- signature over the tx message (constant PAD check when inactive) ---
    let msg = tx_message(t.from_pk_x, t.to_field, t.asset, t.amount, t.from_nonce, t.is_withdraw);
    let pk_x = select(t.is_active, t.from_pk_x, PAD_PK_X);
    let pk_y = select(t.is_active, t.from_pk_y, PAD_PK_Y);
    let sig_msg = select(t.is_active, msg, PAD_MSG);
    let sig = Signature {
        r_x: select(t.is_active, t.sig.r_x, PAD_R_X),
        r_y: select(t.is_active, t.sig.r_y, PAD_R_Y),
        s_lo: select(t.is_active, t.sig.s_lo, PAD_S_LO),
        s_hi: select(t.is_active, t.sig.s_hi, PAD_S_HI),
    };
    verify_sig(pk_x, pk_y, sig_msg, sig);

    // --- debit sender (identity when inactive) ---
    if t.is_active == 1 {
        assert(t.from_pk_x != 0);
        assert(t.amount != 0);
        assert(t.from_pk_x != PAD_PK_X);
        // Canonical y-parity: only even-y pubkeys may spend. Keygen must
        // flip sk -> -sk when raw y is odd (harness + wallet do this).
        assert(is_even_y(t.from_pk_y));
    }
    let old_sender = leaf_value(Account {
        pk_x: t.from_pk_x,
        cash: t.from_cash,
        coll: t.from_coll,
        nonce: t.from_nonce,
    });
    let debited_cash = t.from_cash - (1 - t.asset) * t.amount;
    let debited_coll = t.from_coll - t.asset * t.amount;
    // Underflow wraps to a huge field element and fails the 64-bit check.
    assert_u64(select(t.is_active, debited_cash, 0));
    assert_u64(select(t.is_active, debited_coll, 0));
    let new_sender = leaf_value(Account {
        pk_x: t.from_pk_x,
        cash: debited_cash,
        coll: debited_coll,
        nonce: t.from_nonce + 1,
    });
    let sender_leaf = select(t.is_active, new_sender, old_sender);
    let root1 = update_root(old_sender, sender_leaf, t.from_index, t.from_siblings, root);

    // --- credit recipient (transfers) or fold withdrawal ---
    // Witness convention: for an active transfer, (to_index, to_cash, to_coll,
    // to_nonce, to_siblings) describe the recipient ACCOUNT under root1; the
    // recipient must exist with pk_x == to_field (an empty slot can't produce
    // a valid inclusion proof for a non-zero leaf, so existence is
    // structural). Otherwise (withdrawal or padding) to_cash carries the
    // RAW leaf value at to_index and the update is an identity.
    let is_transfer = t.is_active * (1 - t.is_withdraw);
    if is_transfer == 1 {
        assert(t.to_field != 0);
        assert(t.to_field != PAD_PK_X);
    }
    let credited_cash = t.to_cash + (1 - t.asset) * t.amount;
    let credited_coll = t.to_coll + t.asset * t.amount;
    assert_u64(select(is_transfer, credited_cash, 0));
    assert_u64(select(is_transfer, credited_coll, 0));
    let recipient_old = leaf_value(Account {
        pk_x: t.to_field,
        cash: t.to_cash,
        coll: t.to_coll,
        nonce: t.to_nonce,
    });
    let recipient_new = leaf_value(Account {
        pk_x: t.to_field,
        cash: credited_cash,
        coll: credited_coll,
        nonce: t.to_nonce,
    });
    let old_leaf1 = select(is_transfer, recipient_old, t.to_cash);
    let new_leaf1 = select(is_transfer, recipient_new, t.to_cash);
    let root2 = update_root(old_leaf1, new_leaf1, t.to_index, t.to_siblings, root1);

    // Withdrawal fold binds (dest, asset, amount):
    // acc' = P2([DOMAIN_WD2, acc, P2([to_field, asset, amount])]).
    let is_withdrawal = t.is_active * t.is_withdraw;
    let wd_entry = Poseidon2::hash([t.to_field, t.asset, t.amount], 3);
    let folded = Poseidon2::hash([DOMAIN_WD2, wd_acc, wd_entry], 3);
    let new_wd_acc = select(is_withdrawal, folded, wd_acc);

    // --- DA commitment fold (validium: binds the published tx blob) ---
    let da_folded = Poseidon2::hash([DOMAIN_DA, da_acc, msg], 3);
    let new_da_acc = select(t.is_active, da_folded, da_acc);

    (root2, new_wd_acc, new_da_acc)
}
