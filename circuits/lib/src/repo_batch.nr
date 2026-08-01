// The repo batch state-transition relation (M3+): apply D deposits, then C
// closes, then L defaults/liquidations, then O opens, then T signed L2
// payments, evolving BOTH trees. Closing-type ops run before opens (PLAN.md
// 1.3) so freed slots are reusable. The combined state root binds the trees:
// state_root = P2([account_root, position_root], 2) (PLAN.md 1.1).
//
// DA commitment covers off-chain-originated ops in application order: close
// messages, liq records P2([pos_index, is_liquidation]), open records
// P2([open_msg, pos_index]), then payment tx messages (PLAN.md 6.3;
// deposits are reconstructible from the on-chain queues).
use crate::repo::{apply_open, OpenWitness};
use crate::settle::{apply_close, apply_liq, CloseWitness, LiqWitness};
use crate::tx::{apply_deposit, apply_tx, assert_u64, DepositWitness, TxWitness};
use dep::poseidon::poseidon2::Poseidon2;

pub fn state_root(account_root: Field, position_root: Field) -> Field {
    Poseidon2::hash([account_root, position_root], 2)
}

pub fn batch_repo<let D: u32, let C: u32, let L: u32, let O: u32, let T: u32>(
    old_state_root: Field,
    new_state_root: Field,
    deposit_hash: Field,
    withdraw_hash: Field,
    da_commitment: Field,
    batch_ts: Field,
    price: Field,
    // Private openings of the combined roots.
    old_acct_root: Field,
    old_pos_root: Field,
    deposits: [DepositWitness; D],
    closes: [CloseWitness; C],
    liqs: [LiqWitness; L],
    opens: [OpenWitness; O],
    txs: [TxWitness; T],
) {
    assert(state_root(old_acct_root, old_pos_root) == old_state_root);

    // Issue #1 L8: bind batch_ts and price to u64 unconditionally. The
    // op-level checks only fire when an open/close/liq is active, which left
    // both PIs unconstrained in payment-only batches (the contract already
    // bounds them, but the circuit should not rely on that).
    assert_u64(batch_ts);
    assert_u64(price);

    let mut acct_root = old_acct_root;
    let mut pos_root = old_pos_root;
    let mut dep_acc = 0;
    let mut wd_acc = 0;
    let mut da_acc = 0;

    for i in 0..D {
        let (r, a) = apply_deposit(acct_root, dep_acc, deposits[i]);
        acct_root = r;
        dep_acc = a;
    }
    for i in 0..C {
        let (ar, pr, d) = apply_close(acct_root, pos_root, da_acc, batch_ts, closes[i]);
        acct_root = ar;
        pos_root = pr;
        da_acc = d;
    }
    for i in 0..L {
        let (ar, pr, d) = apply_liq(acct_root, pos_root, da_acc, batch_ts, price, liqs[i]);
        acct_root = ar;
        pos_root = pr;
        da_acc = d;
    }
    for i in 0..O {
        let (ar, pr, d) = apply_open(acct_root, pos_root, da_acc, batch_ts, price, opens[i]);
        acct_root = ar;
        pos_root = pr;
        da_acc = d;
    }
    for i in 0..T {
        let (r, w, d) = apply_tx(acct_root, wd_acc, da_acc, txs[i]);
        acct_root = r;
        wd_acc = w;
        da_acc = d;
    }

    assert(state_root(acct_root, pos_root) == new_state_root);
    assert(dep_acc == deposit_hash);
    assert(wd_acc == withdraw_hash);
    assert(da_acc == da_commitment);
}
