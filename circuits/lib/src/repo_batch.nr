// The repo batch state-transition relation (M2+): apply D deposits, then O
// repo opens, then T signed L2 payments, evolving BOTH trees. The combined
// state root binds them: state_root = P2([account_root, position_root], 2)
// (PLAN.md 1.1). Public inputs are the full 7-PI interface (PLAN.md 6.1.2):
// batch_ts and price are bound by the contract from M2 but only constrained
// by op logic from M3 (time) / M4 (margin).
//
// DA commitment covers off-chain-originated ops in application order: open
// records P2([open_msg, pos_index]) then payment tx messages (PLAN.md 6.3;
// deposits are reconstructible from the on-chain queues).
use crate::repo::{apply_open, OpenWitness};
use crate::tx::{apply_deposit, apply_tx, DepositWitness, TxWitness};
use dep::poseidon::poseidon2::Poseidon2;

pub fn state_root(account_root: Field, position_root: Field) -> Field {
    Poseidon2::hash([account_root, position_root], 2)
}

pub fn batch_repo<let D: u32, let O: u32, let T: u32>(
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
    opens: [OpenWitness; O],
    txs: [TxWitness; T],
) {
    assert(state_root(old_acct_root, old_pos_root) == old_state_root);

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
