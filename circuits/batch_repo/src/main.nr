// Repo batch: D=4 deposits, C=2 closes, L=2 defaults/liquidations, O=2
// opens, T=4 payments (PLAN.md 1.3; sizes are parameters - grow after
// measuring). Public inputs (exactly 7, order matters - the contract
// assembles the same blob): old_state_root, new_state_root, deposit_hash,
// withdraw_hash, da_commitment, batch_ts, price.
use rollup_lib::repo::OpenWitness;
use rollup_lib::repo_batch::batch_repo;
use rollup_lib::settle::{CloseWitness, LiqWitness};
use rollup_lib::tx::{DepositWitness, TxWitness};

fn main(
    old_state_root: pub Field,
    new_state_root: pub Field,
    deposit_hash: pub Field,
    withdraw_hash: pub Field,
    da_commitment: pub Field,
    batch_ts: pub Field,
    price: pub Field,
    old_acct_root: Field,
    old_pos_root: Field,
    deposits: [DepositWitness; 4],
    closes: [CloseWitness; 2],
    liqs: [LiqWitness; 2],
    opens: [OpenWitness; 2],
    txs: [TxWitness; 4],
) {
    batch_repo(
        old_state_root,
        new_state_root,
        deposit_hash,
        withdraw_hash,
        da_commitment,
        batch_ts,
        price,
        old_acct_root,
        old_pos_root,
        deposits,
        closes,
        liqs,
        opens,
        txs,
    );
}
