// Tests for the repo open op and the combined-state batch relation
// (repo.nr / repo_batch.nr). Witness data comes from the harness:
// `cargo run -p harness -- noir-repo-vectors` regenerates repo_vectors.nr.
//
// Negative tests are constructed so every OTHER constraint is satisfied -
// the named guard is the only thing standing between the witness and a
// valid proof (see the per-fixture docs in repo_vectors.nr).
use crate::repo::apply_open;
use crate::repo_batch::batch_repo;
use crate::repo_vectors;

// --- The full relation: seven public inputs pinned to harness values -------

#[test]
fn batch_repo_replays_and_pins_all_seven_public_inputs() {
    let (pis, roots, deps, closes, liqs, opens, txs) = repo_vectors::batch_r();
    batch_repo::<2, 1, 1, 1, 2>(
        pis[0], pis[1], pis[2], pis[3], pis[4], pis[5], pis[6], roots[0], roots[1], deps, closes,
        liqs, opens, txs,
    );
}

#[test(should_fail)]
fn batch_repo_rejects_wrong_new_state_root() {
    let (pis, roots, deps, closes, liqs, opens, txs) = repo_vectors::batch_r();
    batch_repo::<2, 1, 1, 1, 2>(
        pis[0], pis[1] + 1, pis[2], pis[3], pis[4], pis[5], pis[6], roots[0], roots[1], deps,
        closes, liqs, opens, txs,
    );
}

#[test(should_fail)]
fn batch_repo_rejects_wrong_root_opening() {
    // A lying prover cannot open the state root to different tree roots.
    let (pis, roots, deps, closes, liqs, opens, txs) = repo_vectors::batch_r();
    batch_repo::<2, 1, 1, 1, 2>(
        pis[0], pis[1], pis[2], pis[3], pis[4], pis[5], pis[6], roots[0] + 1, roots[1], deps,
        closes, liqs, opens, txs,
    );
}

#[test(should_fail)]
fn batch_repo_rejects_wrong_da_commitment() {
    let (pis, roots, deps, closes, liqs, opens, txs) = repo_vectors::batch_r();
    batch_repo::<2, 1, 1, 1, 2>(
        pis[0], pis[1], pis[2], pis[3], pis[4] + 1, pis[5], pis[6], roots[0], roots[1], deps,
        closes, liqs, opens, txs,
    );
}

// --- apply_open guards ------------------------------------------------------

#[test(should_fail)]
fn open_requires_both_signatures() {
    let (acct_root, pos_root, w) = repo_vectors::open_single_sig();
    let _ = apply_open(acct_root, pos_root, 0, 1700000100, 250000000, w);
}

#[test(should_fail)]
fn open_rejects_occupied_slot() {
    let (acct_root, pos_root, w) = repo_vectors::open_occupied_slot();
    let _ = apply_open(acct_root, pos_root, 0, 1700000100, 250000000, w);
}

#[test(should_fail)]
fn open_rejects_lender_overdraft() {
    let (acct_root, pos_root, w) = repo_vectors::open_lender_overdraft();
    let _ = apply_open(acct_root, pos_root, 0, 1700000100, 250000000, w);
}

#[test(should_fail)]
fn open_rejects_borrower_coll_overdraft() {
    let (acct_root, pos_root, w) = repo_vectors::open_coll_overdraft();
    let _ = apply_open(acct_root, pos_root, 0, 1700000100, 250000000, w);
}

#[test(should_fail)]
fn open_signature_binds_terms() {
    let (acct_root, pos_root, w) = repo_vectors::open_terms_not_signed();
    let _ = apply_open(acct_root, pos_root, 0, 1700000100, 250000000, w);
}

#[test(should_fail)]
fn open_rejects_future_open_ts() {
    // Issue #1 M4: a signed open_ts > batch_ts would make the position's
    // close unprovable (elapsed underflows in settle.nr) until maturity.
    let (acct_root, pos_root, w) = repo_vectors::open_future_ts();
    let _ = apply_open(acct_root, pos_root, 0, 1700000100, 250000000, w);
}

// --- Inactive entries are identities ----------------------------------------

#[test]
fn inactive_open_moves_nothing() {
    let (acct_root, pos_root, w) = repo_vectors::open_inactive();
    let (ar, pr, da) = apply_open(acct_root, pos_root, 42, 1700000100, 250000000, w);
    assert(ar == acct_root);
    assert(pr == pos_root);
    assert(da == 42);
}
