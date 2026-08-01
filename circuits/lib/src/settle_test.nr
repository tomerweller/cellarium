// Tests for close/default/liquidation (settle.nr) and the open adequacy
// guard (repo.nr, M4). Witness data comes from the harness:
// `cargo run -p harness -- noir-repo-vectors` regenerates settle_vectors.nr.
// Positive fixtures carry harness-computed post-roots, so these tests also
// pin the harness <-> circuit state-transition equivalence.
use crate::repo::apply_open;
use crate::settle::{apply_close, apply_liq, constrain_interest};
use crate::settle_vectors;

// --- close ------------------------------------------------------------------

#[test]
fn close_repays_with_interest_and_zeroes_position() {
    let (pre_acct, pre_pos, batch_ts, post_acct, post_pos, w) = settle_vectors::close_happy();
    let (ar, pr, _da) = apply_close(pre_acct, pre_pos, 0, batch_ts, w);
    assert(ar == post_acct);
    assert(pr == post_pos);
}

#[test(should_fail)]
fn close_after_maturity_rejected() {
    let (acct_root, pos_root, batch_ts, w) = settle_vectors::close_after_maturity();
    let _ = apply_close(acct_root, pos_root, 0, batch_ts, w);
}

#[test(should_fail)]
fn close_only_by_borrower() {
    let (acct_root, pos_root, batch_ts, w) = settle_vectors::close_wrong_signer();
    let _ = apply_close(acct_root, pos_root, 0, batch_ts, w);
}

#[test(should_fail)]
fn close_interest_must_be_exact_floor() {
    let (acct_root, pos_root, batch_ts, w) = settle_vectors::close_wrong_interest();
    let _ = apply_close(acct_root, pos_root, 0, batch_ts, w);
}

// --- default / liquidation --------------------------------------------------

#[test]
fn default_transfers_collateral_to_lender() {
    let (pre_acct, pre_pos, batch_ts, post_acct, post_pos, w) = settle_vectors::default_happy();
    let (ar, pr, _da) = apply_liq(pre_acct, pre_pos, 0, batch_ts, 250000000, w);
    assert(ar == post_acct);
    assert(pr == post_pos);
}

#[test(should_fail)]
fn default_requires_strictly_past_maturity() {
    let (acct_root, pos_root, batch_ts, w) = settle_vectors::default_at_maturity();
    let _ = apply_liq(acct_root, pos_root, 0, batch_ts, 250000000, w);
}

#[test]
fn liquidation_fires_on_margin_breach() {
    let (pre_acct, pre_pos, batch_ts, breach_price, _healthy, post_acct, post_pos, w) =
        settle_vectors::liquidation_fixture();
    let (ar, pr, _da) = apply_liq(pre_acct, pre_pos, 0, batch_ts, breach_price, w);
    assert(ar == post_acct);
    assert(pr == post_pos);
}

#[test(should_fail)]
fn liquidation_rejected_when_margin_healthy() {
    let (pre_acct, pre_pos, batch_ts, _breach, healthy_price, _pa, _pp, w) =
        settle_vectors::liquidation_fixture();
    let _ = apply_liq(pre_acct, pre_pos, 0, batch_ts, healthy_price, w);
}

// --- open adequacy (M4) -----------------------------------------------------

#[test]
fn open_passes_at_adequate_price() {
    let (acct_root, pos_root, batch_ts, _low, ok_price, w) =
        settle_vectors::open_undercollateralized();
    let _ = apply_open(acct_root, pos_root, 0, batch_ts, ok_price, w);
}

#[test(should_fail)]
fn open_rejected_when_undercollateralized() {
    let (acct_root, pos_root, batch_ts, low_price, _ok, w) =
        settle_vectors::open_undercollateralized();
    let _ = apply_open(acct_root, pos_root, 0, batch_ts, low_price, w);
}

// --- interest gadget ---------------------------------------------------------

#[test]
fn interest_unit_vectors_match_harness() {
    // (cash, rate_bps, elapsed, expected) incl. zero-elapsed, one-day 430bps
    // on a $10M-equivalent leg, and a 1y max-term boundary (PLAN.md 1.4).
    let cases = settle_vectors::interest_vectors();
    for i in 0..cases.len() {
        let (cash, rate, elapsed, expected) = cases[i];
        constrain_interest(cash, rate, elapsed, expected);
    }
}

#[test(should_fail)]
fn interest_gadget_rejects_off_by_one() {
    let cases = settle_vectors::interest_vectors();
    let (cash, rate, elapsed, expected) = cases[1];
    constrain_interest(cash, rate, elapsed, expected + 1);
}
