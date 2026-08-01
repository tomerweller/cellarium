//! The full custody loop against the real batch_repo fixture — deposits on
//! both assets escrow tokens, the proven batch consumes them, opens a repo
//! position (bilateral), executes a cash transfer + coll withdrawal, and the
//! withdrawal pays out on L1. Also the negative-envelope sweep: every way to
//! lie in the envelope must fail.
//! Fixture scenario: `cargo run -p harness -- demo-repo-batch`
//! (fixtures/batch_repo/meta.json records the constants replayed here).

use oracle::{OracleContract, OracleContractClient};
use rollup::{
    BatchEnvelope, RollupContract, RollupContractClient, RollupError, Withdrawal, ASSET_CASH,
    ASSET_COLL,
};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, vec, Address, Bytes, BytesN, Env, String as SString};

const VK: &[u8] = include_bytes!("../../../fixtures/batch_repo/vk.bin");
const PROOF: &[u8] = include_bytes!("../../../fixtures/batch_repo/proof");
const PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/batch_repo/public_inputs");
const META: &str = include_str!("../../../fixtures/batch_repo/meta.json");

fn hex32(s: &str) -> [u8; 32] {
    let s = s.trim_start_matches("0x");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

struct Setup<'a> {
    env: Env,
    rollup: RollupContractClient<'a>,
    oracle: OracleContractClient<'a>,
    cash: token::TokenClient<'a>,
    coll: token::TokenClient<'a>,
    alice_l1: Address,
    bob_l1: Address,
    operator: Address,
    meta: serde_json::Value,
}

fn setup() -> Setup<'static> {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env.mock_all_auths();
    let meta: serde_json::Value = serde_json::from_str(META).unwrap();
    let batch_ts = meta["batch_ts"].as_u64().unwrap();

    // Ledger clock just past the fixture's claimed batch_ts (inside the
    // one-sided 60s window).
    env.ledger().with_mut(|l| l.timestamp = batch_ts + 5);

    let admin = Address::generate(&env);
    let cash_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let coll_sac = env.register_stellar_asset_contract_v2(admin.clone());

    let alice_l1 = Address::generate(&env);
    let bob_l1 = Address::generate(&env);
    token::StellarAssetClient::new(&env, &cash_sac.address()).mint(&alice_l1, &100_000_000);
    token::StellarAssetClient::new(&env, &coll_sac.address()).mint(&bob_l1, &100_000_000);

    // Mock oracle with a fresh price matching the fixture's price PI.
    let oracle_admin = Address::generate(&env);
    let oracle_id = env.register(OracleContract, (&oracle_admin,));
    let oracle = OracleContractClient::new(&env, &oracle_id);
    let price: i128 = meta["price"].as_str().unwrap().parse().unwrap();
    oracle.set_price(&price);

    let vk = Bytes::from_slice(&env, VK);
    let genesis = BytesN::from_array(&env, &hex32(meta["old_state_root"].as_str().unwrap()));
    let operator = Address::generate(&env);
    // The fixture proof binds instance_id = address_to_field(rollup) as its
    // 8th public input (issue #1 L10), so the contract must live at the
    // exact address the fixture was generated for.
    let instance_addr =
        Address::from_string(&SString::from_str(&env, meta["instance_addr"].as_str().unwrap()));
    let rollup_id = env.register_at(
        &instance_addr,
        RollupContract,
        (cash_sac.address(), coll_sac.address(), oracle_id, operator.clone(), vk, genesis),
    );
    let rollup = RollupContractClient::new(&env, &rollup_id);

    Setup {
        env: env.clone(),
        rollup,
        oracle,
        cash: token::TokenClient::new(&env, &cash_sac.address()),
        coll: token::TokenClient::new(&env, &coll_sac.address()),
        alice_l1,
        bob_l1,
        operator,
        meta,
    }
}

fn fixture_envelope(env: &Env, meta: &serde_json::Value) -> BatchEnvelope {
    let wd = &meta["withdrawals"][0];
    let wd_dest = Address::from_string(&SString::from_str(env, wd["dest"].as_str().unwrap()));
    BatchEnvelope {
        new_root: BytesN::from_array(env, &hex32(meta["new_state_root"].as_str().unwrap())),
        batch_ts: meta["batch_ts"].as_u64().unwrap(),
        deposit_count_cash: 1,
        deposit_count_coll: 1,
        withdrawals: vec![
            env,
            Withdrawal {
                dest: wd_dest,
                asset: wd["asset"].as_u64().unwrap() as u32,
                amount: wd["amount"].as_i64().unwrap() as i128,
            },
        ],
        da_commitment: BytesN::from_array(env, &hex32(meta["da_commitment"].as_str().unwrap())),
        proof: Bytes::from_slice(env, PROOF),
    }
}

fn do_deposits(s: &Setup) {
    let alice_pk = BytesN::from_array(&s.env, &hex32(s.meta["deposits"][0]["pk_x"].as_str().unwrap()));
    let bob_pk = BytesN::from_array(&s.env, &hex32(s.meta["deposits"][1]["pk_x"].as_str().unwrap()));
    s.rollup.deposit(&s.alice_l1, &alice_pk, &ASSET_CASH, &10_000_000);
    s.rollup.deposit(&s.bob_l1, &bob_pk, &ASSET_COLL, &5_000_000);
}

#[test]
fn full_repo_loop() {
    let s = setup();
    let rollup_addr = s.rollup.address.clone();

    do_deposits(&s);
    assert_eq!(s.cash.balance(&rollup_addr), 10_000_000);
    assert_eq!(s.coll.balance(&rollup_addr), 5_000_000);

    let envelope = fixture_envelope(&s.env, &s.meta);
    let sequencer = s.operator.clone();
    s.env.cost_estimate().budget().reset_unlimited();
    s.rollup.submit_batch(&sequencer, &envelope);
    println!(
        "submit_batch (repo) budget: cpu={} mem={}",
        s.env.cost_estimate().budget().cpu_instruction_cost(),
        s.env.cost_estimate().budget().memory_bytes_cost()
    );

    // The 100_000 coll withdrawal paid out; escrow keeps the rest. The repo
    // open itself moves nothing on L1 — positions are invisible here, which
    // is the entire point.
    assert_eq!(s.cash.balance(&rollup_addr), 10_000_000);
    assert_eq!(s.coll.balance(&rollup_addr), 4_900_000);
    let wd_dest = Address::from_string(&SString::from_str(
        &s.env,
        s.meta["withdrawals"][0]["dest"].as_str().unwrap(),
    ));
    assert_eq!(s.coll.balance(&wd_dest), 100_000);

    assert_eq!(
        s.rollup.root(),
        BytesN::from_array(&s.env, &hex32(s.meta["new_state_root"].as_str().unwrap()))
    );
    assert_eq!(s.rollup.batch_num(), 1);

    // Replay must fail: the root has advanced.
    assert!(s.rollup.try_submit_batch(&sequencer, &envelope).is_err());
}

#[test]
fn fixture_public_inputs_match_contract_assembly() {
    // 8 PIs = 256 bytes; roots + batch_ts + price + instance words must
    // match meta (instance_id — issue #1 L10).
    let meta: serde_json::Value = serde_json::from_str(META).unwrap();
    assert_eq!(PUBLIC_INPUTS.len(), 256);
    assert_eq!(&PUBLIC_INPUTS[..32], &hex32(meta["old_state_root"].as_str().unwrap()));
    assert_eq!(&PUBLIC_INPUTS[32..64], &hex32(meta["new_state_root"].as_str().unwrap()));
    // batch_ts word (6th PI).
    let mut ts_word = [0u8; 32];
    ts_word[24..].copy_from_slice(&meta["batch_ts"].as_u64().unwrap().to_be_bytes());
    assert_eq!(&PUBLIC_INPUTS[160..192], &ts_word);
    // price word (7th PI).
    let price: u128 = meta["price"].as_str().unwrap().parse().unwrap();
    let mut price_word = [0u8; 32];
    price_word[16..].copy_from_slice(&price.to_be_bytes());
    assert_eq!(&PUBLIC_INPUTS[192..224], &price_word);
    // instance word (8th PI) = address_to_field(fixture rollup address);
    // the contract derives the same from env.current_contract_address().
    assert_eq!(&PUBLIC_INPUTS[224..256], &hex32(meta["instance_id"].as_str().unwrap()));
    let env = Env::default();
    let addr =
        Address::from_string(&SString::from_str(&env, meta["instance_addr"].as_str().unwrap()));
    assert_eq!(
        rollup::publics::address_to_field(&env, &addr),
        BytesN::from_array(&env, &hex32(meta["instance_id"].as_str().unwrap()))
    );
}

#[test]
fn tampered_da_commitment_fails() {
    let s = setup();
    do_deposits(&s);
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    let mut tampered = hex32(s.meta["da_commitment"].as_str().unwrap());
    tampered[31] ^= 0x01;
    envelope.da_commitment = BytesN::from_array(&s.env, &tampered);
    assert!(s.rollup.try_submit_batch(&s.operator, &envelope).is_err());
}

#[test]
fn wrong_new_root_fails() {
    let s = setup();
    do_deposits(&s);
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    let mut tampered = hex32(s.meta["new_state_root"].as_str().unwrap());
    tampered[31] ^= 0x01;
    envelope.new_root = BytesN::from_array(&s.env, &tampered);
    assert!(s.rollup.try_submit_batch(&s.operator, &envelope).is_err());
}

#[test]
fn wrong_batch_ts_fails_verification() {
    // A claimed ts inside the ledger window but different from the proven
    // 6th public input must fail the proof.
    let s = setup();
    do_deposits(&s);
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    envelope.batch_ts += 1; // still within [ledger-60, ledger]
    assert!(s.rollup.try_submit_batch(&s.operator, &envelope).is_err());
}

#[test]
fn future_or_lagging_batch_ts_rejected() {
    let s = setup();
    do_deposits(&s);
    let ledger_ts = s.meta["batch_ts"].as_u64().unwrap() + 5;

    // Future-dated claimed ts: rejected before verification.
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    envelope.batch_ts = ledger_ts + 1;
    let r = s.rollup.try_submit_batch(&s.operator, &envelope);
    assert_eq!(r, Err(Ok(RollupError::BadTimestamp)));

    // Lag beyond the 60s window: advance the ledger far past the claim.
    s.env.ledger().with_mut(|l| l.timestamp = ledger_ts + 3600);
    let envelope = fixture_envelope(&s.env, &s.meta);
    let r = s.rollup.try_submit_batch(&s.operator, &envelope);
    assert_eq!(r, Err(Ok(RollupError::BadTimestamp)));
}

#[test]
fn stale_price_rejected() {
    let s = setup();
    do_deposits(&s);
    // Age the ledger 6 minutes past the oracle's set_price timestamp, and
    // move the claimed batch_ts along so the timestamp window still passes —
    // isolating the staleness check. (The proof would fail afterwards anyway;
    // StalePrice must fire FIRST.)
    let now = s.meta["batch_ts"].as_u64().unwrap() + 5 + 360;
    s.env.ledger().with_mut(|l| l.timestamp = now);
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    envelope.batch_ts = now - 1;
    let r = s.rollup.try_submit_batch(&s.operator, &envelope);
    assert_eq!(r, Err(Ok(RollupError::StalePrice)));
}

#[test]
fn wrong_price_fails_verification() {
    // A fresh oracle price that differs from the proven 7th public input
    // must fail verification (the contract binds what the oracle says NOW).
    let s = setup();
    do_deposits(&s);
    s.oracle.set_price(&999_999_999i128);
    let envelope = fixture_envelope(&s.env, &s.meta);
    let r = s.rollup.try_submit_batch(&s.operator, &envelope);
    assert_eq!(r, Err(Ok(RollupError::VerificationFailed)));
}

#[test]
fn reasseted_or_tampered_withdrawal_fails() {
    let s = setup();
    do_deposits(&s);
    let sequencer = s.operator.clone();

    // Wrong asset (cash pool instead of coll).
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    let wd = envelope.withdrawals.get(0).unwrap();
    envelope.withdrawals =
        vec![&s.env, Withdrawal { dest: wd.dest.clone(), asset: ASSET_CASH, amount: wd.amount }];
    assert!(s.rollup.try_submit_batch(&sequencer, &envelope).is_err());

    // Wrong amount.
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    let wd = envelope.withdrawals.get(0).unwrap();
    envelope.withdrawals =
        vec![&s.env, Withdrawal { dest: wd.dest.clone(), asset: wd.asset, amount: wd.amount + 1 }];
    assert!(s.rollup.try_submit_batch(&sequencer, &envelope).is_err());

    // Redirected destination.
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    let wd = envelope.withdrawals.get(0).unwrap();
    envelope.withdrawals = vec![
        &s.env,
        Withdrawal { dest: Address::generate(&s.env), asset: wd.asset, amount: wd.amount },
    ];
    assert!(s.rollup.try_submit_batch(&sequencer, &envelope).is_err());
}

#[test]
fn wrong_deposit_count_fails() {
    let s = setup();
    do_deposits(&s);
    let sequencer = s.operator.clone();
    let mut envelope = fixture_envelope(&s.env, &s.meta);
    envelope.deposit_count_cash = 0;
    assert!(s.rollup.try_submit_batch(&sequencer, &envelope).is_err());
    envelope.deposit_count_cash = 2; // more than the cash queue holds
    assert!(s.rollup.try_submit_batch(&sequencer, &envelope).is_err());
}

#[test]
fn missing_deposits_fail() {
    let s = setup();
    let envelope = fixture_envelope(&s.env, &s.meta);
    assert!(s.rollup.try_submit_batch(&s.operator, &envelope).is_err());
}

#[test]
fn deposit_validation() {
    let s = setup();
    let pk = BytesN::from_array(&s.env, &hex32(s.meta["deposits"][0]["pk_x"].as_str().unwrap()));
    assert!(s.rollup.try_deposit(&s.alice_l1, &pk, &ASSET_CASH, &0).is_err());
    assert!(s.rollup.try_deposit(&s.alice_l1, &pk, &ASSET_CASH, &-5).is_err());
    assert!(s
        .rollup
        .try_deposit(&s.alice_l1, &pk, &ASSET_CASH, &(i128::from(u64::MAX) + 1))
        .is_err());
    assert!(s.rollup.try_deposit(&s.alice_l1, &pk, &2u32, &100).is_err());
    let non_canonical = BytesN::from_array(&s.env, &[0xffu8; 32]);
    assert!(s.rollup.try_deposit(&s.alice_l1, &non_canonical, &ASSET_CASH, &100).is_err());
    let zero = BytesN::from_array(&s.env, &[0u8; 32]);
    assert!(s.rollup.try_deposit(&s.alice_l1, &zero, &ASSET_CASH, &100).is_err());
    let pad = BytesN::from_array(&s.env, &rollup::PAD_PK_X);
    assert!(s.rollup.try_deposit(&s.alice_l1, &pad, &ASSET_CASH, &100).is_err());
}
