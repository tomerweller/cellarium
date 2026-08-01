//! submit_batch edge cases the custody-loop suite doesn't reach:
//! withdrawal-list bounds, multi-batch FIFO queue progression (per asset),
//! and the operator-only submit gate (issue #1 H1). All envelope
//! validation under test happens before proof verification, so a
//! fixture-length proof is enough for the rejects; the queue-progression
//! test lands the real fixture proof.
use oracle::{OracleContract, OracleContractClient};
use rollup::{
    BatchEnvelope, RollupContract, RollupContractClient, RollupError, Withdrawal, ASSET_CASH,
    ASSET_COLL,
};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, vec, Address, Bytes, BytesN, Env, String as SString, Vec};

const VK: &[u8] = include_bytes!("../../../fixtures/batch_repo/vk.bin");
const PROOF: &[u8] = include_bytes!("../../../fixtures/batch_repo/proof");
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
    funder: Address,
    operator: Address,
    meta: serde_json::Value,
    batch_ts: u64,
}

fn setup() -> Setup<'static> {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env.mock_all_auths();
    let meta: serde_json::Value = serde_json::from_str(META).unwrap();
    let batch_ts = meta["batch_ts"].as_u64().unwrap();
    env.ledger().with_mut(|l| l.timestamp = batch_ts + 5);

    let admin = Address::generate(&env);
    let cash_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let coll_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let funder = Address::generate(&env);
    token::StellarAssetClient::new(&env, &cash_sac.address()).mint(&funder, &100_000_000);
    token::StellarAssetClient::new(&env, &coll_sac.address()).mint(&funder, &100_000_000);

    let oracle_admin = Address::generate(&env);
    let oracle_id = env.register(OracleContract, (&oracle_admin,));
    let price: i128 = meta["price"].as_str().unwrap().parse().unwrap();
    OracleContractClient::new(&env, &oracle_id).set_price(&price);

    let vk = Bytes::from_slice(&env, VK);
    let genesis = BytesN::from_array(&env, &hex32(meta["old_state_root"].as_str().unwrap()));
    let operator = Address::generate(&env);
    // Pin the fixture's instance address (8th PI, issue #1 L10).
    let instance_addr =
        Address::from_string(&SString::from_str(&env, meta["instance_addr"].as_str().unwrap()));
    let rollup_id = env.register_at(
        &instance_addr,
        RollupContract,
        (cash_sac.address(), coll_sac.address(), oracle_id, operator.clone(), vk, genesis),
    );
    let rollup = RollupContractClient::new(&env, &rollup_id);
    Setup { env: env.clone(), rollup, funder, operator, meta, batch_ts }
}

fn envelope_with_withdrawals(s: &Setup, wds: Vec<Withdrawal>) -> BatchEnvelope {
    BatchEnvelope {
        new_root: BytesN::from_array(&s.env, &[9u8; 32]),
        batch_ts: s.batch_ts,
        deposit_count_cash: 0,
        deposit_count_coll: 0,
        withdrawals: wds,
        da_commitment: BytesN::from_array(&s.env, &[0u8; 32]),
        proof: Bytes::from_slice(&s.env, PROOF), // right length; never reaches verify
    }
}

#[test]
fn five_withdrawals_rejected() {
    // MAX_WITHDRAWALS = 4 aligns the contract with the circuit's T = 4
    // payment slots (issue #1 L14): >4 withdrawals could never verify.
    let s = setup();
    let mut wds = vec![&s.env];
    for _ in 0..5 {
        wds.push_back(Withdrawal { dest: Address::generate(&s.env), asset: ASSET_CASH, amount: 1 });
    }
    let r = s.rollup.try_submit_batch(&s.operator, &envelope_with_withdrawals(&s, wds));
    assert_eq!(r, Err(Ok(RollupError::TooManyWithdrawals)));
    // Exactly 4 passes the bound (and then fails later, at verification).
    let mut wds = vec![&s.env];
    for _ in 0..4 {
        wds.push_back(Withdrawal { dest: Address::generate(&s.env), asset: ASSET_CASH, amount: 1 });
    }
    let r = s.rollup.try_submit_batch(&s.operator, &envelope_with_withdrawals(&s, wds));
    assert_eq!(r, Err(Ok(RollupError::VerificationFailed)));
}

#[test]
fn withdrawal_amount_bounds() {
    let s = setup();
    for bad in [0i128, -5, (u64::MAX as i128) + 1] {
        let wds = vec![
            &s.env,
            Withdrawal { dest: Address::generate(&s.env), asset: ASSET_CASH, amount: bad },
        ];
        let r = s.rollup.try_submit_batch(&s.operator, &envelope_with_withdrawals(&s, wds));
        assert_eq!(r, Err(Ok(RollupError::InvalidAmount)), "amount {bad} must be rejected");
    }
}

#[test]
fn withdrawal_asset_bounds() {
    let s = setup();
    let wds = vec![
        &s.env,
        Withdrawal { dest: Address::generate(&s.env), asset: 2, amount: 1 },
    ];
    let r = s.rollup.try_submit_batch(&s.operator, &envelope_with_withdrawals(&s, wds));
    assert_eq!(r, Err(Ok(RollupError::InvalidAsset)));
}

fn fixture_envelope(s: &Setup) -> BatchEnvelope {
    let wd = &s.meta["withdrawals"][0];
    let wd_dest = Address::from_string(&SString::from_str(&s.env, wd["dest"].as_str().unwrap()));
    BatchEnvelope {
        new_root: BytesN::from_array(&s.env, &hex32(s.meta["new_state_root"].as_str().unwrap())),
        batch_ts: s.batch_ts,
        deposit_count_cash: 1,
        deposit_count_coll: 1,
        withdrawals: vec![
            &s.env,
            Withdrawal {
                dest: wd_dest,
                asset: wd["asset"].as_u64().unwrap() as u32,
                amount: wd["amount"].as_i64().unwrap() as i128,
            },
        ],
        da_commitment: BytesN::from_array(&s.env, &hex32(s.meta["da_commitment"].as_str().unwrap())),
        proof: Bytes::from_slice(&s.env, PROOF),
    }
}

/// Each FIFO queue advances by exactly its deposit_count: entries beyond the
/// consumed prefix stay pending (with their seq/order intact) for the next
/// batch, and consumed entries are gone.
#[test]
fn partial_queue_consumption_across_batches() {
    let s = setup();
    let alice_pk = BytesN::from_array(&s.env, &hex32(s.meta["deposits"][0]["pk_x"].as_str().unwrap()));
    let bob_pk = BytesN::from_array(&s.env, &hex32(s.meta["deposits"][1]["pk_x"].as_str().unwrap()));
    let carol_pk = BytesN::from_array(&s.env, &{
        let mut a = [0u8; 32];
        a[31] = 9; // canonical, nonzero, not PAD
        a
    });

    // Queue three (alice cash, bob coll, carol cash); the fixture batch
    // consumes exactly (1 cash, 1 coll) — carol's cash entry must survive.
    s.rollup.deposit(&s.funder, &alice_pk, &ASSET_CASH, &10_000_000);
    s.rollup.deposit(&s.funder, &bob_pk, &ASSET_COLL, &5_000_000);
    s.rollup.deposit(&s.funder, &carol_pk, &ASSET_CASH, &700);
    assert_eq!((s.rollup.dep_head(&ASSET_CASH), s.rollup.dep_tail(&ASSET_CASH)), (0, 2));

    let envelope = fixture_envelope(&s);
    s.env.cost_estimate().budget().reset_unlimited();
    s.rollup.submit_batch(&s.operator, &envelope);

    assert_eq!((s.rollup.dep_head(&ASSET_CASH), s.rollup.dep_tail(&ASSET_CASH)), (1, 2));
    assert_eq!((s.rollup.dep_head(&ASSET_COLL), s.rollup.dep_tail(&ASSET_COLL)), (1, 1));
    assert_eq!(s.rollup.get_pending_deposit(&ASSET_CASH, &1).amount, 700);
    assert!(s.rollup.try_get_pending_deposit(&ASSET_CASH, &0).is_err());
    assert!(s.rollup.try_get_pending_deposit(&ASSET_COLL, &0).is_err());
    assert_eq!(s.rollup.batch_num(), 1);
}

/// Cross-instance proof replay is rejected (issue #1 L10): a second rollup
/// deployed with the SAME VK and genesis but at a different address derives
/// a different instance_id (8th public input), so the fixture proof — valid
/// on the pinned instance — must fail verification there.
#[test]
fn cross_instance_replay_rejected() {
    let s = setup();
    let admin = Address::generate(&s.env);
    let cash_sac = s.env.register_stellar_asset_contract_v2(admin.clone());
    let coll_sac = s.env.register_stellar_asset_contract_v2(admin);
    token::StellarAssetClient::new(&s.env, &cash_sac.address()).mint(&s.funder, &100_000_000);
    token::StellarAssetClient::new(&s.env, &coll_sac.address()).mint(&s.funder, &100_000_000);
    let oracle_admin = Address::generate(&s.env);
    let oracle_id = s.env.register(OracleContract, (&oracle_admin,));
    let price: i128 = s.meta["price"].as_str().unwrap().parse().unwrap();
    OracleContractClient::new(&s.env, &oracle_id).set_price(&price);

    let vk = Bytes::from_slice(&s.env, VK);
    let genesis =
        BytesN::from_array(&s.env, &hex32(s.meta["old_state_root"].as_str().unwrap()));
    let clone_id = s.env.register(
        RollupContract,
        (cash_sac.address(), coll_sac.address(), oracle_id, s.operator.clone(), vk, genesis),
    );
    let clone = RollupContractClient::new(&s.env, &clone_id);

    // Same deposits, same envelope, same operator — different instance.
    let alice_pk =
        BytesN::from_array(&s.env, &hex32(s.meta["deposits"][0]["pk_x"].as_str().unwrap()));
    let bob_pk =
        BytesN::from_array(&s.env, &hex32(s.meta["deposits"][1]["pk_x"].as_str().unwrap()));
    clone.deposit(&s.funder, &alice_pk, &ASSET_CASH, &10_000_000);
    clone.deposit(&s.funder, &bob_pk, &ASSET_COLL, &5_000_000);
    let envelope = fixture_envelope(&s);
    s.env.cost_estimate().budget().reset_unlimited();
    let r = clone.try_submit_batch(&s.operator, &envelope);
    assert_eq!(r, Err(Ok(RollupError::VerificationFailed)));
}

/// Deposit-queue refunds (issue #1 M5): the head entry can be refunded by
/// anyone once it has aged past REFUND_DELAY_SECS — funds return to the
/// ORIGINAL depositor and the FIFO unblocks for entries behind it.
#[test]
fn deposit_refund_after_timeout() {
    let s = setup();
    let jammed_pk = BytesN::from_array(&s.env, &{
        let mut a = [0u8; 32];
        a[31] = 9; // canonical, nonzero, not PAD
        a
    });
    let funder_before = token_balance(&s, &s.funder);
    s.rollup.deposit(&s.funder, &jammed_pk, &ASSET_CASH, &700);
    assert_eq!(token_balance(&s, &s.funder), funder_before - 700);

    // Too early: the timeout has not elapsed.
    let r = s.rollup.try_refund_deposit(&ASSET_CASH);
    assert_eq!(r, Err(Ok(RollupError::RefundTooEarly)));

    // Age past the refund delay; anyone may now trigger the refund and the
    // funds go back to the recorded depositor.
    let now = s.env.ledger().timestamp();
    s.env.ledger().with_mut(|l| l.timestamp = now + rollup::REFUND_DELAY_SECS + 1);
    assert_eq!(s.rollup.refund_deposit(&ASSET_CASH), 0);
    assert_eq!(token_balance(&s, &s.funder), funder_before);
    assert_eq!((s.rollup.dep_head(&ASSET_CASH), s.rollup.dep_tail(&ASSET_CASH)), (1, 1));

    // Nothing left to refund.
    let r = s.rollup.try_refund_deposit(&ASSET_CASH);
    assert_eq!(r, Err(Ok(RollupError::EmptyQueue)));
}

fn token_balance(s: &Setup, who: &Address) -> i128 {
    let cash = s.rollup.token(&ASSET_CASH);
    token::TokenClient::new(&s.env, &cash).balance(who)
}

/// Submission is operator-only (issue #1 H1): without in-circuit pk_x
/// uniqueness, a permissionless prover could route a queued deposit to a
/// duplicate slot and replay the victim's published signatures against it.
/// A valid envelope from anyone but the pinned operator must be rejected
/// before any other validation, and the same envelope must land when the
/// operator submits it.
#[test]
fn submit_requires_pinned_operator() {
    let s = setup();
    let alice_pk = BytesN::from_array(&s.env, &hex32(s.meta["deposits"][0]["pk_x"].as_str().unwrap()));
    let bob_pk = BytesN::from_array(&s.env, &hex32(s.meta["deposits"][1]["pk_x"].as_str().unwrap()));
    s.rollup.deposit(&s.funder, &alice_pk, &ASSET_CASH, &10_000_000);
    s.rollup.deposit(&s.funder, &bob_pk, &ASSET_COLL, &5_000_000);

    let envelope = fixture_envelope(&s);
    let random_third_party = Address::generate(&s.env);
    s.env.cost_estimate().budget().reset_unlimited();
    let r = s.rollup.try_submit_batch(&random_third_party, &envelope);
    assert_eq!(r, Err(Ok(RollupError::NotOperator)));
    assert_eq!(s.rollup.batch_num(), 0);

    s.rollup.submit_batch(&s.operator, &envelope);
    assert_eq!(s.rollup.batch_num(), 1);
}
