use harness::poseidon::{fr_from_u64, to_hex, Hasher};
use harness::tree::{Account, Asset, Tree};

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        // Shared test vectors pinned in circuits/lib tests (M2 checkpoint).
        "vectors" => vectors(),
        // Schnorr vectors pinned in circuits/lib tests (M3 checkpoint).
        "sig-vectors" => sig_vectors(),
        // Deterministic demo batch -> Prover.toml -> bb -> fixtures/batch_n4.
        "demo-batch" => demo_batch(),
        // Larger batches for cost-scaling measurements -> fixtures/batch_nN.
        "demo-batch-n16" => demo_batch_sized(4, 16, "batch_n16"),
        "demo-batch-n64" => demo_batch_sized(8, 64, "batch_n64"),
        "demo-batch-n128" => demo_batch_sized(8, 128, "batch_n128"),
        "demo-batch-n256" => demo_batch_sized(8, 256, "batch_n256"),
        // Single source of truth for cross-stack golden vectors.
        "vectors-json" => vectors_json(),
        // Witness/signature vectors for the circuit tx_test.nr suite.
        "noir-tx-vectors" => {
            let path = "circuits/lib/src/tx_vectors.nr";
            std::fs::write(path, harness::noir_vectors::emit()).expect("write tx_vectors.nr");
            println!("wrote {path}");
        }
        // Witness vectors for the circuit repo_test.nr + settle_test.nr suites.
        "noir-repo-vectors" => {
            let path = "circuits/lib/src/repo_vectors.nr";
            std::fs::write(path, harness::noir_repo_vectors::emit()).expect("write repo_vectors.nr");
            println!("wrote {path}");
            let path = "circuits/lib/src/settle_vectors.nr";
            std::fs::write(path, harness::noir_repo_vectors::emit_settle())
                .expect("write settle_vectors.nr");
            println!("wrote {path}");
        }
        // Interest helper for e2e assertions: interest <cash> <rate_bps> <elapsed>.
        "interest" => {
            let cash: u64 = std::env::args().nth(2).unwrap().parse().unwrap();
            let rate: u32 = std::env::args().nth(3).unwrap().parse().unwrap();
            let elapsed: u64 = std::env::args().nth(4).unwrap().parse().unwrap();
            println!("{}", harness::settle::interest(cash, rate, elapsed).expect("interest overflow"));
        }
        // Deterministic repo demo batch -> Prover.toml -> bb -> fixtures/batch_repo.
        "demo-repo-batch" => demo_repo_batch(),
        // Combined genesis state root (both trees empty).
        "genesis-state-root" => {
            let hasher = Hasher::new();
            let state = harness::repo::L2State::new();
            println!("{}", to_hex(&state.state_root(&hasher)));
        }
        _ => {
            eprintln!("usage: harness vectors");
            std::process::exit(2);
        }
    }
}

fn vectors() {
    let hasher = Hasher::new();

    println!(
        "hash2(1, 2)            = {}",
        to_hex(&hasher.hash2(fr_from_u64(1), fr_from_u64(2)))
    );
    println!(
        "hash4(1, 2, 3, 4)      = {}",
        to_hex(&hasher.hash(&[fr_from_u64(1), fr_from_u64(2), fr_from_u64(3), fr_from_u64(4)]))
    );

    let empty = Tree::new();
    println!("empty_root (depth 8)   = {}", to_hex(&empty.root(&hasher)));

    let account = Account {
        pk_x: fr_from_u64(1234),
        cash: 100,
        coll: 40,
        nonce: 0,
    };
    println!(
        "bal_hash(100, 40)      = {}",
        to_hex(&Tree::bal_hash(&hasher, 100, 40))
    );
    println!(
        "leaf(1234, 100, 40, 0) = {}",
        to_hex(&Tree::leaf_value(&hasher, Some(&account)))
    );

    let mut one = Tree::new();
    one.set(5, account);
    println!("root(leaf@5)           = {}", to_hex(&one.root(&hasher)));

    // DA fold step (DOMAIN_DA=7, 3-input): acc' = P2([7, acc, msg]).
    println!(
        "da_fold(0, 42)         = {}",
        to_hex(&hasher.hash(&[fr_from_u64(7), fr_from_u64(0), fr_from_u64(42)]))
    );
}

fn sig_vectors() {
    use ark_ec::AffineRepr;
    use harness::keys::{coord_to_fr, sign_with_nonce, verify, Keypair};

    let hasher = Hasher::new();
    let gen = ark_grumpkin::Affine::generator();
    println!("gen_x   = {}", to_hex(&coord_to_fr(&gen.x)));
    println!("gen_y   = {}", to_hex(&coord_to_fr(&gen.y)));

    // Deterministic vector: sk = 7, k = 13, msg = 42 (raw; padding constants).
    let keypair = Keypair::from_sk_raw(ark_grumpkin::Fr::from(7u64));
    println!("pk_x    = {}", to_hex(&keypair.pk_x()));
    println!("pk_y    = {}", to_hex(&keypair.pk_y()));

    let msg = fr_from_u64(42);
    let sig = sign_with_nonce(&hasher, &keypair, msg, ark_grumpkin::Fr::from(13u64));
    assert!(verify(&hasher, &keypair.pk, msg, &sig), "self-check failed");
    let (s_lo, s_hi) = sig.s_limbs();
    println!("msg     = 42");
    println!("r_x     = {}", to_hex(&sig.r_x));
    println!("r_y     = {}", to_hex(&sig.r_y));
    println!("s_lo    = {}", to_hex(&s_lo));
    println!("s_hi    = {}", to_hex(&s_hi));
}

/// The deterministic scenario replayed by the contract's custody-loop test
/// (contracts/rollup/tests/custody_loop.rs). Every constant here is part of
/// the fixture contract between harness and test: alice sk=101 deposits 1000,
/// bob sk=202 deposits 500, alice pays bob 200, bob withdraws 100 to the
/// contract-type address derived from [7u8; 32] (C-addresses receive SAC
/// tokens without a trustline, so the test can assert its balance directly).
fn wd_addr() -> String {
    stellar_strkey::Contract([7u8; 32]).to_string()
}

fn demo_batch() {
    use harness::batch::{build_batch, make_signed_tx, DepositRequest};
    use harness::l1::address_to_field;
    use harness::prover;
    use harness::tree::Tree;
    use rand::SeedableRng;

    let hasher = Hasher::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);

    let alice = harness::keys::Keypair::from_sk(ark_grumpkin::Fr::from(101u64));
    let bob = harness::keys::Keypair::from_sk(ark_grumpkin::Fr::from(202u64));
    let wd_addr = wd_addr();
    let wd_field = address_to_field(&hasher, &wd_addr);

    let mut tree = Tree::new();
    let txs = [
        make_signed_tx(&hasher, &alice, bob.pk_x(), Asset::Cash, 200, 0, false, &mut rng),
        make_signed_tx(&hasher, &bob, wd_field, Asset::Coll, 100, 0, true, &mut rng),
    ];
    let witness = build_batch(
        &hasher,
        &mut tree,
        2,
        4,
        &[
            DepositRequest { pk_x: alice.pk_x(), asset: Asset::Cash, amount: 1000 },
            DepositRequest { pk_x: bob.pk_x(), asset: Asset::Coll, amount: 500 },
        ],
        &txs,
    )
    .expect("demo batch must build");

    println!("old_root      = {}", to_hex(&witness.old_root));
    println!("new_root      = {}", to_hex(&witness.new_root));
    println!("deposit_hash  = {}", to_hex(&witness.deposit_hash));
    println!("withdraw_hash = {}", to_hex(&witness.withdraw_hash));
    println!("da_commitment = {}", to_hex(&witness.da_commitment));

    // Metadata for the contract test to replay the same scenario.
    let meta = serde_json::json!({
        "old_root": to_hex(&witness.old_root),
        "new_root": to_hex(&witness.new_root),
        "deposit_hash": to_hex(&witness.deposit_hash),
        "withdraw_hash": to_hex(&witness.withdraw_hash),
        "da_commitment": to_hex(&witness.da_commitment),
        "deposits": [
            { "pk_x": to_hex(&alice.pk_x()), "asset": 0, "amount": 1000 },
            { "pk_x": to_hex(&bob.pk_x()), "asset": 1, "amount": 500 },
        ],
        "withdrawals": [ { "dest": wd_addr, "asset": 1, "amount": 100 } ],
    });
    let root = prover::repo_root();
    let fixture_dir = root.join("fixtures/batch_n4");
    std::fs::create_dir_all(&fixture_dir).unwrap();
    std::fs::write(
        fixture_dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();

    let toml = prover::to_prover_toml(&witness);
    prover::prove("batch_n4", &toml).expect("prove pipeline failed");

    // CLI-ready envelope (stellar contract invoke JSON arg conventions:
    // BytesN/Bytes as hex, Address as strkey, struct fields snake_case).
    let proof = std::fs::read(fixture_dir.join("proof")).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let envelope = serde_json::json!({
        "new_root": to_hex(&witness.new_root).trim_start_matches("0x"),
        "deposit_count_cash": 1,
        "deposit_count_coll": 1,
        "withdrawals": [ { "dest": wd_addr, "asset": 1, "amount": "100" } ],
        "da_commitment": to_hex(&witness.da_commitment).trim_start_matches("0x"),
        "proof": hex(&proof),
    });
    std::fs::write(
        fixture_dir.join("envelope.json"),
        serde_json::to_string(&envelope).unwrap(),
    )
    .unwrap();
    println!("wrote fixtures/batch_n4/{{meta.json, envelope.json}}");
}

/// The deterministic repo scenario replayed by the contract's repo-loop test:
/// alice (sk=101) deposits 10M cash, bob (sk=202) deposits 5M coll; bob
/// borrows 1M cash from alice against 3M coll (430 bps, 2% haircut, 1 day);
/// then alice pays bob 250k cash and bob withdraws 100k coll to wd_addr().
fn demo_repo_batch() {
    use harness::batch::{make_signed_tx, DepositRequest};
    use harness::keys::sign_with_nonce;
    use harness::l1::address_to_field;
    use harness::prover;
    use harness::repo::{build_repo_batch, open_message, L2State, OpenRequest, Position};
    use rand::SeedableRng;

    let hasher = Hasher::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(3);

    let alice = harness::keys::Keypair::from_sk(ark_grumpkin::Fr::from(101u64)); // lender
    let bob = harness::keys::Keypair::from_sk(ark_grumpkin::Fr::from(202u64)); // borrower
    let wd_addr = wd_addr();
    let wd_field = address_to_field(&hasher, &wd_addr);

    const BATCH_TS: u64 = 1_700_000_100;
    const PRICE: u64 = 250_000_000; // 25 XLM per tUST × 1e7

    let mut state = L2State::new();
    let deposits = [
        DepositRequest { pk_x: alice.pk_x(), asset: Asset::Cash, amount: 10_000_000 },
        DepositRequest { pk_x: bob.pk_x(), asset: Asset::Coll, amount: 5_000_000 },
    ];
    let position = Position {
        borrower_pk_x: bob.pk_x(),
        lender_pk_x: alice.pk_x(),
        cash: 1_000_000,
        coll: 3_000_000,
        rate_bps: 430,
        haircut_bps: 200,
        open_ts: 1_700_000_000,
        maturity_ts: 1_700_000_000 + 86_400,
    };
    let open_msg = open_message(&hasher, &position, 0, 0);
    let open = OpenRequest {
        position: position.clone(),
        borrower_pk_y: bob.pk_y(),
        lender_pk_y: alice.pk_y(),
        borrower_nonce: 0,
        lender_nonce: 0,
        borrower_sig: sign_with_nonce(&hasher, &bob, open_msg, ark_grumpkin::Fr::from(9101u64)),
        lender_sig: sign_with_nonce(&hasher, &alice, open_msg, ark_grumpkin::Fr::from(9102u64)),
    };
    let txs = [
        make_signed_tx(&hasher, &alice, bob.pk_x(), Asset::Cash, 250_000, 1, false, &mut rng),
        make_signed_tx(&hasher, &bob, wd_field, Asset::Coll, 100_000, 1, true, &mut rng),
    ];
    let witness = build_repo_batch(
        &hasher,
        &mut state,
        (4, 2, 2, 2, 4),
        &deposits,
        &[],
        &[],
        &[open],
        &txs,
        BATCH_TS,
        PRICE,
    )
    .expect("demo repo batch must build");

    println!("old_state_root = {}", to_hex(&witness.old_state_root));
    println!("new_state_root = {}", to_hex(&witness.new_state_root));
    println!("da_commitment  = {}", to_hex(&witness.da_commitment));

    let meta = serde_json::json!({
        "old_state_root": to_hex(&witness.old_state_root),
        "new_state_root": to_hex(&witness.new_state_root),
        "deposit_hash": to_hex(&witness.deposit_hash),
        "withdraw_hash": to_hex(&witness.withdraw_hash),
        "da_commitment": to_hex(&witness.da_commitment),
        "batch_ts": BATCH_TS,
        "price": PRICE.to_string(),
        "deposits": [
            { "pk_x": to_hex(&alice.pk_x()), "asset": 0, "amount": 10000000 },
            { "pk_x": to_hex(&bob.pk_x()), "asset": 1, "amount": 5000000 },
        ],
        "open": {
            "borrower_pk_x": to_hex(&bob.pk_x()),
            "lender_pk_x": to_hex(&alice.pk_x()),
            "cash": 1000000, "coll": 3000000,
            "rate_bps": 430, "haircut_bps": 200,
            "open_ts": 1700000000u64, "maturity_ts": 1700086400u64,
            "pos_index": witness.open_slots[0],
        },
        "withdrawals": [ { "dest": wd_addr, "asset": 1, "amount": 100000 } ],
    });
    let root = prover::repo_root();
    let fixture_dir = root.join("fixtures/batch_repo");
    std::fs::create_dir_all(&fixture_dir).unwrap();
    std::fs::write(
        fixture_dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();

    let toml = prover::to_repo_prover_toml(&witness);
    prover::prove("batch_repo", &toml).expect("prove pipeline failed");

    let proof = std::fs::read(fixture_dir.join("proof")).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let envelope = serde_json::json!({
        "new_root": to_hex(&witness.new_state_root).trim_start_matches("0x"),
        "deposit_count_cash": 1,
        "deposit_count_coll": 1,
        "withdrawals": [ { "dest": wd_addr, "asset": 1, "amount": "100000" } ],
        "da_commitment": to_hex(&witness.da_commitment).trim_start_matches("0x"),
        "batch_ts": BATCH_TS,
        "proof": hex(&proof),
    });
    std::fs::write(
        fixture_dir.join("envelope.json"),
        serde_json::to_string(&envelope).unwrap(),
    )
    .unwrap();
    println!("wrote fixtures/batch_repo/{{meta.json, envelope.json}}");
}

/// D deposits + N txs (N-2 transfers, 2 withdrawals) purely for cost-scaling
/// measurements; no meta/envelope needed (measured via the verify entrypoint).
fn demo_batch_sized(d: usize, n: usize, pkg: &str) {
    use harness::batch::{build_batch, make_signed_tx, DepositRequest};
    use harness::l1::address_to_field;
    use harness::prover;
    use harness::tree::Tree;
    use rand::SeedableRng;
    use std::collections::HashMap;

    let hasher = Hasher::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);

    let users: Vec<harness::keys::Keypair> = (0..d)
        .map(|i| harness::keys::Keypair::from_sk(ark_grumpkin::Fr::from(301u64 + i as u64)))
        .collect();
    let wd_field = address_to_field(&hasher, &wd_addr());

    let mut tree = Tree::new();
    // Alternate assets so scaling batches exercise both balance legs.
    let deposits: Vec<DepositRequest> = users
        .iter()
        .enumerate()
        .map(|(i, u)| DepositRequest {
            pk_x: u.pk_x(),
            asset: if i < d / 2 { Asset::Cash } else { Asset::Coll },
            amount: 1_000_000,
        })
        .collect();

    let mut nonces: HashMap<usize, u64> = HashMap::new();
    let mut next_nonce = |user: usize| {
        let n = nonces.entry(user).or_insert(0);
        let cur = *n;
        *n += 1;
        cur
    };

    let mut txs = Vec::new();
    for i in 0..n - 2 {
        let from = i % d;
        let to = &users[(i + 1) % d];
        let nonce = next_nonce(from);
        // Spend the asset this user was funded with.
        let asset = if from < d / 2 { Asset::Cash } else { Asset::Coll };
        txs.push(make_signed_tx(&hasher, &users[from], to.pk_x(), asset, 50 + i as u64, nonce, false, &mut rng));
    }
    let n0 = next_nonce(0);
    txs.push(make_signed_tx(&hasher, &users[0], wd_field, Asset::Cash, 77, n0, true, &mut rng));
    let n1 = next_nonce(1);
    txs.push(make_signed_tx(&hasher, &users[1], wd_field, Asset::Cash, 88, n1, true, &mut rng));

    let witness = build_batch(&hasher, &mut tree, d, n, &deposits, &txs).expect("demo batch must build");
    println!("new_root = {}", to_hex(&witness.new_root));

    let toml = prover::to_prover_toml(&witness);
    prover::prove(pkg, &toml).expect("prove pipeline failed");
}

/// Emit fixtures/vectors.json — the single source of truth for the golden
/// vectors every stack pins: wallet vitest imports it directly, the contract
/// equivalence test include_str!s it, and scripts/check_vectors.sh fails CI
/// when the checked-in copy (or the Noir constants mirroring it) drifts.
fn vectors_json() {
    use harness::batch::{build_batch, make_signed_tx, DepositRequest};
    use harness::keys::{pad_signature, Keypair};
    use harness::l1::address_to_field;
    use harness::tree::Tree as T;
    use rand::SeedableRng;

    let hasher = Hasher::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);

    // Primitive vectors (mirrored as pinned constants in circuits/lib tests).
    let hash2 = hasher.hash2(fr_from_u64(1), fr_from_u64(2));
    let hash4 = hasher.hash(&[fr_from_u64(1), fr_from_u64(2), fr_from_u64(3), fr_from_u64(4)]);
    let da_fold = hasher.hash(&[fr_from_u64(harness::batch::DOMAIN_DA), fr_from_u64(0), fr_from_u64(42)]);
    let empty_root = T::new().root(&hasher);
    let mut t5 = T::new();
    t5.set(5, Account { pk_x: fr_from_u64(1234), cash: 100, coll: 40, nonce: 0 });
    let bal_hash = T::bal_hash(&hasher, 100, 40);
    let leaf = T::leaf_value(&hasher, t5.get(5));
    let root5 = t5.root(&hasher);
    // Fold-step primitives for the multi-asset deposit/withdraw folds.
    let dep2_fold = harness::batch::dep_fold(
        &hasher,
        harness::poseidon::FR_ZERO,
        fr_from_u64(1234),
        Asset::Coll,
        77,
    );
    let wd2_fold = harness::batch::wd_fold(
        &hasher,
        harness::poseidon::FR_ZERO,
        fr_from_u64(1234),
        Asset::Coll,
        77,
    );

    // Pad signature (sk=7, k=13, msg=42) — the PAD_* globals in tx.nr.
    let pad_kp = Keypair::from_sk_raw(ark_grumpkin::Fr::from(7u64));
    let pad_sig = pad_signature(&hasher);
    let (pad_lo, pad_hi) = pad_sig.s_limbs();

    // Repo primitives (M2): the demo position's leaf + open message, and the
    // empty combined state root. Pinned by circuits repo tests + wallet.
    let alice_kp = Keypair::from_sk(ark_grumpkin::Fr::from(101u64));
    let bob_kp = Keypair::from_sk(ark_grumpkin::Fr::from(202u64));
    let demo_pos = harness::repo::Position {
        borrower_pk_x: bob_kp.pk_x(),
        lender_pk_x: alice_kp.pk_x(),
        cash: 1_000_000,
        coll: 3_000_000,
        rate_bps: 430,
        haircut_bps: 200,
        open_ts: 1_700_000_000,
        maturity_ts: 1_700_086_400,
    };
    let demo_pos_leaf = harness::repo::pos_leaf(&hasher, &demo_pos);
    let demo_open_msg = harness::repo::open_message(&hasher, &demo_pos, 0, 0);
    let demo_close_msg = harness::settle::close_message(&hasher, 0, &demo_pos, 1);
    let empty_state_root = harness::repo::L2State::new().state_root(&hasher);

    // The demo scenario shared with fixtures/batch_n4 (meta.json).
    let alice = Keypair::from_sk(ark_grumpkin::Fr::from(101u64));
    let bob = Keypair::from_sk(ark_grumpkin::Fr::from(202u64));
    let wd_dest = wd_addr();
    let wd_field = address_to_field(&hasher, &wd_dest);
    let mut tree = T::new();
    let txs = [
        make_signed_tx(&hasher, &alice, bob.pk_x(), Asset::Cash, 200, 0, false, &mut rng),
        make_signed_tx(&hasher, &bob, wd_field, Asset::Coll, 100, 0, true, &mut rng),
    ];
    let w = build_batch(
        &hasher,
        &mut tree,
        2,
        4,
        &[
            DepositRequest { pk_x: alice.pk_x(), asset: Asset::Cash, amount: 1000 },
            DepositRequest { pk_x: bob.pk_x(), asset: Asset::Coll, amount: 500 },
        ],
        &txs,
    )
    .expect("demo scenario must build");
    let msg1 = harness::batch::tx_message(&hasher, alice.pk_x(), bob.pk_x(), Asset::Cash, 200, 0, false);

    let json = serde_json::json!({
        "_generated": "cargo run -p harness -- vectors-json (do not edit; scripts/check_vectors.sh gates drift)",
        "hash2_1_2": to_hex(&hash2),
        "hash4_1_2_3_4": to_hex(&hash4),
        "da_fold_0_42": to_hex(&da_fold),
        "empty_root_d8": to_hex(&empty_root),
        "bal_hash_100_40": to_hex(&bal_hash),
        "leaf_1234_100_40_0": to_hex(&leaf),
        "root_leaf_at_5": to_hex(&root5),
        "dep2_fold_0_1234_coll_77": to_hex(&dep2_fold),
        "wd2_fold_0_1234_coll_77": to_hex(&wd2_fold),
        "empty_state_root": to_hex(&empty_state_root),
        "repo_demo_position": {
            "borrower_pk_x": to_hex(&demo_pos.borrower_pk_x),
            "lender_pk_x": to_hex(&demo_pos.lender_pk_x),
            "cash": "1000000", "coll": "3000000",
            "rate_bps": 430, "haircut_bps": 200,
            "open_ts": 1700000000u64, "maturity_ts": 1700086400u64,
            "pos_leaf": to_hex(&demo_pos_leaf),
            "open_msg_n0_n0": to_hex(&demo_open_msg),
            "close_msg_slot0_n1": to_hex(&demo_close_msg),
        },
        "interest_vectors": [
            { "cash": "1000000", "rate_bps": 430, "elapsed": 0, "interest": harness::settle::interest(1_000_000, 430, 0).unwrap().to_string() },
            { "cash": "100000000000000", "rate_bps": 430, "elapsed": 86400, "interest": harness::settle::interest(100_000_000_000_000, 430, 86_400).unwrap().to_string() },
            { "cash": "1000000000", "rate_bps": 1250, "elapsed": 31536000, "interest": harness::settle::interest(1_000_000_000, 1250, 31_536_000).unwrap().to_string() },
        ],
        "pad": {
            "pk_x": to_hex(&pad_kp.pk_x()),
            "pk_y": to_hex(&pad_kp.pk_y()),
            "r_x": to_hex(&pad_sig.r_x),
            "r_y": to_hex(&pad_sig.r_y),
            "s_lo": to_hex(&pad_lo),
            "s_hi": to_hex(&pad_hi),
        },
        "alice_pk_x": to_hex(&alice.pk_x()),
        "bob_pk_x": to_hex(&bob.pk_x()),
        "wd_dest": wd_dest,
        "wd_dest_field": to_hex(&wd_field),
        "tx_message_alice_bob_cash_200_0": to_hex(&msg1),
        "demo": {
            "old_root": to_hex(&w.old_root),
            "new_root": to_hex(&w.new_root),
            "deposit_hash": to_hex(&w.deposit_hash),
            "withdraw_hash": to_hex(&w.withdraw_hash),
            "da_commitment": to_hex(&w.da_commitment),
            "deposits": [
                { "pk_x": to_hex(&alice.pk_x()), "asset": 0, "amount": "1000" },
                { "pk_x": to_hex(&bob.pk_x()), "asset": 1, "amount": "500" },
            ],
            "withdrawals": [ { "dest": wd_dest, "asset": 1, "amount": "100" } ],
        },
    });
    let path = "fixtures/vectors.json";
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&json).unwrap()))
        .expect("write vectors.json");
    println!("wrote {path}");
}
