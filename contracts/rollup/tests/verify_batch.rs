//! The real batch_repo proof (2 deposits, 1 bilateral open, 1 transfer,
//! 1 withdrawal + padding) verifies on-chain via the raw verify entrypoint.
//! Regenerate fixtures with `cargo run -p harness -- demo-repo-batch`.

use rollup::{RollupContract, RollupContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env};

const VK: &[u8] = include_bytes!("../../../fixtures/batch_repo/vk.bin");
const PROOF: &[u8] = include_bytes!("../../../fixtures/batch_repo/proof");
const PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/batch_repo/public_inputs");

fn setup(env: &Env) -> RollupContractClient<'_> {
    let vk = Bytes::from_slice(env, VK);
    let token_cash = Address::generate(env);
    let token_coll = Address::generate(env);
    let oracle = Address::generate(env);
    let operator = Address::generate(env);
    let genesis = BytesN::from_array(env, &[0u8; 32]);
    let id = env.register(RollupContract, (token_cash, token_coll, oracle, operator, vk, genesis));
    RollupContractClient::new(env, &id)
}

#[test]
fn batch_proof_verifies() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let client = setup(&env);

    assert_eq!(PUBLIC_INPUTS.len(), 256, "8 public inputs expected");
    let proof = Bytes::from_slice(&env, PROOF);
    let pis = Bytes::from_slice(&env, PUBLIC_INPUTS);

    env.cost_estimate().budget().reset_unlimited();
    client.verify(&pis, &proof);

    println!(
        "batch_repo verify budget: cpu={} mem={}",
        env.cost_estimate().budget().cpu_instruction_cost(),
        env.cost_estimate().budget().memory_bytes_cost()
    );
}

#[test]
fn batch_proof_rejects_wrong_root() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let client = setup(&env);

    // Flip a byte in new_root (second 32-byte word).
    let mut wrong = PUBLIC_INPUTS.to_vec();
    wrong[63] ^= 0x01;
    let proof = Bytes::from_slice(&env, PROOF);
    let pis = Bytes::from_slice(&env, &wrong);
    assert!(client.try_verify(&pis, &proof).is_err());
}
