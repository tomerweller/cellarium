//! Repo ZK-rollup contract (multi-asset validium): custody of two SEP-41
//! tokens — cash (XLM) and collateral (tUST) — with the combined state root
//! (accounts + positions) advanced by UltraHonk-proven batches carrying the
//! full 8-public-input interface: old/new state roots, deposit/withdraw
//! folds, DA commitment, batch timestamp (one-sided window), the oracle
//! price, and the instance id — address_to_field(this contract) — so proofs
//! cannot replay across deployments sharing a VK (issue #1 L10).
//! (DESIGN.md, PLAN.md.)
#![no_std]

pub mod events;
pub mod publics;
pub mod storage;

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, token, Address, Bytes,
    BytesN, Env, Vec,
};
pub use storage::{PendingDeposit, ASSET_CASH, ASSET_COLL};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, PROOF_BYTES};

/// Inline withdrawal execution cap per batch. The circuit proves at most
/// T = 4 payments per batch, so more than 4 withdrawals can never verify —
/// keep the contract bound aligned with the circuit capacity (issue #1 L14).
pub const MAX_WITHDRAWALS: u32 = 4;
/// L2 balances are u64 in-circuit; deposits must fit.
///
/// Deployment invariant: each custody token's total supply (in base units)
/// must be <= u64::MAX. The circuit conserves value per asset, so no L2
/// balance can exceed the tokens escrowed, and escrow can't exceed supply —
/// a balance overflow (unprovable queue head) is arithmetically impossible.
/// Native XLM qualifies (~1.05e18 stroops < u64::MAX ~1.84e19); the mock
/// tUST token enforces the cap in its mint (contracts/tust).
pub const MAX_AMOUNT: i128 = (u64::MAX as i128) + 1;

/// Claimed batch timestamp must satisfy claimed <= ledger.timestamp() and
/// ledger.timestamp() - claimed <= this window (one-sided, past only:
/// premature default/liquidation via a future-dated batch is impossible;
/// PLAN.md 6.1.3).
pub const MAX_TS_LAG_SECS: u64 = 60;
/// Oracle price must be at most this old at submission (PLAN.md 1.5).
pub const MAX_PRICE_AGE_SECS: u64 = 300;

/// How long a deposit-queue entry must sit unconsumed before anyone may
/// trigger its refund (issue #1 M5). A healthy sequencer consumes deposits
/// within minutes; an entry this old is jammed (tree full / operator gone),
/// and because the FIFO prefix is mandatory it blocks everything behind it.
/// Refunds are head-only and pay the ORIGINAL depositor, so the permission-
/// less trigger can at worst return someone's own funds to them.
pub const REFUND_DELAY_SECS: u64 = 86_400;

/// Public padding account x-coordinate (circuits PAD_PK_X / sk=7·G). Deposits
/// to this key are rejected — the secret is public, so any credit would be
/// immediately drainable by anyone.
pub const PAD_PK_X: [u8; 32] = [
    0x0e, 0x60, 0x2b, 0x9d, 0xd6, 0xa3, 0xe8, 0xd0, 0x39, 0xa1, 0x7f, 0x06, 0x9a, 0xdd, 0x3f, 0x9c,
    0x2a, 0x18, 0x7a, 0x8f, 0x62, 0x9a, 0x1d, 0xe6, 0x0a, 0x33, 0xa8, 0x06, 0x7b, 0x9b, 0x28, 0x42,
];

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RollupError {
    InvalidVerificationKey = 1,
    InvalidProofLength = 2,
    VerificationFailed = 3,
    InvalidAmount = 4,
    NonCanonicalField = 5,
    TooManyWithdrawals = 6,
    NotEnoughDeposits = 7,
    /// Deposit targets the public padding keypair.
    ReservedPaddingPk = 9,
    /// Asset id out of range (must be 0 = cash or 1 = coll).
    InvalidAsset = 10,
    /// Claimed batch_ts is in the future or lags the ledger by > 60s.
    BadTimestamp = 11,
    /// Oracle has no price or it is older than MAX_PRICE_AGE_SECS.
    StalePrice = 12,
    /// submit_batch caller is not the pinned operator (issue #1 H1).
    NotOperator = 13,
    /// refund_deposit: the queue is empty (nothing to refund).
    EmptyQueue = 14,
    /// refund_deposit: the head entry is younger than REFUND_DELAY_SECS.
    RefundTooEarly = 15,
}

/// Mirror of the oracle's PriceData (contracts/oracle); field names must
/// match for the contracttype map encoding.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PriceData {
    pub price: i128,
    pub timestamp: u64,
}

/// Minimal client for the mock oracle's read surface.
#[contractclient(name = "OracleClient")]
pub trait OracleInterface {
    fn lastprice(env: Env) -> Option<PriceData>;
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchEnvelope {
    pub new_root: BytesN<32>,
    /// Claimed batch timestamp (6th public input): the value the circuit's
    /// time logic uses. Bound one-sidedly to the ledger clock (see
    /// MAX_TS_LAG_SECS) so proving isn't racing the ledger.
    pub batch_ts: u64,
    /// How many entries of each FIFO deposit queue this batch consumes.
    /// The proven deposit fold covers the cash prefix, then the coll prefix.
    pub deposit_count_cash: u32,
    pub deposit_count_coll: u32,
    pub withdrawals: Vec<Withdrawal>,
    /// Poseidon2 fold over the batch's tx messages (DOMAIN_DA), proven
    /// in-circuit as the 5th public input. Validium: the blob itself lives
    /// off-chain (sequencer DA endpoint); verifiers re-fold it against this
    /// commitment.
    pub da_commitment: BytesN<32>,
    pub proof: Bytes,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub dest: Address,
    pub asset: u32,
    pub amount: i128,
}

#[contract]
pub struct RollupContract;

#[contractimpl]
impl RollupContract {
    pub fn __constructor(
        env: Env,
        token_cash: Address,
        token_coll: Address,
        oracle: Address,
        operator: Address,
        vk: Bytes,
        genesis_root: BytesN<32>,
    ) -> Result<(), RollupError> {
        // Parse-validate the VK. 8 user PIs (old/new state roots,
        // deposit_hash, withdraw_hash, da_commitment, batch_ts, price,
        // instance_id) + 16 pairing.
        UltraHonkVerifier::new(&env, &vk).map_err(|_| RollupError::InvalidVerificationKey)?;
        storage::set_vk(&env, &vk);
        storage::set_token(&env, ASSET_CASH, &token_cash);
        storage::set_token(&env, ASSET_COLL, &token_coll);
        storage::set_oracle(&env, &oracle);
        storage::set_operator(&env, &operator);
        storage::set_root(&env, &genesis_root);
        Ok(())
    }

    /// Escrow `amount` of the asset's pinned token and enqueue an L2 credit
    /// to the account with public key x-coordinate `l2_pk_x`. The credit
    /// lands when a batch consumes the queue entry.
    pub fn deposit(
        env: Env,
        from: Address,
        l2_pk_x: BytesN<32>,
        asset: u32,
        amount: i128,
    ) -> Result<u64, RollupError> {
        from.require_auth();
        if asset > ASSET_COLL {
            return Err(RollupError::InvalidAsset);
        }
        if amount <= 0 || amount >= MAX_AMOUNT {
            return Err(RollupError::InvalidAmount);
        }
        let arr = l2_pk_x.to_array();
        if !publics::is_canonical_field(&arr) || arr == publics::FR_ZERO_WORD {
            return Err(RollupError::NonCanonicalField);
        }
        if arr == PAD_PK_X {
            return Err(RollupError::ReservedPaddingPk);
        }

        // Balance overflow (unprovable queue head) needs no per-key tracking:
        // see the deployment invariant on MAX_AMOUNT — per-asset total supply
        // <= u64::MAX bounds every L2 balance below the circuit's u64 range.
        let token_client = token::TokenClient::new(&env, &storage::get_token(&env, asset));
        token_client.transfer(&from, env.current_contract_address(), &amount);

        let seq = storage::enqueue_deposit(
            &env,
            asset,
            &PendingDeposit {
                pk_x: l2_pk_x.clone(),
                amount,
                from,
                enqueued_at: env.ledger().timestamp(),
            },
        );
        events::Deposit {
            seq: &seq,
            asset: &asset,
            pk_x: &l2_pk_x,
            amount: &amount,
        }
        .publish(&env);
        Ok(seq)
    }

    /// Refund the HEAD entry of an asset's deposit queue to its original
    /// depositor once it has sat unconsumed for REFUND_DELAY_SECS (issue #1
    /// M5). Permissionless: the funds can only go back to the recorded
    /// depositor, and clearing a jammed head is exactly what unblocks the
    /// FIFO for everyone queued behind it (accounts are never evicted, so a
    /// deposit to a fresh pk_x with the 256-slot tree full is unconsumable
    /// forever). Head-only keeps the on-chain fold semantics intact — no
    /// tombstones inside the provable prefix.
    pub fn refund_deposit(env: Env, asset: u32) -> Result<u64, RollupError> {
        if asset > ASSET_COLL {
            return Err(RollupError::InvalidAsset);
        }
        let head = storage::dep_head(&env, asset);
        if head >= storage::dep_tail(&env, asset) {
            return Err(RollupError::EmptyQueue);
        }
        let dep = storage::get_deposit(&env, asset, head);
        let now = env.ledger().timestamp();
        if now < dep.enqueued_at + REFUND_DELAY_SECS {
            return Err(RollupError::RefundTooEarly);
        }
        let token_client = token::TokenClient::new(&env, &storage::get_token(&env, asset));
        token_client.transfer(&env.current_contract_address(), &dep.from, &dep.amount);
        storage::dequeue_deposits(&env, asset, 1);
        events::Refund {
            seq: &head,
            asset: &asset,
            to: &dep.from,
            amount: &dep.amount,
        }
        .publish(&env);
        Ok(head)
    }

    /// Verify a batch proof against the current root and the FIFO prefixes of
    /// both deposit queues; on success advance the root, release the consumed
    /// deposits, and pay out the batch's withdrawals.
    ///
    /// Operator-only (issue #1 H1): while the circuit does not enforce pk_x
    /// uniqueness across account slots, a permissionless prover could route
    /// a queued deposit to a duplicate slot and replay the victim's published
    /// nonce-0 signatures against it. Pinning the submitter restores the
    /// documented single-operator trust model.
    pub fn submit_batch(
        env: Env,
        sequencer: Address,
        envelope: BatchEnvelope,
    ) -> Result<(), RollupError> {
        sequencer.require_auth();
        if sequencer != storage::get_operator(&env) {
            return Err(RollupError::NotOperator);
        }

        if envelope.proof.len() as usize != PROOF_BYTES {
            return Err(RollupError::InvalidProofLength);
        }
        if envelope.withdrawals.len() > MAX_WITHDRAWALS {
            return Err(RollupError::TooManyWithdrawals);
        }
        let counts = [envelope.deposit_count_cash, envelope.deposit_count_coll];
        for asset in [ASSET_CASH, ASSET_COLL] {
            let head = storage::dep_head(&env, asset);
            let tail = storage::dep_tail(&env, asset);
            if head + counts[asset as usize] as u64 > tail {
                return Err(RollupError::NotEnoughDeposits);
            }
        }

        // --- timestamp: one-sided past-only window (PLAN.md 6.1.3) ---
        let ledger_ts = env.ledger().timestamp();
        if envelope.batch_ts > ledger_ts || ledger_ts - envelope.batch_ts > MAX_TS_LAG_SECS {
            return Err(RollupError::BadTimestamp);
        }

        // --- price: read the oracle inside this invocation (PLAN.md 1.5) ---
        let oracle = OracleClient::new(&env, &storage::get_oracle(&env));
        let price_data = oracle.lastprice().ok_or(RollupError::StalePrice)?;
        if price_data.timestamp + MAX_PRICE_AGE_SECS < ledger_ts {
            return Err(RollupError::StalePrice);
        }
        if price_data.price <= 0 || price_data.price >= MAX_AMOUNT {
            return Err(RollupError::StalePrice);
        }

        // --- assemble the 8 public inputs (256 bytes), all derived on-chain ---
        let old_root = storage::get_root(&env);

        // Deposit fold: cash-queue prefix first, then coll-queue prefix
        // (matches the circuit's deposit array order; DESIGN.md).
        let mut deposit_hash = BytesN::from_array(&env, &publics::FR_ZERO_WORD);
        for asset in [ASSET_CASH, ASSET_COLL] {
            let head = storage::dep_head(&env, asset);
            for seq in head..head + counts[asset as usize] as u64 {
                let dep = storage::get_deposit(&env, asset, seq);
                deposit_hash = publics::fold(
                    &env,
                    publics::DOMAIN_DEP2,
                    &deposit_hash,
                    &dep.pk_x,
                    asset,
                    dep.amount,
                );
            }
        }

        let mut withdraw_hash = BytesN::from_array(&env, &publics::FR_ZERO_WORD);
        for wd in envelope.withdrawals.iter() {
            if wd.asset > ASSET_COLL {
                return Err(RollupError::InvalidAsset);
            }
            if wd.amount <= 0 || wd.amount >= MAX_AMOUNT {
                return Err(RollupError::InvalidAmount);
            }
            let dest_field = publics::address_to_field(&env, &wd.dest);
            withdraw_hash = publics::fold(
                &env,
                publics::DOMAIN_WD2,
                &withdraw_hash,
                &dest_field,
                wd.asset,
                wd.amount,
            );
        }

        let mut pis = Bytes::new(&env);
        publics::append_field(&env, &mut pis, &old_root);
        publics::append_field(&env, &mut pis, &envelope.new_root);
        publics::append_field(&env, &mut pis, &deposit_hash);
        publics::append_field(&env, &mut pis, &withdraw_hash);
        publics::append_field(&env, &mut pis, &envelope.da_commitment);
        publics::append_field(&env, &mut pis, &publics::u64_word(&env, envelope.batch_ts));
        publics::append_field(
            &env,
            &mut pis,
            &publics::u128_word(&env, price_data.price as u128),
        );
        // 8th PI (issue #1 L10): bind the proof to THIS deployment. Two
        // instances sharing a VK and genesis root would otherwise accept
        // each other's proofs.
        let instance_id = publics::address_to_field(&env, &env.current_contract_address());
        publics::append_field(&env, &mut pis, &instance_id);

        // --- verify ---
        let vk = storage::get_vk(&env);
        let verifier =
            UltraHonkVerifier::new(&env, &vk).map_err(|_| RollupError::InvalidVerificationKey)?;
        verifier
            .verify(&env, &envelope.proof, &pis)
            .map_err(|_| RollupError::VerificationFailed)?;

        // --- state transition ---
        storage::dequeue_deposits(&env, ASSET_CASH, envelope.deposit_count_cash as u64);
        storage::dequeue_deposits(&env, ASSET_COLL, envelope.deposit_count_coll as u64);
        storage::set_root(&env, &envelope.new_root);
        let batch_num = storage::get_batch_num(&env) + 1;
        storage::set_batch_num(&env, batch_num);

        for wd in envelope.withdrawals.iter() {
            let token_client = token::TokenClient::new(&env, &storage::get_token(&env, wd.asset));
            token_client.transfer(&env.current_contract_address(), &wd.dest, &wd.amount);
        }

        events::Batch {
            batch_num: &batch_num,
            new_root: &envelope.new_root,
            da_commitment: &envelope.da_commitment,
        }
        .publish(&env);
        Ok(())
    }

    /// Verify-only entrypoint kept for cost isolation on localnet (M6).
    pub fn verify(env: Env, public_inputs: Bytes, proof: Bytes) -> Result<(), RollupError> {
        if proof.len() as usize != PROOF_BYTES {
            return Err(RollupError::InvalidProofLength);
        }
        let vk = storage::get_vk(&env);
        let verifier =
            UltraHonkVerifier::new(&env, &vk).map_err(|_| RollupError::InvalidVerificationKey)?;
        verifier
            .verify(&env, &proof, &public_inputs)
            .map_err(|_| RollupError::VerificationFailed)
    }

    pub fn root(env: Env) -> BytesN<32> {
        storage::get_root(&env)
    }

    pub fn batch_num(env: Env) -> u64 {
        storage::get_batch_num(&env)
    }

    pub fn pending_deposit_count(env: Env, asset: u32) -> u64 {
        storage::dep_tail(&env, asset) - storage::dep_head(&env, asset)
    }

    /// Next unassigned deposit-queue sequence number (exclusive end).
    pub fn dep_tail(env: Env, asset: u32) -> u64 {
        storage::dep_tail(&env, asset)
    }

    /// First unconsumed deposit-queue sequence number.
    pub fn dep_head(env: Env, asset: u32) -> u64 {
        storage::dep_head(&env, asset)
    }

    /// Read one pending queue entry (traps if consumed/nonexistent). The
    /// sequencer's deposit watcher polls dep_tail + this instead of events:
    /// contract storage has no retention window.
    pub fn get_pending_deposit(env: Env, asset: u32, seq: u64) -> PendingDeposit {
        storage::get_deposit(&env, asset, seq)
    }

    pub fn token(env: Env, asset: u32) -> Address {
        storage::get_token(&env, asset)
    }

    pub fn oracle(env: Env) -> Address {
        storage::get_oracle(&env)
    }

    /// SHA-256 of the stored verification key. Deployment tooling compares
    /// this against the VK compiled into the release image so a circuit
    /// change can never ship against a contract whose immutable VK cannot
    /// verify its proofs (issue #2).
    pub fn vk_hash(env: Env) -> BytesN<32> {
        env.crypto().sha256(&storage::get_vk(&env)).to_bytes()
    }
}

#[cfg(test)]
mod test;
