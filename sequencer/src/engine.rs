//! The engine actor: a single OS thread owning the account tree, the SQLite
//! connection, and every state mutation. HTTP handlers and the watcher/
//! batcher threads talk to it over an mpsc channel — this serializes
//! admission checks against batch building (no TOCTOU) and sidesteps the
//! fact that neither `soroban_sdk::Env` (inside Hasher) nor
//! `rusqlite::Connection` can be shared across threads.
//!
//! A fresh `Hasher` (soroban Env) is created per command: the Env's host-
//! object table grows monotonically, so a long-lived one would leak.

use crate::config::Config;
use crate::db;
use crate::hexutil::{fr_hex, parse_fr};
use harness::batch::{tx_message, BuildError, DepositRequest, SignedTx};
use harness::keys::{pk_from_coords, verify, Signature};
use harness::l1::address_to_field;
use harness::poseidon::{fr_from_u64, Fr, Hasher, FR_ZERO};
use harness::repo::{
    build_repo_batch, open_message, L2State, OpenRequest, PosTree, Position, RepoBuildError,
};
use harness::settle::{close_message, CloseRequest, LiqRequest, SettleError};
use harness::tree::{Account, Tree};
use rusqlite::Connection;
use std::sync::mpsc;
use tokio::sync::oneshot;

/// Max client clock skew tolerated on an intent's open_ts (issue #1 M4):
/// the circuit requires open_ts <= batch_ts, and batch_ts is assigned at
/// build time (>= admission time), so any open admitted under this bound
/// becomes provable within one skew window. The builder defers opens up to
/// 2x this bound instead of rejecting them.
const OPEN_TS_SKEW_SECS: u64 = 60;

/// Cap on signed rate/haircut bps at admission (issue #1 L7): 1e6 bps =
/// 10,000%. Keeps cash * rate * elapsed < 2^128 for any elapsed < 136 years,
/// so the interest mirror can never overflow for admitted terms.
const MAX_TERM_BPS: u32 = 1_000_000;

/// Freshness window for read-auth timestamps (issue #1 L12), both ways
/// (client clocks skew in either direction).
const AUTH_FRESH_SECS: u64 = 300;

/// Withdrawal cap per batch — mirrors the contract's MAX_WITHDRAWALS, which
/// is aligned with the circuit's T = 4 payment slots (issue #1 L14).
const MAX_WITHDRAWALS: usize = 4;

// ---------- wire/result types ----------

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WireSig {
    pub r_x: String,
    pub r_y: String,
    pub s_lo: String,
    pub s_hi: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WireIntent {
    /// Which role the initiator (and signer) of this intent plays.
    pub initiator: String, // "borrower" | "lender"
    pub borrower_pk_x: String,
    pub borrower_pk_y: String,
    pub lender_pk_x: String,
    pub lender_pk_y: String,
    pub cash: String,
    pub coll: String,
    pub rate_bps: u32,
    pub haircut_bps: u32,
    pub open_ts: u64,
    pub maturity_ts: u64,
    pub borrower_nonce: u64,
    pub lender_nonce: u64,
    pub sig: WireSig,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WireAccept {
    pub sig: WireSig,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WireClose {
    pub pos_index: u32,
    pub borrower_pk_x: String,
    pub borrower_pk_y: String,
    pub nonce: u64,
    pub sig: WireSig,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PositionInfo {
    pub slot: u32,
    pub borrower_pk_x: String,
    pub lender_pk_x: String,
    pub cash: String,
    pub coll: String,
    pub rate_bps: u32,
    pub haircut_bps: u32,
    pub open_ts: u64,
    pub maturity_ts: u64,
}

/// Read-auth proof for private listing endpoints (issue #1 L12), carried as
/// query parameters: a Schnorr signature by the queried account's key over
/// `P2([DOMAIN_AUTH, pk_x, ts], 3)`. `ts` must be within AUTH_FRESH_SECS of
/// the sequencer clock (coarse replay bound; listings are reads).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WireAuth {
    pub ts: u64,
    pub pk_y: String,
    pub r_x: String,
    pub r_y: String,
    pub s_lo: String,
    pub s_hi: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WireTx {
    pub from_pk_x: String,
    pub from_pk_y: String,
    /// Transfer: recipient pk_x hex. Withdrawal: destination strkey.
    pub to: String,
    /// Asset id: 0 = cash (XLM), 1 = collateral (tUST).
    pub asset: u32,
    pub amount: String,
    pub nonce: u64,
    pub is_withdraw: bool,
    pub sig: WireSig,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TxReceipt {
    pub id: i64,
    pub status: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountInfo {
    pub pk_x: String,
    pub index: u32,
    pub cash: String,
    pub coll: String,
    pub nonce: u64,
    pub pending_nonce: u64,
    pub pending_out_cash: String,
    pub pending_out_coll: String,
    pub root: String,
    pub batch_num: u64,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusInfo {
    pub root: String,
    pub batch_num: u64,
    pub pending_txs: u64,
    pub pending_opens: u64,
    pub pending_deposits: u64,
    pub contract_id: String,
    pub inflight_batch: Option<InflightInfo>,
    pub chain_synced: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InflightInfo {
    pub batch_num: u64,
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("BAD_FIELD: {0}")]
    BadField(String),
    #[error("BAD_SIGNATURE")]
    BadSignature,
    #[error("NONCE_MISMATCH: expected {expected}")]
    NonceMismatch { expected: u64 },
    /// A DIFFERENT tx already occupies this (sender, nonce) slot (issue #1
    /// L11 / issue #45) — resubmitting the identical tx returns the
    /// original receipt.
    #[error("DUPLICATE_NONCE: a different tx is already pending at this nonce")]
    DuplicateNonce,
    #[error("QUEUE_CONFLICT: {0}")]
    QueueConflict(String),
    #[error("INSUFFICIENT_BALANCE: available {available}")]
    InsufficientBalance { available: u64 },
    #[error("RECIPIENT_UNKNOWN")]
    RecipientUnknown,
    #[error("RATE_LIMITED: {0}")]
    RateLimited(String),
    #[error("ACCOUNT_UNKNOWN")]
    AccountUnknown,
    #[error("NOT_FOUND")]
    NotFound,
    #[error("internal: {0}")]
    Internal(String),
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

/// Work order handed to the batcher thread once a batch row is persisted.
/// The bb public_inputs are validated against the persisted batch row in
/// `record_proof`, so nothing beyond the toml needs to travel here.
#[derive(Debug)]
pub struct BatchJob {
    pub batch_num: u64,
    /// The proven post-state root; confirmation compares the CHAIN root
    /// against this, never just the batch counter (issue #1 H2).
    pub new_root: Fr,
    pub prover_toml: String,
}

pub enum Command {
    SubmitTx(WireTx, oneshot::Sender<Result<TxReceipt, ApiError>>),
    SubmitIntent(WireIntent, oneshot::Sender<Result<TxReceipt, ApiError>>),
    /// (intent id, counterparty signature)
    AcceptIntent(
        i64,
        WireAccept,
        oneshot::Sender<Result<TxReceipt, ApiError>>,
    ),
    SubmitClose(WireClose, oneshot::Sender<Result<TxReceipt, ApiError>>),
    /// Intents where this pk is counterparty or initiator. Requires a
    /// signed read-auth proof of key control (issue #1 L12).
    GetIntents(
        String,
        WireAuth,
        oneshot::Sender<Result<serde_json::Value, ApiError>>,
    ),
    GetPositions(String, oneshot::Sender<Result<Vec<PositionInfo>, ApiError>>),
    GetAccount(String, oneshot::Sender<Result<AccountInfo, ApiError>>),
    GetStatus(oneshot::Sender<StatusInfo>),
    GetHistory(
        String,
        oneshot::Sender<Result<Vec<db::HistoryEntry>, ApiError>>,
    ),
    GetDa(u64, oneshot::Sender<Result<serde_json::Value, ApiError>>),
    GetBatches(oneshot::Sender<Vec<serde_json::Value>>),
    /// From the watcher: newly observed L1 deposits (asset, seq, pk_x, amount).
    ObservedDeposits(
        Vec<(u32, u64, Fr, u64)>,
        oneshot::Sender<Result<(), ApiError>>,
    ),
    /// From the watcher: current on-chain queue heads per asset. Pending
    /// rows below a head were refunded on-chain (issue #1 M5).
    ObservedQueueHeads([u64; 2], oneshot::Sender<Result<(), ApiError>>),
    /// From the batcher tick: build a batch if trigger conditions hold.
    /// Carries the current oracle price (fetched by the batcher) — bound as
    /// the 7th public input.
    TryBuildBatch(u64, oneshot::Sender<Result<Option<BatchJob>, ApiError>>),
    /// From the batcher: bb finished; validate + persist the proof.
    RecordProof {
        batch_num: u64,
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
        reply: oneshot::Sender<Result<String, ApiError>>, // envelope_json for submission
    },
    MarkSubmitting(u64, oneshot::Sender<Result<String, ApiError>>), // -> envelope_json
    MarkSubmitted(u64, Option<String>, oneshot::Sender<Result<(), ApiError>>),
    /// From the batcher: chain root now equals the batch's new_root.
    ConfirmBatch(u64, oneshot::Sender<Result<(), ApiError>>),
    /// Batch failed pre-submission; requeue its inputs.
    FailBatch(u64, String, oneshot::Sender<Result<(), ApiError>>),
    /// Resume state for the batcher after boot:
    /// (batch_num, status, batch_ts, new_root).
    GetInflight(oneshot::Sender<Option<(u64, String, u64, Fr)>>),
}

pub struct Engine {
    cfg: Config,
    conn: Connection,
    state: L2State,
    chain_synced: bool,
}

pub fn spawn(
    cfg: Config,
    conn: Connection,
    state: L2State,
    chain_synced: bool,
) -> mpsc::Sender<Command> {
    let (tx, rx) = mpsc::channel::<Command>();
    std::thread::Builder::new()
        .name("engine".into())
        .spawn(move || {
            let mut engine = Engine {
                cfg,
                conn,
                state,
                chain_synced,
            };
            while let Ok(cmd) = rx.recv() {
                engine.handle(cmd);
            }
        })
        .expect("spawn engine thread");
    tx
}

impl Engine {
    fn handle(&mut self, cmd: Command) {
        match cmd {
            Command::SubmitTx(tx, reply) => {
                let _ = reply.send(self.submit_tx(tx));
            }
            Command::SubmitIntent(intent, reply) => {
                let _ = reply.send(self.submit_intent(intent));
            }
            Command::AcceptIntent(id, accept, reply) => {
                let _ = reply.send(self.accept_intent(id, accept));
            }
            Command::SubmitClose(close, reply) => {
                let _ = reply.send(self.submit_close(close));
            }
            Command::GetIntents(pk_hex, auth, reply) => {
                let _ = reply.send(self.get_intents(&pk_hex, &auth));
            }
            Command::GetPositions(pk_hex, reply) => {
                let _ = reply.send(self.get_positions(&pk_hex));
            }
            Command::GetAccount(pk_hex, reply) => {
                let _ = reply.send(self.get_account(&pk_hex));
            }
            Command::GetStatus(reply) => {
                let _ = reply.send(self.get_status());
            }
            Command::GetHistory(pk_hex, reply) => {
                let _ = reply.send(self.get_history(&pk_hex));
            }
            Command::GetDa(batch_num, reply) => {
                let _ = reply.send(self.get_da(batch_num));
            }
            Command::GetBatches(reply) => {
                let _ = reply.send(self.get_batches());
            }
            Command::ObservedDeposits(deps, reply) => {
                let _ = reply.send(self.observed_deposits(deps));
            }
            Command::ObservedQueueHeads(heads, reply) => {
                let _ = reply.send(self.observed_queue_heads(heads));
            }
            Command::TryBuildBatch(price, reply) => {
                let _ = reply.send(self.try_build_batch(price));
            }
            Command::RecordProof {
                batch_num,
                proof,
                public_inputs,
                reply,
            } => {
                let _ = reply.send(self.record_proof(batch_num, proof, public_inputs));
            }
            Command::MarkSubmitting(batch_num, reply) => {
                let _ = reply.send(self.mark_submitting(batch_num));
            }
            Command::MarkSubmitted(batch_num, tx_hash, reply) => {
                let _ = reply.send(
                    db::batch_set_submitted(&self.conn, batch_num, tx_hash.as_deref())
                        .map_err(Into::into),
                );
            }
            Command::ConfirmBatch(batch_num, reply) => {
                let result = self.confirm_batch(batch_num);
                if let Err(e) = &result {
                    // The batcher only asks to confirm after the chain landed
                    // this batch's root: failing to persist it durably means
                    // local state no longer matches the chain. Degrade
                    // readiness and stop building on top (issue #13).
                    tracing::error!(batch_num, %e, "durable confirmation failed; marking chain-desynced");
                    self.chain_synced = false;
                }
                let _ = reply.send(result);
            }
            Command::FailBatch(batch_num, reason, reply) => {
                let _ = reply.send(self.fail_batch(batch_num, &reason));
            }
            Command::GetInflight(reply) => {
                let inflight = db::inflight_batch(&self.conn)
                    .ok()
                    .flatten()
                    .map(|b| (b.batch_num, b.status, b.batch_ts, b.new_root));
                let _ = reply.send(inflight);
            }
        }
    }

    // ---------- reads ----------

    fn confirmed_batch_num(&self) -> u64 {
        db::meta_get_u64(&self.conn, "confirmed_batch_num").unwrap_or(0)
    }

    fn get_account(&self, pk_hex: &str) -> Result<AccountInfo, ApiError> {
        let hasher = Hasher::new();
        let pk_x = parse_fr(pk_hex).map_err(|e| ApiError::BadField(format!("pk_x: {e:?}")))?;
        let index = self
            .state
            .accounts
            .find(&pk_x)
            .ok_or(ApiError::AccountUnknown)?;
        let account = self.state.accounts.get(index).unwrap().clone();
        let (siblings, _) = self.state.accounts.path(&hasher, index);
        let pending = db::mempool_pending_for(&self.conn, &pk_x)?;
        let pending_opens =
            db::opens_pending_for(&self.conn, &pk_x)? + db::closes_pending_for(&self.conn, &pk_x)?;
        let pending_out_cash: u64 = pending
            .iter()
            .filter(|t| t.asset == 0)
            .map(|t| t.amount)
            .sum();
        let pending_out_coll: u64 = pending
            .iter()
            .filter(|t| t.asset == 1)
            .map(|t| t.amount)
            .sum();
        Ok(AccountInfo {
            pk_x: fr_hex(&pk_x),
            index,
            cash: account.cash.to_string(),
            coll: account.coll.to_string(),
            nonce: account.nonce,
            pending_nonce: account.nonce + pending.len() as u64 + pending_opens,
            pending_out_cash: pending_out_cash.to_string(),
            pending_out_coll: pending_out_coll.to_string(),
            root: fr_hex(&self.state.state_root(&hasher)),
            batch_num: self.confirmed_batch_num(),
            siblings: siblings.iter().map(fr_hex).collect(),
        })
    }

    fn get_status(&self) -> StatusInfo {
        let hasher = Hasher::new();
        StatusInfo {
            root: fr_hex(&self.state.state_root(&hasher)),
            batch_num: self.confirmed_batch_num(),
            pending_txs: db::mempool_count_pending(&self.conn).unwrap_or(0),
            pending_opens: db::opens_count_pending(&self.conn).unwrap_or(0),
            pending_deposits: db::deposits_count_pending(&self.conn).unwrap_or(0),
            contract_id: self.cfg.contract_id.clone(),
            inflight_batch: db::inflight_batch(&self.conn)
                .ok()
                .flatten()
                .map(|b| InflightInfo {
                    batch_num: b.batch_num,
                    status: b.status,
                }),
            chain_synced: self.chain_synced,
        }
    }

    fn get_history(&self, pk_hex: &str) -> Result<Vec<db::HistoryEntry>, ApiError> {
        let pk_x = parse_fr(pk_hex).map_err(|e| ApiError::BadField(format!("pk_x: {e:?}")))?;
        Ok(db::history_for(&self.conn, &pk_x, 100)?)
    }

    fn get_da(&self, batch_num: u64) -> Result<serde_json::Value, ApiError> {
        let batch = db::get_batch(&self.conn, batch_num)?.ok_or(ApiError::NotFound)?;
        if batch.status != "confirmed" {
            return Err(ApiError::NotFound);
        }
        let mut blob: serde_json::Value = serde_json::from_str(&batch.blob_json)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        blob["proof"] = serde_json::Value::String(hex::encode(batch.proof.unwrap_or_default()));
        blob["tx_hash"] = match batch.tx_hash {
            Some(h) => serde_json::Value::String(h),
            None => serde_json::Value::Null,
        };
        Ok(blob)
    }

    fn get_batches(&self) -> Vec<serde_json::Value> {
        db::batch_list(&self.conn, 50)
            .unwrap_or_default()
            .into_iter()
            .map(|b| {
                serde_json::json!({
                    "batch_num": b.batch_num,
                    "old_root": fr_hex(&b.old_root),
                    "new_root": fr_hex(&b.new_root),
                    "deposit_count_cash": b.deposit_count_cash,
                    "deposit_count_coll": b.deposit_count_coll,
                    "da_commitment": fr_hex(&b.da_commitment),
                    "status": b.status,
                    "tx_hash": b.tx_hash,
                    "created_at": b.created_at,
                    "confirmed_at": b.confirmed_at,
                })
            })
            .collect()
    }

    // ---------- mempool admission ----------

    fn submit_tx(&mut self, tx: WireTx) -> Result<TxReceipt, ApiError> {
        let hasher = Hasher::new();
        let bad = |field: &str| ApiError::BadField(field.to_string());

        // Flood backstop (issue #2 M4): unbounded pending rows grow the DB
        // and every admission/build scans them. Per-IP limiting lives in the
        // HTTP layer; this caps the aggregate.
        const MEMPOOL_MAX_PENDING: u64 = 5_000;
        if db::mempool_count_pending(&self.conn)? >= MEMPOOL_MAX_PENDING {
            return Err(ApiError::RateLimited(
                "mempool is full; retry shortly".into(),
            ));
        }

        let from_pk_x = parse_fr(&tx.from_pk_x).map_err(|_| bad("from_pk_x"))?;
        let from_pk_y = parse_fr(&tx.from_pk_y).map_err(|_| bad("from_pk_y"))?;
        let asset = harness::tree::Asset::from_u32(tx.asset).ok_or_else(|| bad("asset"))?;
        let amount: u64 = tx.amount.parse().map_err(|_| bad("amount"))?;
        if amount == 0 {
            return Err(bad("amount"));
        }

        // Idempotent resubmission: the IDENTICAL tx at (sender, nonce)
        // returns the original receipt; a different payload at an occupied
        // slot is an error, not a silent success (issue #1 L11 / #45).
        if let Some(row) = db::mempool_find(&self.conn, &from_pk_x, tx.nonce)? {
            let same_sig = [&row.sig_r_x, &row.sig_r_y, &row.sig_s_lo, &row.sig_s_hi]
                .iter()
                .zip([&tx.sig.r_x, &tx.sig.r_y, &tx.sig.s_lo, &tx.sig.s_hi])
                .all(|(stored, given)| parse_fr(given).map(|g| g == **stored).unwrap_or(false));
            if row.asset == tx.asset
                && row.amount.to_string() == tx.amount
                && row.is_withdraw == tx.is_withdraw
                && same_sig
            {
                return Ok(TxReceipt {
                    id: row.id,
                    status: row.status,
                });
            }
            return Err(ApiError::DuplicateNonce);
        }

        let (to_field, withdraw_dest) = if tx.is_withdraw {
            // Full strkey validation (checksum, not just shape): a typo'd
            // destination would exit funds to an unspendable L1 address, and
            // the contract pays whatever address the proof binds (issue #2 M6).
            match stellar_strkey::Strkey::from_string(&tx.to) {
                Ok(stellar_strkey::Strkey::PublicKeyEd25519(_))
                | Ok(stellar_strkey::Strkey::Contract(_)) => {}
                _ => return Err(bad("to: expected a valid G… or C… strkey")),
            }
            (address_to_field(&hasher, &tx.to), Some(tx.to.clone()))
        } else {
            let to = parse_fr(&tx.to).map_err(|_| bad("to"))?;
            if to == FR_ZERO {
                return Err(bad("to"));
            }
            (to, None)
        };

        // Signature (pk from untrusted coordinates; message per DESIGN.md).
        let pk = pk_from_coords(&from_pk_x, &from_pk_y).ok_or(ApiError::BadSignature)?;
        let sig_r_x = parse_fr(&tx.sig.r_x).map_err(|_| bad("sig.r_x"))?;
        let sig_r_y = parse_fr(&tx.sig.r_y).map_err(|_| bad("sig.r_y"))?;
        let sig_s_lo = parse_fr(&tx.sig.s_lo).map_err(|_| bad("sig.s_lo"))?;
        let sig_s_hi = parse_fr(&tx.sig.s_hi).map_err(|_| bad("sig.s_hi"))?;
        let sig = Signature::from_limbs(sig_r_x, sig_r_y, sig_s_lo, sig_s_hi)
            .ok_or(ApiError::BadSignature)?;
        let msg = tx_message(
            &hasher,
            from_pk_x,
            to_field,
            asset,
            amount,
            tx.nonce,
            tx.is_withdraw,
        );
        if !verify(&hasher, &pk, msg, &sig) {
            return Err(ApiError::BadSignature);
        }

        // Nonce and balance against confirmed state + mempool/opens shadow
        // (each queued open consumes one nonce for each party).
        let sender_index = self
            .state
            .accounts
            .find(&from_pk_x)
            .ok_or(ApiError::AccountUnknown)?;
        let sender = self.state.accounts.get(sender_index).unwrap().clone();
        let pending = db::mempool_pending_for(&self.conn, &from_pk_x)?;
        let pending_open_count = db::opens_pending_for(&self.conn, &from_pk_x)?;
        let pending_close_count = db::closes_pending_for(&self.conn, &from_pk_x)?;
        let expected_nonce =
            sender.nonce + pending.len() as u64 + pending_open_count + pending_close_count;
        if tx.nonce != expected_nonce {
            return Err(ApiError::NonceMismatch {
                expected: expected_nonce,
            });
        }
        let pending_out: u64 = pending
            .iter()
            .filter(|t| t.asset == tx.asset)
            .map(|t| t.amount)
            .sum();
        let available = sender.balance(asset).saturating_sub(pending_out);
        if amount > available {
            return Err(ApiError::InsufficientBalance { available });
        }

        // Transfers: recipient must exist now or be created by a pending deposit.
        if !tx.is_withdraw
            && self.state.accounts.find(&to_field).is_none()
            && !db::deposits_pending_pk(&self.conn, &to_field)?
        {
            return Err(ApiError::RecipientUnknown);
        }

        let id = db::insert_mempool(
            &self.conn,
            &from_pk_x,
            &from_pk_y,
            &to_field,
            withdraw_dest.as_deref(),
            tx.asset,
            amount,
            tx.nonce,
            tx.is_withdraw,
            [&sig_r_x, &sig_r_y, &sig_s_lo, &sig_s_hi],
        )?;
        Ok(TxReceipt {
            id,
            status: "pending".into(),
        })
    }

    fn observed_deposits(&mut self, deps: Vec<(u32, u64, Fr, u64)>) -> Result<(), ApiError> {
        let mut max_seq: [Option<u64>; 2] = [None, None];
        for (asset, seq, pk_x, amount) in deps {
            let a = asset as usize;
            max_seq[a] = Some(max_seq[a].map_or(seq, |m| m.max(seq)));
            if db::insert_deposit(&self.conn, asset, seq, &pk_x, amount)? {
                tracing::info!(asset, seq, amount, "observed L1 deposit");
                // Jam alarms (known protocol limitation, see DESIGN.md).
                if let Some(idx) = self.state.accounts.find(&pk_x) {
                    let account = self.state.accounts.get(idx).unwrap();
                    let bal = match asset {
                        0 => account.cash,
                        _ => account.coll,
                    };
                    if bal.checked_add(amount).is_none() {
                        tracing::error!(asset, seq, "DEPOSIT JAM: balance would exceed u64; FIFO is stuck until the head times out into refund_deposit (issue #1 M5)");
                    }
                } else if self.state.accounts.free_index().is_none() {
                    tracing::error!(asset, seq, "DEPOSIT JAM: tree full (256 accounts); FIFO is stuck until the head times out into refund_deposit (issue #1 M5)");
                }
            }
        }
        // Persist the watcher cursors so a restart doesn't try to re-fetch
        // deposits that may already be dequeued (get_pending_deposit traps).
        for asset in 0..2u32 {
            if let Some(seq) = max_seq[asset as usize] {
                db::meta_set(
                    &self.conn,
                    &format!("dep_cursor_{asset}"),
                    &(seq + 1).to_string(),
                )?;
            }
        }
        Ok(())
    }

    /// Retire pending deposit rows the chain already refunded (issue #1 M5).
    /// With the operator pinned, only our own batches consume queue entries,
    /// and those rows are 'batching'/'consumed' while a batch is in flight —
    /// so a still-'pending' row below the on-chain head can only have been
    /// refunded by the contract's refund_deposit path.
    fn observed_queue_heads(&mut self, heads: [u64; 2]) -> Result<(), ApiError> {
        for asset in 0..2u32 {
            let n = db::deposits_mark_refunded_below(&self.conn, asset, heads[asset as usize])?;
            if n > 0 {
                tracing::warn!(
                    asset,
                    count = n,
                    "marked deposits refunded (on-chain queue head advanced past pending rows)"
                );
            }
        }
        Ok(())
    }

    // ---------- repo intents (M2) ----------

    fn parse_wire_intent(
        &self,
        w: &WireIntent,
    ) -> Result<(Position, Fr, Fr, Signature, Fr), ApiError> {
        let bad = |field: &str| ApiError::BadField(field.to_string());
        let position = Position {
            borrower_pk_x: parse_fr(&w.borrower_pk_x).map_err(|_| bad("borrower_pk_x"))?,
            lender_pk_x: parse_fr(&w.lender_pk_x).map_err(|_| bad("lender_pk_x"))?,
            cash: w.cash.parse().map_err(|_| bad("cash"))?,
            coll: w.coll.parse().map_err(|_| bad("coll"))?,
            rate_bps: w.rate_bps,
            haircut_bps: w.haircut_bps,
            open_ts: w.open_ts,
            maturity_ts: w.maturity_ts,
        };
        if position.cash == 0 || position.coll == 0 {
            return Err(bad("amounts"));
        }
        if position.maturity_ts <= position.open_ts {
            return Err(bad("maturity_ts"));
        }
        // Issue #1 M4: the circuit requires open_ts <= batch_ts at open time;
        // batch_ts is assigned at build (>= now), so cap the client's clock
        // skew here. A signed far-future open_ts would strand as unprovable.
        if position.open_ts > db::now() as u64 + OPEN_TS_SKEW_SECS {
            return Err(bad("open_ts"));
        }
        // Issue #1 L7: bound the signed terms so interest arithmetic can
        // never leave u64/u128 range for any realistic horizon (rate <= 1e6
        // bps keeps cash*rate*elapsed < 2^128 for elapsed < 136 years).
        if position.rate_bps > MAX_TERM_BPS || position.haircut_bps > MAX_TERM_BPS {
            return Err(bad("terms_bps"));
        }
        if position.borrower_pk_x == position.lender_pk_x {
            return Err(bad("counterparty"));
        }
        let borrower_pk_y = parse_fr(&w.borrower_pk_y).map_err(|_| bad("borrower_pk_y"))?;
        let lender_pk_y = parse_fr(&w.lender_pk_y).map_err(|_| bad("lender_pk_y"))?;
        let sig = Signature::from_limbs(
            parse_fr(&w.sig.r_x).map_err(|_| bad("sig.r_x"))?,
            parse_fr(&w.sig.r_y).map_err(|_| bad("sig.r_y"))?,
            parse_fr(&w.sig.s_lo).map_err(|_| bad("sig.s_lo"))?,
            parse_fr(&w.sig.s_hi).map_err(|_| bad("sig.s_hi"))?,
        )
        .ok_or(ApiError::BadSignature)?;
        let hasher = Hasher::new();
        let msg = open_message(&hasher, &position, w.borrower_nonce, w.lender_nonce);
        Ok((position, borrower_pk_y, lender_pk_y, sig, msg))
    }

    /// Admit a half-signed open intent: the INITIATOR's signature must verify
    /// over the open message; the counterparty countersigns via accept.
    fn submit_intent(&mut self, w: WireIntent) -> Result<TxReceipt, ApiError> {
        let hasher = Hasher::new();
        let (position, borrower_pk_y, lender_pk_y, sig, msg) = self.parse_wire_intent(&w)?;
        let (signer_x, signer_y) = match w.initiator.as_str() {
            "borrower" => (position.borrower_pk_x, borrower_pk_y),
            "lender" => (position.lender_pk_x, lender_pk_y),
            _ => return Err(ApiError::BadField("initiator".into())),
        };
        let pk = pk_from_coords(&signer_x, &signer_y).ok_or(ApiError::BadSignature)?;
        if !verify(&hasher, &pk, msg, &sig) {
            return Err(ApiError::BadSignature);
        }
        // Both parties must exist on the rollup (an intent naming an unknown
        // counterparty could never be applied).
        if self.state.accounts.find(&position.borrower_pk_x).is_none()
            || self.state.accounts.find(&position.lender_pk_x).is_none()
        {
            return Err(ApiError::AccountUnknown);
        }
        // Cross-class ordering (issue #16): opens execute before payments in
        // a batch, so an intent signed while the initiator has pending
        // payments carries a nonce the open could never satisfy. Fail fast
        // here; the acceptor's queue is re-checked at accept time.
        if !db::mempool_pending_for(&self.conn, &signer_x)?.is_empty() {
            return Err(ApiError::QueueConflict(
                "pending transfers must be included before an intent can be signed".into(),
            ));
        }
        // Bound the intent store (issue #20): a valid signed intent can be
        // replayed forever, so resubmission must be idempotent and the table
        // capped. Expired intents are pruned opportunistically (their signed
        // nonces go stale quickly regardless).
        const INTENT_TTL_SECS: u64 = 24 * 3600;
        const INTENTS_MAX_OPEN: u64 = 1_000;
        const INTENTS_MAX_PER_INITIATOR: u64 = 25;
        db::intents_prune_expired(&self.conn, INTENT_TTL_SECS)?;
        let (lo, hi) = sig.s_limbs();
        let row = db::IntentRow {
            id: 0,
            initiator: w.initiator.clone(),
            borrower_pk_x: fr_hex(&position.borrower_pk_x),
            borrower_pk_y: fr_hex(&borrower_pk_y),
            lender_pk_x: fr_hex(&position.lender_pk_x),
            lender_pk_y: fr_hex(&lender_pk_y),
            cash: position.cash.to_string(),
            coll: position.coll.to_string(),
            rate_bps: position.rate_bps,
            haircut_bps: position.haircut_bps,
            open_ts: position.open_ts,
            maturity_ts: position.maturity_ts,
            borrower_nonce: w.borrower_nonce,
            lender_nonce: w.lender_nonce,
            sig: [fr_hex(&sig.r_x), fr_hex(&sig.r_y), fr_hex(&lo), fr_hex(&hi)],
            status: "open".into(),
            created_at: 0,
        };
        // Replaying the same signed intent returns the original row.
        if let Some(id) = db::find_open_intent_duplicate(&self.conn, &row)? {
            return Ok(TxReceipt {
                id,
                status: "open".into(),
            });
        }
        if db::intents_count_open(&self.conn)? >= INTENTS_MAX_OPEN {
            return Err(ApiError::RateLimited(
                "intent store is full; retry later".into(),
            ));
        }
        if db::intents_count_open_by_initiator(&self.conn, &fr_hex(&signer_x))?
            >= INTENTS_MAX_PER_INITIATOR
        {
            return Err(ApiError::RateLimited(
                "too many open intents for this account".into(),
            ));
        }
        let id = db::insert_intent(&self.conn, &row)?;
        Ok(TxReceipt {
            id,
            status: "open".into(),
        })
    }

    /// Countersign an intent: verify the acceptor's signature over the SAME
    /// open message, then enqueue the fully signed open for batching.
    fn accept_intent(&mut self, id: i64, accept: WireAccept) -> Result<TxReceipt, ApiError> {
        let hasher = Hasher::new();
        let bad = |field: &str| ApiError::BadField(field.to_string());
        let intent = db::get_intent(&self.conn, id)?.ok_or(ApiError::NotFound)?;
        if intent.status != "open" {
            return Err(ApiError::NotFound);
        }
        let position = Position {
            borrower_pk_x: parse_fr(&intent.borrower_pk_x).map_err(|_| bad("intent"))?,
            lender_pk_x: parse_fr(&intent.lender_pk_x).map_err(|_| bad("intent"))?,
            cash: intent.cash.parse().map_err(|_| bad("intent"))?,
            coll: intent.coll.parse().map_err(|_| bad("intent"))?,
            rate_bps: intent.rate_bps,
            haircut_bps: intent.haircut_bps,
            open_ts: intent.open_ts,
            maturity_ts: intent.maturity_ts,
        };
        let borrower_pk_y = parse_fr(&intent.borrower_pk_y).map_err(|_| bad("intent"))?;
        let lender_pk_y = parse_fr(&intent.lender_pk_y).map_err(|_| bad("intent"))?;
        let msg = open_message(
            &hasher,
            &position,
            intent.borrower_nonce,
            intent.lender_nonce,
        );

        // The acceptor is whichever role did NOT initiate.
        let (acceptor_x, acceptor_y) = match intent.initiator.as_str() {
            "borrower" => (position.lender_pk_x, lender_pk_y),
            _ => (position.borrower_pk_x, borrower_pk_y),
        };
        let acc_sig = Signature::from_limbs(
            parse_fr(&accept.sig.r_x).map_err(|_| bad("sig.r_x"))?,
            parse_fr(&accept.sig.r_y).map_err(|_| bad("sig.r_y"))?,
            parse_fr(&accept.sig.s_lo).map_err(|_| bad("sig.s_lo"))?,
            parse_fr(&accept.sig.s_hi).map_err(|_| bad("sig.s_hi"))?,
        )
        .ok_or(ApiError::BadSignature)?;
        let pk = pk_from_coords(&acceptor_x, &acceptor_y).ok_or(ApiError::BadSignature)?;
        if !verify(&hasher, &pk, msg, &acc_sig) {
            return Err(ApiError::BadSignature);
        }

        // Cross-class ordering (issue #16): the open executes before any
        // payment in the batch, so pending payments from EITHER party mean
        // the open's signed nonces cannot line up with batch execution
        // order. Refuse the countersign instead of queueing a doomed open.
        if !db::mempool_pending_for(&self.conn, &position.borrower_pk_x)?.is_empty()
            || !db::mempool_pending_for(&self.conn, &position.lender_pk_x)?.is_empty()
        {
            return Err(ApiError::QueueConflict(
                "pending transfers must be included before this intent can be accepted".into(),
            ));
        }

        // Reassemble both signatures in role order.
        let init_sig = [
            parse_fr(&intent.sig[0]).map_err(|_| bad("intent sig"))?,
            parse_fr(&intent.sig[1]).map_err(|_| bad("intent sig"))?,
            parse_fr(&intent.sig[2]).map_err(|_| bad("intent sig"))?,
            parse_fr(&intent.sig[3]).map_err(|_| bad("intent sig"))?,
        ];
        let (acc_lo, acc_hi) = acc_sig.s_limbs();
        let acc = [acc_sig.r_x, acc_sig.r_y, acc_lo, acc_hi];
        let (b_sig, l_sig) = match intent.initiator.as_str() {
            "borrower" => (init_sig, acc),
            _ => (acc, init_sig),
        };

        let open_id = db::insert_open(
            &self.conn,
            Some(id),
            &db::OpenRow {
                id: 0,
                borrower_pk_x: position.borrower_pk_x,
                borrower_pk_y,
                lender_pk_x: position.lender_pk_x,
                lender_pk_y,
                cash: position.cash,
                coll: position.coll,
                rate_bps: position.rate_bps,
                haircut_bps: position.haircut_bps,
                open_ts: position.open_ts,
                maturity_ts: position.maturity_ts,
                borrower_nonce: intent.borrower_nonce,
                lender_nonce: intent.lender_nonce,
                b_sig,
                l_sig,
                status: "pending".into(),
            },
        )?;
        db::intent_set_status(&self.conn, id, "accepted")?;
        Ok(TxReceipt {
            id: open_id,
            status: "pending".into(),
        })
    }

    fn get_intents(&self, pk_hex: &str, auth: &WireAuth) -> Result<serde_json::Value, ApiError> {
        let pk_x = parse_fr(pk_hex).map_err(|e| ApiError::BadField(format!("pk_x: {e:?}")))?;
        // Issue #1 L12: intents reveal counterparties and full term sheets,
        // so listing requires proof of control of the queried key — a
        // Schnorr signature over P2([DOMAIN_AUTH, pk_x, ts], 3) with a fresh
        // ts (coarse replay bound; this is a read).
        let now = db::now() as u64;
        if auth.ts.abs_diff(now) > AUTH_FRESH_SECS {
            return Err(ApiError::BadField(format!("auth ts: stale (now {now})")));
        }
        let bad = |field: &str| ApiError::BadField(field.to_string());
        let pk_y = parse_fr(&auth.pk_y).map_err(|_| bad("auth pk_y"))?;
        let sig = Signature::from_limbs(
            parse_fr(&auth.r_x).map_err(|_| bad("auth r_x"))?,
            parse_fr(&auth.r_y).map_err(|_| bad("auth r_y"))?,
            parse_fr(&auth.s_lo).map_err(|_| bad("auth s_lo"))?,
            parse_fr(&auth.s_hi).map_err(|_| bad("auth s_hi"))?,
        )
        .ok_or(ApiError::BadSignature)?;
        let hasher = Hasher::new();
        let msg = harness::batch::auth_message(&hasher, pk_x, auth.ts);
        let pk = pk_from_coords(&pk_x, &pk_y).ok_or(ApiError::BadSignature)?;
        if !verify(&hasher, &pk, msg, &sig) {
            return Err(ApiError::BadSignature);
        }

        let canonical = fr_hex(&pk_x);
        let incoming = db::intents_for_counterparty(&self.conn, &canonical)?;
        let outgoing = db::intents_by_initiator(&self.conn, &canonical)?;
        Ok(serde_json::json!({ "incoming": incoming, "outgoing": outgoing }))
    }

    fn get_positions(&self, pk_hex: &str) -> Result<Vec<PositionInfo>, ApiError> {
        let pk_x = parse_fr(pk_hex).map_err(|e| ApiError::BadField(format!("pk_x: {e:?}")))?;
        Ok(self
            .state
            .positions
            .slots
            .iter()
            .filter(|(_, p)| p.borrower_pk_x == pk_x || p.lender_pk_x == pk_x)
            .map(|(slot, p)| PositionInfo {
                slot: *slot,
                borrower_pk_x: fr_hex(&p.borrower_pk_x),
                lender_pk_x: fr_hex(&p.lender_pk_x),
                cash: p.cash.to_string(),
                coll: p.coll.to_string(),
                rate_bps: p.rate_bps,
                haircut_bps: p.haircut_bps,
                open_ts: p.open_ts,
                maturity_ts: p.maturity_ts,
            })
            .collect())
    }

    /// Admit a borrower-signed close: signature over the close message
    /// (which binds the CURRENT position leaf + slot + nonce) must verify
    /// against the position's borrower key.
    fn submit_close(&mut self, w: WireClose) -> Result<TxReceipt, ApiError> {
        let hasher = Hasher::new();
        let bad = |field: &str| ApiError::BadField(field.to_string());
        let borrower_pk_x = parse_fr(&w.borrower_pk_x).map_err(|_| bad("borrower_pk_x"))?;
        let borrower_pk_y = parse_fr(&w.borrower_pk_y).map_err(|_| bad("borrower_pk_y"))?;
        let position = self
            .state
            .positions
            .get(w.pos_index)
            .cloned()
            .ok_or(ApiError::NotFound)?;
        if position.borrower_pk_x != borrower_pk_x {
            return Err(ApiError::BadSignature);
        }
        let sig = Signature::from_limbs(
            parse_fr(&w.sig.r_x).map_err(|_| bad("sig.r_x"))?,
            parse_fr(&w.sig.r_y).map_err(|_| bad("sig.r_y"))?,
            parse_fr(&w.sig.s_lo).map_err(|_| bad("sig.s_lo"))?,
            parse_fr(&w.sig.s_hi).map_err(|_| bad("sig.s_hi"))?,
        )
        .ok_or(ApiError::BadSignature)?;
        let msg = close_message(&hasher, w.pos_index, &position, w.nonce);
        let pk = pk_from_coords(&borrower_pk_x, &borrower_pk_y).ok_or(ApiError::BadSignature)?;
        if !verify(&hasher, &pk, msg, &sig) {
            return Err(ApiError::BadSignature);
        }
        // Nonce plausibility against the shadow (exact check happens at build).
        let idx = self
            .state
            .accounts
            .find(&borrower_pk_x)
            .ok_or(ApiError::AccountUnknown)?;
        let account = self.state.accounts.get(idx).unwrap().clone();
        let pending = db::mempool_pending_for(&self.conn, &borrower_pk_x)?;
        let pending_opens = db::opens_pending_for(&self.conn, &borrower_pk_x)?;
        let pending_closes = db::closes_pending_for(&self.conn, &borrower_pk_x)?;
        // Cross-class ordering (issue #16): the batch applies closes BEFORE
        // opens and payments, so a close queued behind pending opens/payments
        // would execute against a lower account nonce than the shadow nonce
        // it was signed with and be rejected deterministically at build —
        // near maturity that turns an intended close into a default. Refuse
        // the conflicting queue up front instead.
        if !pending.is_empty() || pending_opens > 0 {
            return Err(ApiError::QueueConflict(
                "pending transfers/opens must be included before a close can be queued".into(),
            ));
        }
        let expected = account.nonce + pending.len() as u64 + pending_opens + pending_closes;
        if w.nonce != expected {
            return Err(ApiError::NonceMismatch { expected });
        }
        let (lo, hi) = sig.s_limbs();
        let id = db::insert_close(
            &self.conn,
            &db::CloseRow {
                id: 0,
                pos_index: w.pos_index,
                borrower_pk_x,
                borrower_pk_y,
                borrower_nonce: w.nonce,
                sig: [sig.r_x, sig.r_y, lo, hi],
            },
        )?;
        Ok(TxReceipt {
            id,
            status: "pending".into(),
        })
    }

    // ---------- batch pipeline ----------

    fn try_build_batch(&mut self, price: u64) -> Result<Option<BatchJob>, ApiError> {
        if !self.chain_synced {
            return Ok(None);
        }
        if db::inflight_batch(&self.conn)?.is_some() {
            return Ok(None);
        }

        // Maturity/margin watcher runs every tick (PLAN.md 1.8).
        self.sweep_positions(db::now() as u64, price)?;

        let pending_txs = db::mempool_count_pending(&self.conn)?;
        let pending_deps = db::deposits_count_pending(&self.conn)?;
        let pending_opens = db::opens_count_pending(&self.conn)?;
        let pending_closes = db::closes_count_pending(&self.conn)?;
        let pending_liqs = db::liqs_count_pending(&self.conn)?;
        if pending_txs + pending_deps + pending_opens + pending_closes + pending_liqs == 0 {
            return Ok(None);
        }
        let oldest_age = [
            db::mempool_oldest_pending_age(&self.conn)?,
            db::deposits_oldest_pending_age(&self.conn)?,
            db::opens_oldest_pending_age(&self.conn)?,
            db::closes_oldest_pending_age(&self.conn)?,
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0);

        // Batch eagerly: whenever more than one op is pending, build on
        // this tick (no waiting to fill the batch or hit the timer). The
        // deposit-queue-full and max-wait conditions remain as fallbacks so a
        // lone single payment, or deposit-only activity with no payments,
        // still settles instead of stranding. Watcher-driven liqs/defaults
        // always fire immediately.
        let many_ops = pending_txs + pending_opens + pending_closes > 1;
        let deposits_full = pending_deps >= self.cfg.deposit_slots as u64;
        let waited = (oldest_age as u64) >= self.cfg.batch_max_wait_secs;
        if !(many_ops || deposits_full || waited || pending_liqs > 0) {
            return Ok(None);
        }

        self.build_batch_now(price)
    }

    /// Maturity/margin watcher sweep (PLAN.md 1.8): enqueue defaults for
    /// past-maturity positions and liquidations for under-margined ones at
    /// the current oracle price. Idempotent per slot (INSERT OR IGNORE);
    /// stale entries are evicted at build time if the condition no longer
    /// holds (e.g. the borrower closed first).
    fn sweep_positions(&mut self, now: u64, price: u64) -> Result<(), ApiError> {
        let slots: Vec<(u32, Position)> = self
            .state
            .positions
            .slots
            .iter()
            .map(|(s, p)| (*s, p.clone()))
            .collect();
        for (slot, p) in slots {
            if now > p.maturity_ts {
                if db::insert_liq(&self.conn, slot, false)? {
                    tracing::info!(slot, "maturity watcher: enqueueing default");
                }
            } else if harness::settle::margin_breached(&p, price)
                && db::insert_liq(&self.conn, slot, true)?
            {
                tracing::info!(slot, price, "margin watcher: enqueueing liquidation");
            }
        }
        Ok(())
    }

    fn build_batch_now(&mut self, price: u64) -> Result<Option<BatchJob>, ApiError> {
        let hasher = Hasher::new();
        let deposits = db::deposits_pending(&self.conn, self.cfg.deposit_slots)?;
        let mut close_rows = db::closes_pending(&self.conn, self.cfg.close_slots)?;
        let mut liq_rows = db::liqs_pending(&self.conn, self.cfg.liq_slots)?;
        let mut open_rows = db::opens_pending(&self.conn, self.cfg.open_slots)?;
        let mut candidates = db::mempool_pending(&self.conn, self.cfg.tx_slots * 4)?;

        // Cap withdrawals per batch (contract MAX_WITHDRAWALS = 4, aligned
        // with the circuit's T = 4 payment slots — issue #1 L14).
        let mut txs: Vec<db::MempoolRow> = Vec::new();
        let mut withdrawals = 0usize;
        candidates.retain(|t| {
            if txs.len() >= self.cfg.tx_slots {
                return true;
            }
            if t.is_withdraw {
                if withdrawals >= MAX_WITHDRAWALS {
                    return true;
                }
                withdrawals += 1;
            }
            txs.push(t.clone());
            false
        });

        let dep_requests: Vec<DepositRequest> = deposits
            .iter()
            .map(|d| DepositRequest {
                pk_x: d.pk_x,
                asset: harness::tree::Asset::from_u32(d.asset).expect("db asset corrupt"),
                amount: d.amount,
            })
            .collect();

        // Claimed batch timestamp: slightly behind wall-clock so it can never
        // land ahead of the ledger (one-sided window, PLAN.md 6.1.3).
        let batch_ts = (db::now() as u64).saturating_sub(5);

        // Build on a clone; the live state only advances at confirmation.
        loop {
            let mut work_state = self.clone_state();
            let signed: Vec<SignedTx> = txs.iter().map(row_to_signed).collect();
            let closes: Vec<CloseRequest> = close_rows.iter().map(close_row_to_request).collect();
            let liqs: Vec<LiqRequest> = liq_rows
                .iter()
                .map(|l| LiqRequest {
                    pos_index: l.pos_index,
                    is_liquidation: l.is_liquidation,
                })
                .collect();
            let opens: Vec<OpenRequest> = open_rows.iter().map(open_row_to_request).collect();
            match build_repo_batch(
                &hasher,
                &mut work_state,
                (
                    self.cfg.deposit_slots,
                    self.cfg.close_slots,
                    self.cfg.liq_slots,
                    self.cfg.open_slots,
                    self.cfg.tx_slots,
                ),
                &dep_requests,
                &closes,
                &liqs,
                &opens,
                &signed,
                batch_ts,
                price,
            ) {
                Ok(witness) => {
                    let batch_num = self.confirmed_batch_num() + 1;
                    let count_cash = deposits.iter().filter(|d| d.asset == 0).count() as u32;
                    let count_coll = deposits.iter().filter(|d| d.asset == 1).count() as u32;
                    let blob = blob_json(
                        batch_num,
                        &witness,
                        &deposits,
                        &close_rows,
                        &liq_rows,
                        &open_rows,
                        &txs,
                    );
                    let envelope = envelope_json(&witness, count_cash, count_coll, &txs);
                    let prover_toml =
                        harness::prover::to_repo_prover_toml(&witness, &self.instance_id());
                    db::insert_batch(
                        &self.conn,
                        batch_num,
                        &witness.old_state_root,
                        &witness.new_state_root,
                        count_cash,
                        count_coll,
                        batch_ts,
                        price,
                        &witness.deposit_hash,
                        &witness.withdraw_hash,
                        &witness.da_commitment,
                        &blob,
                        &envelope,
                    )?;
                    db::deposits_set_status(
                        &self.conn,
                        &deposits
                            .iter()
                            .map(|d| (d.asset, d.seq))
                            .collect::<Vec<_>>(),
                        "batching",
                        Some(batch_num),
                    )?;
                    db::closes_set_status(
                        &self.conn,
                        &close_rows.iter().map(|c| c.id).collect::<Vec<_>>(),
                        "batching",
                        Some(batch_num),
                        None,
                    )?;
                    db::liqs_set_status(
                        &self.conn,
                        &liq_rows.iter().map(|l| l.pos_index).collect::<Vec<_>>(),
                        "batching",
                        Some(batch_num),
                        None,
                    )?;
                    db::opens_set_status(
                        &self.conn,
                        &open_rows.iter().map(|o| o.id).collect::<Vec<_>>(),
                        "batching",
                        Some(batch_num),
                        None,
                    )?;
                    db::mempool_set_status(
                        &self.conn,
                        &txs.iter().map(|t| t.id).collect::<Vec<_>>(),
                        "batching",
                        Some(batch_num),
                        None,
                    )?;
                    tracing::info!(
                        batch_num,
                        txs = txs.len(),
                        opens = open_rows.len(),
                        closes = close_rows.len(),
                        liqs = liq_rows.len(),
                        deposits = deposits.len(),
                        "batch built"
                    );
                    return Ok(Some(BatchJob {
                        batch_num,
                        new_root: witness.new_state_root,
                        prover_toml,
                    }));
                }
                Err(RepoBuildError::Payments(BuildError::TreeFull))
                | Err(RepoBuildError::Payments(BuildError::BalanceOverflow { .. }))
                    if !deposits.is_empty() =>
                {
                    // Deposit jam: cannot make progress at all (FIFO prefix is
                    // mandatory). Alarm and stop trying this tick.
                    tracing::error!("deposit jam while building; batching stalled");
                    return Ok(None);
                }
                Err(RepoBuildError::Close(err)) => {
                    let idx = settle_index(&err);
                    let evicted = close_rows.remove(idx);
                    tracing::warn!(id = evicted.id, ?err, "rejecting queued close");
                    db::closes_set_status(
                        &self.conn,
                        &[evicted.id],
                        "rejected",
                        None,
                        Some(&format!("{err:?}")),
                    )?;
                    if txs.is_empty()
                        && deposits.is_empty()
                        && open_rows.is_empty()
                        && close_rows.is_empty()
                        && liq_rows.is_empty()
                    {
                        return Ok(None);
                    }
                }
                Err(RepoBuildError::Liq(err)) => {
                    let idx = settle_index(&err);
                    let evicted = liq_rows.remove(idx);
                    tracing::warn!(
                        slot = evicted.pos_index,
                        ?err,
                        "dropping queued default/liquidation"
                    );
                    db::delete_liq(&self.conn, evicted.pos_index)?;
                    if txs.is_empty()
                        && deposits.is_empty()
                        && open_rows.is_empty()
                        && close_rows.is_empty()
                        && liq_rows.is_empty()
                    {
                        return Ok(None);
                    }
                }
                Err(RepoBuildError::Open(err)) => {
                    // Evict the offending open and retry without it.
                    use harness::repo::OpenError::*;
                    let idx = match err {
                        BorrowerNotFound { open_index }
                        | LenderNotFound { open_index }
                        | SameParty { open_index }
                        | NonceMismatch { open_index, .. }
                        | InsufficientCash { open_index, .. }
                        | InsufficientColl { open_index, .. }
                        | BadSignature { open_index, .. }
                        | ZeroAmount { open_index }
                        | BadTerms { open_index }
                        | FutureOpenTs { open_index }
                        | Undercollateralized { open_index }
                        | PositionsFull { open_index }
                        | ReservedPaddingPk { open_index } => open_index,
                    };
                    let evicted = open_rows.remove(idx);
                    // Issue #1 M4: an open_ts slightly ahead of batch_ts
                    // (client clock skew inside the admission window)
                    // becomes provable once the batch clock catches up —
                    // leave it 'pending' for a later batch instead of
                    // rejecting. Anything further out was tampered past
                    // admission; reject it like the rest.
                    if matches!(err, FutureOpenTs { .. })
                        && evicted.open_ts <= batch_ts + 2 * OPEN_TS_SKEW_SECS
                    {
                        tracing::info!(
                            id = evicted.id,
                            open_ts = evicted.open_ts,
                            batch_ts,
                            "open_ts ahead of batch clock; deferring open to a later batch"
                        );
                    } else {
                        tracing::warn!(id = evicted.id, ?err, "rejecting queued open");
                        db::opens_set_status(
                            &self.conn,
                            &[evicted.id],
                            "rejected",
                            None,
                            Some(&format!("{err:?}")),
                        )?;
                    }
                    if txs.is_empty() && deposits.is_empty() && open_rows.is_empty() {
                        return Ok(None);
                    }
                }
                Err(RepoBuildError::Payments(err)) => {
                    // Evict the offending tx and retry without it.
                    let idx = match err {
                        BuildError::SenderNotFound { tx_index }
                        | BuildError::NonceMismatch { tx_index, .. }
                        | BuildError::InsufficientBalance { tx_index, .. }
                        | BuildError::RecipientNotFound { tx_index }
                        | BuildError::BadSignature { tx_index } => tx_index,
                        other => {
                            tracing::error!(?other, "unbuildable batch");
                            return Ok(None);
                        }
                    };
                    let evicted = txs.remove(idx);
                    tracing::warn!(id = evicted.id, ?err, "rejecting mempool tx");
                    db::mempool_set_status(
                        &self.conn,
                        &[evicted.id],
                        "rejected",
                        None,
                        Some(&format!("{err:?}")),
                    )?;
                    if txs.is_empty() && deposits.is_empty() && open_rows.is_empty() {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// instance_id = address_to_field(rollup contract) — the 8th public
    /// input the contract derives from its own address (issue #1 L10).
    fn instance_id(&self) -> Fr {
        let hasher = Hasher::new();
        address_to_field(&hasher, &self.cfg.contract_id)
    }

    fn record_proof(
        &mut self,
        batch_num: u64,
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> Result<String, ApiError> {
        let batch = db::get_batch(&self.conn, batch_num)?.ok_or(ApiError::NotFound)?;
        // Trust bb's public_inputs only if ALL 8 words match the persisted
        // batch row (the fold hashes are persisted at build time — issue #1
        // L15 closed the 64..128 gap) plus the derived instance word.
        let ts_word = fr_from_u64(batch.batch_ts);
        let price_word = fr_from_u64(batch.price);
        if public_inputs.len() != 256
            || public_inputs[..32] != batch.old_root
            || public_inputs[32..64] != batch.new_root
            || public_inputs[64..96] != batch.deposit_hash
            || public_inputs[96..128] != batch.withdraw_hash
            || public_inputs[128..160] != batch.da_commitment
            || public_inputs[160..192] != ts_word
            || public_inputs[192..224] != price_word
            || public_inputs[224..256] != self.instance_id()
        {
            return Err(ApiError::Internal("bb public_inputs mismatch".into()));
        }
        if proof.len() != 14_592 {
            return Err(ApiError::Internal(format!(
                "bad proof length {}",
                proof.len()
            )));
        }
        let envelope: serde_json::Value = serde_json::from_str(&batch.envelope_json)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let mut envelope = envelope;
        envelope["proof"] = serde_json::Value::String(hex::encode(&proof));
        let envelope_json = envelope.to_string();
        db::batch_set_proof(&self.conn, batch_num, &proof, &envelope_json)?;
        tracing::info!(batch_num, "proof recorded");
        Ok(envelope_json)
    }

    fn mark_submitting(&mut self, batch_num: u64) -> Result<String, ApiError> {
        let batch = db::get_batch(&self.conn, batch_num)?.ok_or(ApiError::NotFound)?;
        if batch.proof.is_none() {
            return Err(ApiError::Internal("no proof recorded".into()));
        }
        db::batch_set_status(&self.conn, batch_num, "submitting")?;
        Ok(batch.envelope_json)
    }

    /// Apply a landed batch to the live tree + leaves table by replaying the
    /// stored blob through the same build path — one code path for build and
    /// apply means the two can't diverge.
    fn confirm_batch(&mut self, batch_num: u64) -> Result<(), ApiError> {
        let hasher = Hasher::new();
        let batch = db::get_batch(&self.conn, batch_num)?.ok_or(ApiError::NotFound)?;
        let blob: serde_json::Value = serde_json::from_str(&batch.blob_json)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        // Replay on a clone: the live state must not move unless the replay
        // reproduces the exact state root the proof landed (otherwise a
        // corrupt blob/row would silently diverge the in-memory state).
        let (deposits, closes, liqs, opens, txs) = parse_blob(&blob).map_err(ApiError::Internal)?;
        let mut work_state = self.clone_state();
        let witness = build_repo_batch(
            &hasher,
            &mut work_state,
            (
                self.cfg.deposit_slots,
                self.cfg.close_slots,
                self.cfg.liq_slots,
                self.cfg.open_slots,
                self.cfg.tx_slots,
            ),
            &deposits,
            &closes,
            &liqs,
            &opens,
            &txs,
            batch.batch_ts,
            batch.price,
        )
        .map_err(|e| ApiError::Internal(format!("replay failed: {e:?}")))?;
        if witness.new_state_root != batch.new_root {
            return Err(ApiError::Internal("replay root mismatch".into()));
        }
        let open_slots = witness.open_slots.clone();

        // Persist everything atomically FROM work_state; the live in-memory
        // tree advances only after the commit succeeds (issue #13) — a write
        // or commit failure must not leave memory ahead of SQLite, and a
        // confirmation retry must replay against the unadvanced tree.
        let tx = self.conn.unchecked_transaction()?;
        for (idx, account) in work_state.accounts.leaves.iter() {
            db::upsert_leaf(
                &tx,
                *idx,
                &account.pk_x,
                account.cash,
                account.coll,
                account.nonce,
            )?;
        }
        for (slot, req) in open_slots.iter().zip(&opens) {
            let p = &req.position;
            db::upsert_position(
                &tx,
                &db::PositionRow {
                    slot: *slot,
                    borrower_pk_x: p.borrower_pk_x,
                    lender_pk_x: p.lender_pk_x,
                    cash: p.cash,
                    coll: p.coll,
                    rate_bps: p.rate_bps,
                    haircut_bps: p.haircut_bps,
                    open_ts: p.open_ts,
                    maturity_ts: p.maturity_ts,
                },
                batch_num,
            )?;
        }
        db::meta_set(&tx, "confirmed_batch_num", &batch_num.to_string())?;

        // History + terminal statuses.
        let dep_keys: Vec<(u32, u64)> = blob["deposits"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|d| {
                (
                    d["asset"].as_u64().unwrap_or(0) as u32,
                    d["seq"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        db::deposits_set_status(&tx, &dep_keys, "consumed", Some(batch_num))?;
        for d in &deposits {
            db::insert_history(
                &tx,
                &d.pk_x,
                batch_num,
                "deposit",
                None,
                d.asset as u32,
                d.amount,
                None,
            )?;
        }
        // Closes: mark rows included, drop positions, record history.
        let close_ids: Vec<i64> = blob["closes"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|c| c["close_id"].as_i64())
            .collect();
        db::closes_set_status(&tx, &close_ids, "included", Some(batch_num), None)?;
        for (creq, centry) in closes.iter().zip(witness.closes.iter()) {
            let p = &centry.position;
            db::delete_position(&tx, creq.pos_index)?;
            db::insert_history(
                &tx,
                &p.borrower_pk_x,
                batch_num,
                "repo_close",
                Some(&fr_hex(&p.lender_pk_x)),
                0,
                p.cash + centry.interest,
                Some(creq.pos_index as u64),
            )?;
            db::insert_history(
                &tx,
                &p.lender_pk_x,
                batch_num,
                "repo_close",
                Some(&fr_hex(&p.borrower_pk_x)),
                0,
                p.cash + centry.interest,
                Some(creq.pos_index as u64),
            )?;
        }
        // Defaults/liquidations: settle rows, drop positions, history.
        for (lreq, lentry) in liqs.iter().zip(witness.liqs.iter()) {
            let p = &lentry.position;
            db::delete_position(&tx, lreq.pos_index)?;
            // DELETE (not mark-included): liq rows are keyed by slot, and a
            // freed slot is reusable by a later open — a lingering settled
            // row would block the watcher from ever enqueueing that slot
            // again (bug found by the M4 e2e).
            db::delete_liq(&tx, lreq.pos_index)?;
            let kind = if lreq.is_liquidation {
                "repo_liquidation"
            } else {
                "repo_default"
            };
            db::insert_history(
                &tx,
                &p.borrower_pk_x,
                batch_num,
                kind,
                Some(&fr_hex(&p.lender_pk_x)),
                1,
                p.coll,
                Some(lreq.pos_index as u64),
            )?;
            db::insert_history(
                &tx,
                &p.lender_pk_x,
                batch_num,
                kind,
                Some(&fr_hex(&p.borrower_pk_x)),
                1,
                p.coll,
                Some(lreq.pos_index as u64),
            )?;
        }
        let open_ids: Vec<i64> = blob["opens"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|o| o["open_id"].as_i64())
            .collect();
        db::opens_set_status(&tx, &open_ids, "included", Some(batch_num), None)?;
        for (slot, req) in open_slots.iter().zip(&opens) {
            let p = &req.position;
            db::insert_history(
                &tx,
                &p.borrower_pk_x,
                batch_num,
                "repo_open",
                Some(&fr_hex(&p.lender_pk_x)),
                0,
                p.cash,
                Some(*slot as u64),
            )?;
            db::insert_history(
                &tx,
                &p.lender_pk_x,
                batch_num,
                "repo_open",
                Some(&fr_hex(&p.borrower_pk_x)),
                0,
                p.cash,
                Some(*slot as u64),
            )?;
        }
        let tx_ids: Vec<i64> = blob["txs"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|t| t["mempool_id"].as_i64())
            .collect();
        db::mempool_set_status(&tx, &tx_ids, "included", Some(batch_num), None)?;
        for (i, t) in txs.iter().enumerate() {
            let dest = blob["txs"][i]["withdraw_dest"].as_str().map(String::from);
            let asset = t.asset as u32;
            if t.is_withdraw {
                db::insert_history(
                    &tx,
                    &t.from_pk_x,
                    batch_num,
                    "withdraw",
                    dest.as_deref(),
                    asset,
                    t.amount,
                    Some(t.nonce),
                )?;
            } else {
                db::insert_history(
                    &tx,
                    &t.from_pk_x,
                    batch_num,
                    "transfer_out",
                    Some(&fr_hex(&t.to_field)),
                    asset,
                    t.amount,
                    Some(t.nonce),
                )?;
                db::insert_history(
                    &tx,
                    &t.to_field,
                    batch_num,
                    "transfer_in",
                    Some(&fr_hex(&t.from_pk_x)),
                    asset,
                    t.amount,
                    None,
                )?;
            }
        }
        db::batch_set_status(&tx, batch_num, "confirmed")?;
        tx.commit()?;
        self.state = work_state;
        tracing::info!(batch_num, root = %fr_hex(&batch.new_root), "batch confirmed");
        Ok(())
    }

    fn fail_batch(&mut self, batch_num: u64, reason: &str) -> Result<(), ApiError> {
        tracing::warn!(batch_num, reason, "batch failed; requeueing inputs");
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE mempool SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
            [batch_num as i64],
        )?;
        tx.execute(
            "UPDATE opens SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
            [batch_num as i64],
        )?;
        tx.execute(
            "UPDATE deposits SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
            [batch_num as i64],
        )?;
        // Closes and liqs too (issue #1 H3): rows stuck in 'batching' are
        // invisible to closes_pending/liqs_pending, and insert_liq is
        // INSERT OR IGNORE keyed by slot — a stranded default/liquidation
        // could never be re-enqueued, freezing that position's collateral.
        tx.execute(
            "UPDATE closes SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
            [batch_num as i64],
        )?;
        tx.execute(
            "UPDATE liqs SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
            [batch_num as i64],
        )?;
        // Delete (not mark failed): the rebuild reuses this batch_num, and
        // batches.batch_num is the PRIMARY KEY — a lingering row would make
        // every future insert_batch fail and wedge batching permanently.
        db::delete_batch(&tx, batch_num)?;
        tx.commit()?;
        Ok(())
    }

    fn clone_state(&self) -> L2State {
        L2State {
            accounts: Tree {
                leaves: self.state.accounts.leaves.clone(),
            },
            positions: PosTree {
                slots: self.state.positions.slots.clone(),
            },
        }
    }
}

/// The published DA blob for one batch (free function: also the seam the
/// round-trip tests drive — `parse_blob(blob_json(..)) == build inputs`).
pub(crate) fn blob_json(
    batch_num: u64,
    witness: &harness::repo::RepoBatchWitness,
    deposits: &[db::DepositRow],
    closes: &[db::CloseRow],
    liqs: &[db::LiqRow],
    opens: &[db::OpenRow],
    txs: &[db::MempoolRow],
) -> String {
    serde_json::json!({
            "v": 2,
            "batch_num": batch_num,
            "old_root": fr_hex(&witness.old_state_root),
            "new_root": fr_hex(&witness.new_state_root),
            "batch_ts": witness.batch_ts,
            "price": witness.price.to_string(),
            "closes": closes.iter().map(|c| serde_json::json!({
                "close_id": c.id,
                "pos_index": c.pos_index,
                "borrower_pk_x": fr_hex(&c.borrower_pk_x),
                "borrower_pk_y": fr_hex(&c.borrower_pk_y),
                "borrower_nonce": c.borrower_nonce,
                "sig": { "r_x": fr_hex(&c.sig[0]), "r_y": fr_hex(&c.sig[1]), "s_lo": fr_hex(&c.sig[2]), "s_hi": fr_hex(&c.sig[3]) },
            })).collect::<Vec<_>>(),
            "liqs": liqs.iter().map(|l| serde_json::json!({
                "pos_index": l.pos_index,
                "is_liquidation": l.is_liquidation,
            })).collect::<Vec<_>>(),
            "opens": opens.iter().enumerate().map(|(i, o)| serde_json::json!({
                "open_id": o.id,
                "pos_index": witness.open_slots.get(i),
                "borrower_pk_x": fr_hex(&o.borrower_pk_x),
                "borrower_pk_y": fr_hex(&o.borrower_pk_y),
                "lender_pk_x": fr_hex(&o.lender_pk_x),
                "lender_pk_y": fr_hex(&o.lender_pk_y),
                "cash": o.cash.to_string(),
                "coll": o.coll.to_string(),
                "rate_bps": o.rate_bps,
                "haircut_bps": o.haircut_bps,
                "open_ts": o.open_ts,
                "maturity_ts": o.maturity_ts,
                "borrower_nonce": o.borrower_nonce,
                "lender_nonce": o.lender_nonce,
                "b_sig": { "r_x": fr_hex(&o.b_sig[0]), "r_y": fr_hex(&o.b_sig[1]), "s_lo": fr_hex(&o.b_sig[2]), "s_hi": fr_hex(&o.b_sig[3]) },
                "l_sig": { "r_x": fr_hex(&o.l_sig[0]), "r_y": fr_hex(&o.l_sig[1]), "s_lo": fr_hex(&o.l_sig[2]), "s_hi": fr_hex(&o.l_sig[3]) },
            })).collect::<Vec<_>>(),
            "deposit_count_cash": deposits.iter().filter(|d| d.asset == 0).count(),
            "deposit_count_coll": deposits.iter().filter(|d| d.asset == 1).count(),
            "deposits": deposits.iter().map(|d| serde_json::json!({
                "asset": d.asset, "seq": d.seq, "pk_x": fr_hex(&d.pk_x), "amount": d.amount.to_string(),
            })).collect::<Vec<_>>(),
            "withdrawals": txs.iter().filter(|t| t.is_withdraw).map(|t| serde_json::json!({
                "dest": t.withdraw_dest, "asset": t.asset, "amount": t.amount.to_string(),
            })).collect::<Vec<_>>(),
            "da_commitment": fr_hex(&witness.da_commitment),
            "txs": txs.iter().map(|t| serde_json::json!({
                "mempool_id": t.id,
                "from_pk_x": fr_hex(&t.from_pk_x),
                "from_pk_y": fr_hex(&t.from_pk_y),
                "to_field": fr_hex(&t.to_field),
                "withdraw_dest": t.withdraw_dest,
                "asset": t.asset,
                "amount": t.amount.to_string(),
                "nonce": t.nonce,
                "is_withdraw": t.is_withdraw,
                "sig": {
                    "r_x": fr_hex(&t.sig_r_x), "r_y": fr_hex(&t.sig_r_y),
                    "s_lo": fr_hex(&t.sig_s_lo), "s_hi": fr_hex(&t.sig_s_hi),
                },
            })).collect::<Vec<_>>(),
        })
        .to_string()
}

fn row_to_signed(row: &db::MempoolRow) -> SignedTx {
    SignedTx {
        from_pk_x: row.from_pk_x,
        from_pk_y: row.from_pk_y,
        to_field: row.to_field,
        asset: harness::tree::Asset::from_u32(row.asset).expect("db asset corrupt"),
        amount: row.amount,
        nonce: row.nonce,
        is_withdraw: row.is_withdraw,
        sig: Signature::from_limbs(row.sig_r_x, row.sig_r_y, row.sig_s_lo, row.sig_s_hi)
            .expect("db sig corrupt"),
    }
}

/// CLI-arg-ready envelope; `proof` filled after proving. BytesN fields are
/// bare hex (no 0x) per the stellar CLI's JSON arg convention.
fn envelope_json(
    witness: &harness::repo::RepoBatchWitness,
    deposit_count_cash: u32,
    deposit_count_coll: u32,
    txs: &[db::MempoolRow],
) -> String {
    let strip = |fr: &Fr| hex::encode(fr);
    serde_json::json!({
        "new_root": strip(&witness.new_state_root),
        "batch_ts": witness.batch_ts,
        "deposit_count_cash": deposit_count_cash,
        "deposit_count_coll": deposit_count_coll,
        "withdrawals": txs.iter().filter(|t| t.is_withdraw).map(|t| serde_json::json!({
            "dest": t.withdraw_dest, "asset": t.asset, "amount": t.amount.to_string(),
        })).collect::<Vec<_>>(),
        "da_commitment": strip(&witness.da_commitment),
        "proof": "",
    })
    .to_string()
}

/// Reconstruct build inputs from a stored DA blob (also the documented
/// external-verifier recipe: re-fold open records + tx messages ->
/// da_commitment).
#[allow(clippy::type_complexity)]
pub fn parse_blob(
    blob: &serde_json::Value,
) -> Result<
    (
        Vec<DepositRequest>,
        Vec<CloseRequest>,
        Vec<LiqRequest>,
        Vec<OpenRequest>,
        Vec<SignedTx>,
    ),
    String,
> {
    let mut deposits = Vec::new();
    for d in blob["deposits"].as_array().ok_or("bad blob: deposits")? {
        let asset = harness::tree::Asset::from_u32(d["asset"].as_u64().ok_or("bad asset")? as u32)
            .ok_or("bad asset")?;
        deposits.push(DepositRequest {
            pk_x: parse_fr(d["pk_x"].as_str().ok_or("bad pk_x")?).map_err(|e| format!("{e:?}"))?,
            asset,
            amount: d["amount"]
                .as_str()
                .ok_or("bad amount")?
                .parse()
                .map_err(|_| "bad amount")?,
        });
    }
    let mut closes = Vec::new();
    for c in blob["closes"].as_array().unwrap_or(&Vec::new()) {
        let sig_fr = |k: &str| -> Result<Fr, String> {
            parse_fr(
                c["sig"][k]
                    .as_str()
                    .ok_or_else(|| format!("bad close sig.{k}"))?,
            )
            .map_err(|e| format!("close sig.{k}: {e:?}"))
        };
        closes.push(CloseRequest {
            pos_index: c["pos_index"].as_u64().ok_or("bad pos_index")? as u32,
            borrower_pk_y: parse_fr(c["borrower_pk_y"].as_str().ok_or("bad borrower_pk_y")?)
                .map_err(|e| format!("borrower_pk_y: {e:?}"))?,
            borrower_nonce: c["borrower_nonce"].as_u64().ok_or("bad borrower_nonce")?,
            sig: Signature::from_limbs(
                sig_fr("r_x")?,
                sig_fr("r_y")?,
                sig_fr("s_lo")?,
                sig_fr("s_hi")?,
            )
            .ok_or("bad close sig limbs")?,
        });
    }
    let mut liqs = Vec::new();
    for l in blob["liqs"].as_array().unwrap_or(&Vec::new()) {
        liqs.push(LiqRequest {
            pos_index: l["pos_index"].as_u64().ok_or("bad pos_index")? as u32,
            is_liquidation: l["is_liquidation"].as_bool().ok_or("bad is_liquidation")?,
        });
    }
    let mut opens = Vec::new();
    for o in blob["opens"].as_array().unwrap_or(&Vec::new()) {
        let fr = |key: &str| -> Result<Fr, String> {
            parse_fr(o[key].as_str().ok_or_else(|| format!("bad {key}"))?)
                .map_err(|e| format!("{key}: {e:?}"))
        };
        let sig = |name: &str| -> Result<Signature, String> {
            let g = |k: &str| -> Result<Fr, String> {
                parse_fr(
                    o[name][k]
                        .as_str()
                        .ok_or_else(|| format!("bad {name}.{k}"))?,
                )
                .map_err(|e| format!("{name}.{k}: {e:?}"))
            };
            Signature::from_limbs(g("r_x")?, g("r_y")?, g("s_lo")?, g("s_hi")?)
                .ok_or_else(|| format!("bad {name} limbs"))
        };
        opens.push(OpenRequest {
            position: Position {
                borrower_pk_x: fr("borrower_pk_x")?,
                lender_pk_x: fr("lender_pk_x")?,
                cash: o["cash"]
                    .as_str()
                    .ok_or("bad cash")?
                    .parse()
                    .map_err(|_| "bad cash")?,
                coll: o["coll"]
                    .as_str()
                    .ok_or("bad coll")?
                    .parse()
                    .map_err(|_| "bad coll")?,
                rate_bps: o["rate_bps"].as_u64().ok_or("bad rate_bps")? as u32,
                haircut_bps: o["haircut_bps"].as_u64().ok_or("bad haircut_bps")? as u32,
                open_ts: o["open_ts"].as_u64().ok_or("bad open_ts")?,
                maturity_ts: o["maturity_ts"].as_u64().ok_or("bad maturity_ts")?,
            },
            borrower_pk_y: fr("borrower_pk_y")?,
            lender_pk_y: fr("lender_pk_y")?,
            borrower_nonce: o["borrower_nonce"].as_u64().ok_or("bad borrower_nonce")?,
            lender_nonce: o["lender_nonce"].as_u64().ok_or("bad lender_nonce")?,
            borrower_sig: sig("b_sig")?,
            lender_sig: sig("l_sig")?,
        });
    }
    let mut txs = Vec::new();
    for t in blob["txs"].as_array().ok_or("bad blob: txs")? {
        let fr = |key: &str| -> Result<Fr, String> {
            parse_fr(t[key].as_str().ok_or_else(|| format!("bad {key}"))?)
                .map_err(|e| format!("{key}: {e:?}"))
        };
        let sig_fr = |key: &str| -> Result<Fr, String> {
            parse_fr(
                t["sig"][key]
                    .as_str()
                    .ok_or_else(|| format!("bad sig.{key}"))?,
            )
            .map_err(|e| format!("sig.{key}: {e:?}"))
        };
        txs.push(SignedTx {
            from_pk_x: fr("from_pk_x")?,
            from_pk_y: fr("from_pk_y")?,
            to_field: fr("to_field")?,
            asset: harness::tree::Asset::from_u32(t["asset"].as_u64().ok_or("bad asset")? as u32)
                .ok_or("bad asset")?,
            amount: t["amount"]
                .as_str()
                .ok_or("bad amount")?
                .parse()
                .map_err(|_| "bad amount")?,
            nonce: t["nonce"].as_u64().ok_or("bad nonce")?,
            is_withdraw: t["is_withdraw"].as_bool().ok_or("bad is_withdraw")?,
            sig: Signature::from_limbs(
                sig_fr("r_x")?,
                sig_fr("r_y")?,
                sig_fr("s_lo")?,
                sig_fr("s_hi")?,
            )
            .ok_or("bad sig limbs")?,
        });
    }
    Ok((deposits, closes, liqs, opens, txs))
}

fn settle_index(err: &SettleError) -> usize {
    use harness::settle::SettleError::*;
    match err {
        PositionNotFound { index }
        | BorrowerNotFound { index }
        | LenderNotFound { index }
        | NonceMismatch { index, .. }
        | BadSignature { index }
        | PastMaturity { index }
        | NotPastMaturity { index }
        | MarginHealthy { index }
        | InsufficientCash { index, .. }
        | BalanceOverflow { index }
        | FutureOpenTs { index }
        | InterestOverflow { index } => *index,
    }
}

/// Reconstruct a signed CloseRequest from its DB row.
pub(crate) fn close_row_to_request(row: &db::CloseRow) -> CloseRequest {
    CloseRequest {
        pos_index: row.pos_index,
        borrower_pk_y: row.borrower_pk_y,
        borrower_nonce: row.borrower_nonce,
        sig: Signature::from_limbs(row.sig[0], row.sig[1], row.sig[2], row.sig[3])
            .expect("db sig corrupt"),
    }
}

/// Reconstruct a signed OpenRequest from its DB row.
pub(crate) fn open_row_to_request(row: &db::OpenRow) -> OpenRequest {
    OpenRequest {
        position: Position {
            borrower_pk_x: row.borrower_pk_x,
            lender_pk_x: row.lender_pk_x,
            cash: row.cash,
            coll: row.coll,
            rate_bps: row.rate_bps,
            haircut_bps: row.haircut_bps,
            open_ts: row.open_ts,
            maturity_ts: row.maturity_ts,
        },
        borrower_pk_y: row.borrower_pk_y,
        lender_pk_y: row.lender_pk_y,
        borrower_nonce: row.borrower_nonce,
        lender_nonce: row.lender_nonce,
        borrower_sig: Signature::from_limbs(row.b_sig[0], row.b_sig[1], row.b_sig[2], row.b_sig[3])
            .expect("db sig corrupt"),
        lender_sig: Signature::from_limbs(row.l_sig[0], row.l_sig[1], row.l_sig[2], row.l_sig[3])
            .expect("db sig corrupt"),
    }
}

/// Boot-time state loading + reconciliation against the chain.
#[derive(Debug)]
pub struct BootState {
    pub state: L2State,
    pub chain_synced: bool,
}

pub fn load_and_reconcile(
    conn: &Connection,
    chain_root: &Fr,
    chain_batch_num: u64,
) -> Result<BootState, String> {
    let hasher = Hasher::new();
    let mut state = L2State::new();
    for (idx, pk_x, cash, coll, nonce) in db::load_leaves(conn).map_err(|e| e.to_string())? {
        state.accounts.set(
            idx,
            Account {
                pk_x,
                cash,
                coll,
                nonce,
            },
        );
    }
    for p in db::load_positions(conn).map_err(|e| e.to_string())? {
        state.positions.set(
            p.slot,
            Position {
                borrower_pk_x: p.borrower_pk_x,
                lender_pk_x: p.lender_pk_x,
                cash: p.cash,
                coll: p.coll,
                rate_bps: p.rate_bps,
                haircut_bps: p.haircut_bps,
                open_ts: p.open_ts,
                maturity_ts: p.maturity_ts,
            },
        );
    }
    let db_batch_num = db::meta_get_u64(conn, "confirmed_batch_num").map_err(|e| e.to_string())?;
    let inflight = db::inflight_batch(conn).map_err(|e| e.to_string())?;

    // Case: crashed after landing, before recording -> finish the confirm by
    // replaying the stored blob (main() routes this through the engine once
    // spawned; here we just classify).
    if chain_batch_num == db_batch_num + 1 {
        if let Some(batch) = &inflight {
            if batch.new_root == *chain_root {
                tracing::warn!(batch.batch_num, "recovering: batch landed before crash");
                // Confirmation happens via the engine after spawn (needs &mut state);
                // signal by leaving status as-is; batcher resumes it.
                return Ok(BootState {
                    state,
                    chain_synced: true,
                });
            }
        }
        return Err(format!(
            "chain at batch {chain_batch_num} but DB at {db_batch_num} with no matching inflight — manual repair needed"
        ));
    }

    if chain_batch_num != db_batch_num {
        return Err(format!(
            "chain batch_num {chain_batch_num} != DB {db_batch_num} — someone else advanced the root? halting"
        ));
    }

    let local_root = state.state_root(&hasher);
    if local_root != *chain_root {
        return Err(format!(
            "state root {} != chain root {} — refusing to batch",
            fr_hex(&local_root),
            fr_hex(chain_root)
        ));
    }

    // Normalize a pre-submission inflight: building/proving work is lost on
    // crash (Prover.toml/bb output gone) — fail + requeue; proved/submitting/
    // submitted are resumable (proof is in the DB, resubmission is safe: the
    // proof binds old_root, double-landing is impossible).
    if let Some(batch) = inflight {
        if batch.status == "proving" {
            tracing::warn!(batch.batch_num, "recovering: failing interrupted prove");
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE mempool SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
                [batch.batch_num as i64],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE opens SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
                [batch.batch_num as i64],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE deposits SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
                [batch.batch_num as i64],
            )
            .map_err(|e| e.to_string())?;
            // Closes and liqs too (issue #1 H3, mirroring fail_batch).
            tx.execute(
                "UPDATE closes SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
                [batch.batch_num as i64],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE liqs SET status = 'pending', batch_num = NULL WHERE batch_num = ?1 AND status = 'batching'",
                [batch.batch_num as i64],
            )
            .map_err(|e| e.to_string())?;
            // Delete, not mark-failed: the batch_num gets reused (see fail_batch).
            db::delete_batch(&tx, batch.batch_num).map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        }
    }

    Ok(BootState {
        state,
        chain_synced: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness::batch::{tx_message, DepositRequest};
    use harness::keys::{sign_with_nonce, Keypair};
    use harness::poseidon::FR_ZERO;
    use harness::tree::Asset;

    /// parse_blob(blob_json(..)) reproduces the exact build inputs, and
    /// re-folding the blob's tx list reproduces the proven da_commitment —
    /// the documented external DA-verifier recipe, as a unit test.
    #[test]
    fn blob_round_trips_and_refolds() {
        let hasher = Hasher::new();
        let alice = Keypair::from_sk(ark_grumpkin::Fr::from(101u64));
        let bob = Keypair::from_sk(ark_grumpkin::Fr::from(202u64));

        let deposits = vec![
            DepositRequest {
                pk_x: alice.pk_x(),
                asset: Asset::Cash,
                amount: 1_000_000,
            },
            DepositRequest {
                pk_x: bob.pk_x(),
                asset: Asset::Coll,
                amount: 500_000,
            },
        ];
        let msg1 = tx_message(
            &hasher,
            alice.pk_x(),
            bob.pk_x(),
            Asset::Cash,
            250_000,
            0,
            false,
        );
        let sig1 = sign_with_nonce(&hasher, &alice, msg1, ark_grumpkin::Fr::from(41u64));
        let wd_field = fr_from_u64(770_007);
        let msg2 = tx_message(&hasher, bob.pk_x(), wd_field, Asset::Coll, 100_000, 0, true);
        let sig2 = sign_with_nonce(&hasher, &bob, msg2, ark_grumpkin::Fr::from(42u64));

        let signed = vec![
            SignedTx {
                from_pk_x: alice.pk_x(),
                from_pk_y: alice.pk_y(),
                to_field: bob.pk_x(),
                asset: Asset::Cash,
                amount: 250_000,
                nonce: 0,
                is_withdraw: false,
                sig: sig1.clone(),
            },
            SignedTx {
                from_pk_x: bob.pk_x(),
                from_pk_y: bob.pk_y(),
                to_field: wd_field,
                asset: Asset::Coll,
                amount: 100_000,
                nonce: 0,
                is_withdraw: true,
                sig: sig2.clone(),
            },
        ];
        let mut state = L2State::new();
        let witness = build_repo_batch(
            &hasher,
            &mut state,
            (2, 1, 1, 1, 4),
            &deposits,
            &[],
            &[],
            &[],
            &signed,
            1_700_000_100,
            250_000_000,
        )
        .unwrap();

        // Rows as the DB would hold them.
        let dep_rows: Vec<db::DepositRow> = deposits
            .iter()
            .enumerate()
            .map(|(i, d)| db::DepositRow {
                asset: d.asset as u32,
                seq: i as u64,
                pk_x: d.pk_x,
                amount: d.amount,
                status: "batching".into(),
            })
            .collect();
        let tx_rows: Vec<db::MempoolRow> = signed
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let (s_lo, s_hi) = t.sig.s_limbs();
                db::MempoolRow {
                    id: i as i64 + 1,
                    from_pk_x: t.from_pk_x,
                    from_pk_y: t.from_pk_y,
                    to_field: t.to_field,
                    withdraw_dest: t.is_withdraw.then(|| "GTESTDEST".to_string()),
                    asset: t.asset as u32,
                    amount: t.amount,
                    nonce: t.nonce,
                    is_withdraw: t.is_withdraw,
                    sig_r_x: t.sig.r_x,
                    sig_r_y: t.sig.r_y,
                    sig_s_lo: s_lo,
                    sig_s_hi: s_hi,
                    status: "batching".into(),
                    received_at: 0,
                }
            })
            .collect();

        let blob_str = blob_json(7, &witness, &dep_rows, &[], &[], &[], &tx_rows);
        let blob: serde_json::Value = serde_json::from_str(&blob_str).unwrap();
        assert_eq!(blob["batch_num"], 7);
        assert_eq!(blob["da_commitment"], fr_hex(&witness.da_commitment));

        // Round-trip to build inputs.
        let (deps2, closes2, liqs2, opens2, txs2) = parse_blob(&blob).unwrap();
        assert!(opens2.is_empty() && closes2.is_empty() && liqs2.is_empty());
        assert_eq!(deps2.len(), deposits.len());
        for (a, b) in deposits.iter().zip(&deps2) {
            assert_eq!(a.pk_x, b.pk_x);
            assert_eq!(a.asset, b.asset);
            assert_eq!(a.amount, b.amount);
        }
        assert_eq!(txs2.len(), signed.len());
        for (a, b) in signed.iter().zip(&txs2) {
            assert_eq!(a.from_pk_x, b.from_pk_x);
            assert_eq!(a.to_field, b.to_field);
            assert_eq!(a.asset, b.asset);
            assert_eq!(a.amount, b.amount);
            assert_eq!(a.nonce, b.nonce);
            assert_eq!(a.is_withdraw, b.is_withdraw);
            assert_eq!(a.sig.s, b.sig.s);
        }

        // Rebuilding from the parsed blob reproduces the same witness
        // (deterministic replay — the confirm path's core assumption).
        let mut state2 = L2State::new();
        let replay = build_repo_batch(
            &hasher,
            &mut state2,
            (2, 1, 1, 1, 4),
            &deps2,
            &closes2,
            &liqs2,
            &opens2,
            &txs2,
            1_700_000_100,
            250_000_000,
        )
        .unwrap();
        assert_eq!(replay.new_state_root, witness.new_state_root);
        assert_eq!(replay.da_commitment, witness.da_commitment);

        // External verifier recipe: fold the blob's tx messages.
        let mut acc = FR_ZERO;
        for t in blob["txs"].as_array().unwrap() {
            let fr = |k: &str| parse_fr(t[k].as_str().unwrap()).unwrap();
            let msg = tx_message(
                &hasher,
                fr("from_pk_x"),
                fr("to_field"),
                Asset::from_u32(t["asset"].as_u64().unwrap() as u32).unwrap(),
                t["amount"].as_str().unwrap().parse().unwrap(),
                t["nonce"].as_u64().unwrap(),
                t["is_withdraw"].as_bool().unwrap(),
            );
            acc = hasher.hash(&[fr_from_u64(harness::batch::DOMAIN_DA), acc, msg]);
        }
        assert_eq!(fr_hex(&acc), fr_hex(&witness.da_commitment));
    }
}

/// Engine integration tests: a real Engine over a private temp SQLite DB, no
/// chain and no bb. `ObservedDeposits`/`ConfirmBatch`/`FailBatch` are ordinary
/// commands, so the tests play watcher + batcher; record_proof validates
/// shape (not soundness), so synthetic proofs suffice at this layer.
#[cfg(test)]
mod engine_tests {
    use super::*;
    use crate::config::Config;
    use harness::batch::tx_message;
    use harness::keys::{sign_with_nonce, Keypair};
    use harness::poseidon::fr_from_u64;
    use harness::tree::Asset;

    fn kp(sk: u64) -> Keypair {
        Keypair::from_sk(ark_grumpkin::Fr::from(sk))
    }

    fn engine(deposit_slots: usize, tx_slots: usize, max_wait: u64) -> Engine {
        // Connection::open("") = private on-disk temp DB (WAL works, unlike :memory:).
        let conn = db::open(std::path::Path::new("")).unwrap();
        Engine {
            cfg: Config {
                rpc_url: String::new(),
                network_passphrase: String::new(),
                // 56 chars so address_to_field (instance_id, issue #1 L10)
                // accepts it like a real C… strkey.
                contract_id: "C".repeat(56),
                token_id: String::new(),
                tust_id: String::new(),
                sequencer_secret: String::new(),
                sequencer_address: None,
                db_path: "".into(),
                listen_addr: String::new(),
                batch_max_wait_secs: max_wait,
                tick_secs: 1,
                trusted_proxy_header: None,
                cli_timeout_secs: 30,
                submit_timeout_secs: 180,
                circuit_pkg: "batch_repo".into(),
                deposit_slots,
                close_slots: 2,
                liq_slots: 2,
                open_slots: 2,
                tx_slots,
                oracle_id: String::new(),
                oracle_admin_secret: None,
            },
            conn,
            state: L2State::new(),
            chain_synced: true,
        }
    }

    fn fund(e: &mut Engine, idx: u32, who: &Keypair, cash: u64) {
        // Every funded test account also gets some collateral so asset-1
        // admission paths are reachable.
        e.state.accounts.set(
            idx,
            Account {
                pk_x: who.pk_x(),
                cash,
                coll: 1_000,
                nonce: 0,
            },
        );
    }

    /// A correctly signed WireTx (transfer: `to` = recipient pk_x hex).
    fn wire_asset(
        from: &Keypair,
        to: &str,
        asset: u32,
        amount: u64,
        nonce: u64,
        wd: bool,
    ) -> WireTx {
        let hasher = Hasher::new();
        // Malformed withdrawal dests are rejected by submit_tx before the
        // signature is even parsed — sign over a dummy field for those.
        let to_field = if wd && to.len() == 56 {
            address_to_field(&hasher, to)
        } else if wd {
            fr_from_u64(1)
        } else {
            parse_fr(to).unwrap()
        };
        let msg = tx_message(
            &hasher,
            from.pk_x(),
            to_field,
            Asset::from_u32(asset).unwrap(),
            amount,
            nonce,
            wd,
        );
        let sig = sign_with_nonce(
            &hasher,
            from,
            msg,
            ark_grumpkin::Fr::from(7_000 + nonce * 131 + amount),
        );
        let (lo, hi) = sig.s_limbs();
        WireTx {
            from_pk_x: fr_hex(&from.pk_x()),
            from_pk_y: fr_hex(&from.pk_y()),
            to: to.into(),
            asset,
            amount: amount.to_string(),
            nonce,
            is_withdraw: wd,
            sig: WireSig {
                r_x: fr_hex(&sig.r_x),
                r_y: fr_hex(&sig.r_y),
                s_lo: fr_hex(&lo),
                s_hi: fr_hex(&hi),
            },
        }
    }

    fn wire(from: &Keypair, to: &str, amount: u64, nonce: u64, wd: bool) -> WireTx {
        wire_asset(from, to, 0, amount, nonce, wd)
    }

    fn transfer(from: &Keypair, to: &Keypair, amount: u64, nonce: u64) -> WireTx {
        wire(from, &fr_hex(&to.pk_x()), amount, nonce, false)
    }

    fn wire_sig(sig: &Signature) -> WireSig {
        let (lo, hi) = sig.s_limbs();
        WireSig {
            r_x: fr_hex(&sig.r_x),
            r_y: fr_hex(&sig.r_y),
            s_lo: fr_hex(&lo),
            s_hi: fr_hex(&hi),
        }
    }

    fn test_position(borrower: &Keypair, lender: &Keypair) -> Position {
        Position {
            borrower_pk_x: borrower.pk_x(),
            lender_pk_x: lender.pk_x(),
            cash: 10_000,
            coll: 20_000,
            rate_bps: 500,
            haircut_bps: 1_000,
            open_ts: 0,
            maturity_ts: 10_000,
        }
    }

    /// A correctly signed WireIntent over `test_position(borrower, lender)`.
    fn wire_intent(
        initiator: &str,
        borrower: &Keypair,
        lender: &Keypair,
        b_nonce: u64,
        l_nonce: u64,
    ) -> WireIntent {
        let hasher = Hasher::new();
        let p = test_position(borrower, lender);
        let msg = open_message(&hasher, &p, b_nonce, l_nonce);
        let signer = if initiator == "borrower" {
            borrower
        } else {
            lender
        };
        let sig = sign_with_nonce(&hasher, signer, msg, ark_grumpkin::Fr::from(9_999u64));
        WireIntent {
            initiator: initiator.into(),
            borrower_pk_x: fr_hex(&borrower.pk_x()),
            borrower_pk_y: fr_hex(&borrower.pk_y()),
            lender_pk_x: fr_hex(&lender.pk_x()),
            lender_pk_y: fr_hex(&lender.pk_y()),
            cash: p.cash.to_string(),
            coll: p.coll.to_string(),
            rate_bps: p.rate_bps,
            haircut_bps: p.haircut_bps,
            open_ts: p.open_ts,
            maturity_ts: p.maturity_ts,
            borrower_nonce: b_nonce,
            lender_nonce: l_nonce,
            sig: wire_sig(&sig),
        }
    }

    /// Issue #16: closes/opens execute before payments, so admission must
    /// refuse cross-class queues whose nonces cannot match execution order.
    #[test]
    fn cross_class_queue_conflicts_rejected() {
        let mut e = engine(2, 4, 3600);
        let (alice, bob) = (kp(101), kp(202));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);
        let hasher = Hasher::new();

        // A payment sits in the queue first (consumes shadow nonce 0).
        e.submit_tx(transfer(&alice, &bob, 1_000, 0)).unwrap();

        // payment-then-open, initiator side: alice cannot sign a new intent
        // while her payment is pending.
        let w = wire_intent("borrower", &alice, &bob, 1, 0);
        assert!(matches!(
            e.submit_intent(w),
            Err(ApiError::QueueConflict(_))
        ));

        // payment-then-open, acceptor side: bob (clean queue) initiates, but
        // the countersign is refused while either party has pending payments.
        let w = wire_intent("lender", &alice, &bob, 1, 0);
        let intent_id = e.submit_intent(w).unwrap().id;
        let p = test_position(&alice, &bob);
        let msg = open_message(&hasher, &p, 1, 0);
        let acc_sig = sign_with_nonce(&hasher, &alice, msg, ark_grumpkin::Fr::from(8_888u64));
        let accept = WireAccept {
            sig: wire_sig(&acc_sig),
        };
        assert!(matches!(
            e.accept_intent(intent_id, accept),
            Err(ApiError::QueueConflict(_))
        ));

        // payment-then-close: a close signed at the shadow nonce would
        // execute before the payment against a lower account nonce.
        e.state.positions.set(0, test_position(&alice, &bob));
        let cmsg = close_message(&hasher, 0, &test_position(&alice, &bob), 1);
        let csig = sign_with_nonce(&hasher, &alice, cmsg, ark_grumpkin::Fr::from(7_777u64));
        let close = WireClose {
            pos_index: 0,
            borrower_pk_x: fr_hex(&alice.pk_x()),
            borrower_pk_y: fr_hex(&alice.pk_y()),
            nonce: 1,
            sig: wire_sig(&csig),
        };
        assert!(matches!(
            e.submit_close(close),
            Err(ApiError::QueueConflict(_))
        ));
    }

    /// Issue #20: replaying the same signed intent must not grow the store,
    /// and per-initiator queues are capped.
    #[test]
    fn intent_replay_is_idempotent_and_capped() {
        let mut e = engine(2, 4, 3600);
        let (alice, bob) = (kp(101), kp(202));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);

        let w = wire_intent("borrower", &alice, &bob, 0, 0);
        let r1 = e.submit_intent(w.clone()).unwrap();
        for _ in 0..10 {
            assert_eq!(
                e.submit_intent(w.clone()).unwrap().id,
                r1.id,
                "replay created a new row"
            );
        }
        assert_eq!(db::intents_count_open(&e.conn).unwrap(), 1);

        // Distinct intents count toward the per-initiator cap.
        for i in 1..25u64 {
            e.submit_intent(wire_intent("borrower", &alice, &bob, i, i))
                .unwrap();
        }
        assert!(matches!(
            e.submit_intent(wire_intent("borrower", &alice, &bob, 99, 99)),
            Err(ApiError::RateLimited(_))
        ));
        // The counterparty is unaffected by the initiator's cap.
        e.submit_intent(wire_intent("lender", &alice, &bob, 50, 50))
            .unwrap();
    }

    /// Issue #45: a reused nonce is idempotent only for identical content;
    /// a different payload gets an explicit conflict, never the original
    /// receipt.
    #[test]
    fn reused_nonce_different_payload_conflicts() {
        let mut e = engine(2, 4, 3600);
        let (alice, bob) = (kp(101), kp(202));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);

        let r1 = e.submit_tx(transfer(&alice, &bob, 600_000, 0)).unwrap();
        let r2 = e.submit_tx(transfer(&alice, &bob, 600_000, 0)).unwrap();
        assert_eq!(
            r1.id, r2.id,
            "byte-equivalent resubmission stays idempotent"
        );

        assert!(matches!(
            e.submit_tx(transfer(&alice, &bob, 1_234, 0)),
            Err(ApiError::DuplicateNonce)
        ));
        // Different withdraw flag over the same nonce also conflicts.
        assert!(matches!(
            e.submit_tx(wire(
                &alice,
                "GB5JFZJIVTKNBXNIUOZVNUGBOW4IHZRXFDGTBXIZDPXTOAZFSCV3QQSI",
                600_000,
                0,
                true
            )),
            Err(ApiError::DuplicateNonce)
        ));
    }

    #[test]
    fn admission_matrix() {
        let mut e = engine(2, 4, 3600);
        let (alice, bob, carol) = (kp(101), kp(202), kp(303));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);

        // Valid transfer admitted as pending.
        let r1 = e.submit_tx(transfer(&alice, &bob, 600_000, 0)).unwrap();
        assert_eq!(r1.status, "pending");

        // Idempotent resubmission: same (sender, nonce) returns the original id.
        let r2 = e.submit_tx(transfer(&alice, &bob, 600_000, 0)).unwrap();
        assert_eq!(r2.id, r1.id);

        // A DIFFERENT tx at the occupied (sender, nonce) is an error, not a
        // silent success answering with the original receipt (issue #1 L11).
        match e.submit_tx(transfer(&alice, &bob, 600_001, 0)) {
            Err(ApiError::DuplicateNonce) => {}
            other => panic!("expected DuplicateNonce, got {other:?}"),
        }

        // Nonce gap: pending shadow makes the expected nonce 1.
        match e.submit_tx(transfer(&alice, &bob, 1, 2)) {
            Err(ApiError::NonceMismatch { expected }) => assert_eq!(expected, 1),
            other => panic!("expected NonceMismatch, got {other:?}"),
        }

        // Balance shadow: 600k of 1M is already pending outbound.
        match e.submit_tx(transfer(&alice, &bob, 500_000, 1)) {
            Err(ApiError::InsufficientBalance { available }) => assert_eq!(available, 400_000),
            other => panic!("expected InsufficientBalance, got {other:?}"),
        }

        // Unknown sender / unknown recipient.
        assert!(matches!(
            e.submit_tx(transfer(&carol, &alice, 1, 0)),
            Err(ApiError::AccountUnknown)
        ));
        assert!(matches!(
            e.submit_tx(transfer(&alice, &carol, 1, 1)),
            Err(ApiError::RecipientUnknown)
        ));

        // ...unless a pending deposit will create the recipient.
        e.observed_deposits(vec![(0, 0, carol.pk_x(), 700_000)])
            .unwrap();
        assert!(e.submit_tx(transfer(&alice, &carol, 100_000, 1)).is_ok());

        // Withdrawal destination must be a 56-char G/C strkey.
        assert!(matches!(
            e.submit_tx(wire(&bob, "XNOTASTRKEY", 1, 0, true)),
            Err(ApiError::BadField(_))
        ));
        // Tampered signature (amount changed after signing).
        let mut bad = transfer(&bob, &alice, 1_000, 0);
        bad.amount = "2000".into();
        assert!(matches!(e.submit_tx(bad), Err(ApiError::BadSignature)));

        // Zero amount.
        assert!(matches!(
            e.submit_tx(transfer(&bob, &alice, 0, 0)),
            Err(ApiError::BadField(_))
        ));

        // Strkey CHECKSUM validation, not just shape (issue #2 M6): one
        // corrupted char in an otherwise well-formed G address = typo'd
        // dest = funds exiting to an unspendable L1 account. (Last: the
        // admitted withdrawal occupies bob's nonce 0.)
        let valid_g = stellar_strkey::ed25519::PublicKey([7u8; 32]).to_string();
        let mut corrupted = valid_g.clone().into_bytes();
        corrupted[30] = if corrupted[30] == b'A' { b'B' } else { b'A' };
        let corrupted = String::from_utf8(corrupted).unwrap();
        assert!(e.submit_tx(wire(&bob, &valid_g, 1_000, 0, true)).is_ok());
        assert!(matches!(
            e.submit_tx(wire(&bob, &corrupted, 1_000, 1, true)),
            Err(ApiError::BadField(_))
        ));
    }

    #[test]
    fn eager_trigger_truth_table() {
        let (alice, bob) = (kp(101), kp(202));

        // Nothing pending -> no batch.
        let mut e = engine(2, 4, 3600);
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);
        assert!(e.try_build_batch(250_000_000).unwrap().is_none());

        // One pending payment, young, deposits not full -> wait.
        e.submit_tx(transfer(&alice, &bob, 1_000, 0)).unwrap();
        assert!(e.try_build_batch(250_000_000).unwrap().is_none());

        // >1 pending payments -> eager build.
        e.submit_tx(transfer(&bob, &alice, 2_000, 0)).unwrap();
        let job = e
            .try_build_batch(250_000_000)
            .unwrap()
            .expect("eager build");
        assert_eq!(job.batch_num, 1);

        // Inflight suppression: nothing builds while batch 1 is open.
        e.submit_tx(transfer(&alice, &bob, 10, 1)).unwrap();
        e.submit_tx(transfer(&bob, &alice, 20, 1)).unwrap();
        assert!(e.try_build_batch(250_000_000).unwrap().is_none());

        // Deposit queue full -> build (fresh engine, no payments).
        let mut e = engine(2, 4, 3600);
        e.observed_deposits(vec![(0, 0, alice.pk_x(), 5)]).unwrap();
        assert!(e.try_build_batch(250_000_000).unwrap().is_none()); // 1 of 2 slots
        e.observed_deposits(vec![(0, 1, bob.pk_x(), 6)]).unwrap();
        assert!(e.try_build_batch(250_000_000).unwrap().is_some());

        // Max-wait fallback: a lone deposit with the timer at zero.
        let mut e = engine(2, 4, 0);
        e.observed_deposits(vec![(0, 0, alice.pk_x(), 5)]).unwrap();
        assert!(e.try_build_batch(250_000_000).unwrap().is_some());

        // Out-of-sync engine refuses to batch.
        let mut e = engine(2, 4, 0);
        e.chain_synced = false;
        e.observed_deposits(vec![(0, 0, alice.pk_x(), 5)]).unwrap();
        assert!(e.try_build_batch(250_000_000).unwrap().is_none());
    }

    #[test]
    fn eviction_rebuilds_without_bad_tx() {
        let mut e = engine(2, 4, 0);
        let (alice, bob) = (kp(101), kp(202));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);

        // Valid tx via admission; corrupt row injected directly (admission
        // would refuse it — this simulates admission/build divergence).
        let good = e.submit_tx(transfer(&alice, &bob, 1_000, 0)).unwrap();
        let zero = FR_ZERO;
        let bad_id = db::insert_mempool(
            &e.conn,
            &bob.pk_x(),
            &bob.pk_y(),
            &alice.pk_x(),
            None,
            0,
            2_000,
            0,
            false,
            [&zero, &zero, &zero, &zero],
        )
        .unwrap();

        let job = e
            .try_build_batch(250_000_000)
            .unwrap()
            .expect("builds after eviction");
        assert_eq!(job.batch_num, 1);

        // Bad row rejected with a reason; good row riding in the batch.
        let status: (String, Option<String>) = e
            .conn
            .query_row(
                "SELECT status, reject_reason FROM mempool WHERE id = ?1",
                [bad_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(status.0, "rejected");
        assert!(status.1.unwrap().contains("BadSignature"));
        let good_status: String = e
            .conn
            .query_row("SELECT status FROM mempool WHERE id = ?1", [good.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(good_status, "batching");
    }

    /// Build a valid 256-byte public-input blob for an inflight batch row
    /// (all 8 words, exactly as record_proof cross-checks them).
    fn pis_for(e: &Engine, batch_num: u64) -> Vec<u8> {
        let b = db::get_batch(&e.conn, batch_num).unwrap().unwrap();
        let mut pis = Vec::with_capacity(256);
        pis.extend_from_slice(&b.old_root);
        pis.extend_from_slice(&b.new_root);
        pis.extend_from_slice(&b.deposit_hash);
        pis.extend_from_slice(&b.withdraw_hash);
        pis.extend_from_slice(&b.da_commitment);
        pis.extend_from_slice(&fr_from_u64(b.batch_ts));
        pis.extend_from_slice(&fr_from_u64(b.price));
        pis.extend_from_slice(&e.instance_id());
        pis
    }

    #[test]
    fn pipeline_happy_path_to_confirm() {
        let mut e = engine(2, 4, 0);
        let (alice, bob, carol) = (kp(101), kp(202), kp(303));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);

        e.observed_deposits(vec![(0, 0, carol.pk_x(), 700_000)])
            .unwrap();
        e.submit_tx(transfer(&alice, &bob, 100_000, 0)).unwrap();

        let job = e.try_build_batch(250_000_000).unwrap().expect("build");
        assert_eq!(
            db::inflight_batch(&e.conn).unwrap().unwrap().status,
            "proving"
        );

        // Prove (synthetic), submit, land, confirm.
        let envelope = e
            .record_proof(job.batch_num, vec![1u8; 14_592], pis_for(&e, 1))
            .unwrap();
        assert!(envelope.contains("\"proof\""));
        assert_eq!(
            db::inflight_batch(&e.conn).unwrap().unwrap().status,
            "proved"
        );
        e.mark_submitting(job.batch_num).unwrap();
        db::batch_set_submitted(&e.conn, job.batch_num, Some("txhash")).unwrap();
        e.confirm_batch(job.batch_num).unwrap();

        // State advanced everywhere.
        assert_eq!(e.confirmed_batch_num(), 1);
        let hasher = Hasher::new();
        assert_eq!(e.state.accounts.get(0).unwrap().cash, 900_000);
        assert_eq!(e.state.accounts.get(0).unwrap().nonce, 1);
        assert_eq!(e.state.accounts.get(1).unwrap().cash, 600_000);
        let carol_idx = e
            .state
            .accounts
            .find(&carol.pk_x())
            .expect("carol created by deposit");
        assert_eq!(e.state.accounts.get(carol_idx).unwrap().cash, 700_000);
        // Persisted leaves match the live tree root.
        let boot = load_and_reconcile(&e.conn, &e.state.state_root(&hasher), 1).unwrap();
        assert!(boot.chain_synced);
        // Terminal statuses + history.
        assert!(db::inflight_batch(&e.conn).unwrap().is_none());
        assert_eq!(db::deposits_count_pending(&e.conn).unwrap(), 0);
        assert!(!db::history_for(&e.conn, &alice.pk_x(), 10)
            .unwrap()
            .is_empty());
        // DA blob is served for the confirmed batch and re-parses.
        let blob = e.get_da(1).unwrap();
        assert!(parse_blob(&blob).is_ok());
    }

    #[test]
    fn confirm_write_failure_leaves_live_state_unadvanced() {
        // Issue #13: a failed persist must not leave the in-memory tree
        // ahead of SQLite, and a later retry must replay cleanly.
        let mut e = engine(2, 4, 0);
        let (alice, bob) = (kp(101), kp(202));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);
        e.submit_tx(transfer(&alice, &bob, 100_000, 0)).unwrap();
        let job = e.try_build_batch(250_000_000).unwrap().expect("build");
        e.record_proof(job.batch_num, vec![1u8; 14_592], pis_for(&e, 1))
            .unwrap();
        e.mark_submitting(job.batch_num).unwrap();
        db::batch_set_submitted(&e.conn, job.batch_num, Some("txhash")).unwrap();

        let hasher = Hasher::new();
        let root_before = e.state.state_root(&hasher);

        // Inject a mid-transaction write failure: the history table vanishes.
        e.conn
            .execute_batch("ALTER TABLE history RENAME TO history_bak")
            .unwrap();
        assert!(e.confirm_batch(job.batch_num).is_err());
        assert_eq!(
            e.state.state_root(&hasher),
            root_before,
            "memory advanced past a failed commit"
        );
        assert_eq!(e.confirmed_batch_num(), 0);
        assert_eq!(
            db::inflight_batch(&e.conn).unwrap().unwrap().status,
            "submitted"
        );

        // Restore and retry: confirmation replays against the unadvanced tree.
        e.conn
            .execute_batch("ALTER TABLE history_bak RENAME TO history")
            .unwrap();
        e.confirm_batch(job.batch_num).unwrap();
        assert_eq!(e.confirmed_batch_num(), 1);
        assert_eq!(e.state.accounts.get(0).unwrap().cash, 900_000);
    }

    #[test]
    fn record_proof_rejects_bad_shapes() {
        let mut e = engine(2, 4, 0);
        let (alice, bob) = (kp(101), kp(202));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);
        e.submit_tx(transfer(&alice, &bob, 1_000, 0)).unwrap();
        let job = e.try_build_batch(250_000_000).unwrap().unwrap();

        let good_pis = pis_for(&e, job.batch_num);
        // Wrong PI length (the old 5-PI size must be rejected too).
        assert!(e
            .record_proof(job.batch_num, vec![1u8; 14_592], vec![0u8; 160])
            .is_err());
        // Tampered da_commitment word.
        let mut bad = good_pis.clone();
        bad[159] ^= 1;
        assert!(e
            .record_proof(job.batch_num, vec![1u8; 14_592], bad)
            .is_err());
        // Wrong proof length.
        assert!(e
            .record_proof(job.batch_num, vec![1u8; 14_591], good_pis.clone())
            .is_err());
        // Correct shape lands.
        assert!(e
            .record_proof(job.batch_num, vec![1u8; 14_592], good_pis)
            .is_ok());
    }

    /// Regression (bug found by this suite): a corrupt batch row must not
    /// move the live tree — replay happens on a clone.
    #[test]
    fn confirm_replay_mismatch_aborts_without_state_change() {
        let mut e = engine(2, 4, 0);
        let (alice, bob) = (kp(101), kp(202));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);
        e.submit_tx(transfer(&alice, &bob, 1_000, 0)).unwrap();
        let job = e.try_build_batch(250_000_000).unwrap().unwrap();
        e.record_proof(job.batch_num, vec![1u8; 14_592], pis_for(&e, 1))
            .unwrap();

        // Corrupt the recorded new_root.
        e.conn
            .execute(
                "UPDATE batches SET new_root = ?1 WHERE batch_num = 1",
                [fr_hex(&fr_from_u64(999))],
            )
            .unwrap();

        let hasher = Hasher::new();
        let root_before = e.state.state_root(&hasher);
        assert!(e.confirm_batch(1).is_err());
        assert_eq!(
            e.state.state_root(&hasher),
            root_before,
            "live state must not move"
        );
        assert_eq!(e.confirmed_batch_num(), 0);
    }

    /// Regression (bug found by this suite): after fail_batch the batch_num
    /// is reused — the failed row must not wedge the next insert_batch.
    #[test]
    fn fail_batch_requeues_and_rebuild_succeeds() {
        let mut e = engine(2, 4, 0);
        let (alice, bob) = (kp(101), kp(202));
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);
        e.submit_tx(transfer(&alice, &bob, 1_000, 0)).unwrap();
        let job = e.try_build_batch(250_000_000).unwrap().unwrap();
        assert_eq!(job.batch_num, 1);

        e.fail_batch(1, "submit_batch returned error").unwrap();
        assert!(db::inflight_batch(&e.conn).unwrap().is_none());
        assert_eq!(
            db::mempool_count_pending(&e.conn).unwrap(),
            1,
            "inputs requeued"
        );

        // The rebuild reuses batch_num 1 and must succeed.
        let rebuilt = e
            .try_build_batch(250_000_000)
            .unwrap()
            .expect("rebuild after failure");
        assert_eq!(rebuilt.batch_num, 1);
    }

    /// Regression (issue #1 H3): fail_batch must requeue closes and liqs
    /// alongside mempool/opens/deposits. A default/liquidation stuck in
    /// 'batching' can never be re-enqueued (insert_liq is INSERT OR IGNORE
    /// keyed by slot), permanently freezing the position's collateral.
    #[test]
    fn fail_batch_requeues_closes_and_liqs() {
        let mut e = engine(2, 4, 0);
        let close = db::CloseRow {
            id: 0,
            pos_index: 3,
            borrower_pk_x: fr_from_u64(11),
            borrower_pk_y: fr_from_u64(12),
            borrower_nonce: 0,
            sig: [
                fr_from_u64(1),
                fr_from_u64(2),
                fr_from_u64(3),
                fr_from_u64(4),
            ],
        };
        let close_id = db::insert_close(&e.conn, &close).unwrap();
        assert!(db::insert_liq(&e.conn, 7, false).unwrap());
        db::closes_set_status(&e.conn, &[close_id], "batching", Some(1), None).unwrap();
        db::liqs_set_status(&e.conn, &[7], "batching", Some(1), None).unwrap();
        assert_eq!(db::closes_count_pending(&e.conn).unwrap(), 0);
        assert!(db::liqs_pending(&e.conn, 8).unwrap().is_empty());
        // Stuck in 'batching', the watcher cannot re-enqueue the same slot.
        assert!(!db::insert_liq(&e.conn, 7, false).unwrap());

        e.fail_batch(1, "prove failed").unwrap();

        assert_eq!(
            db::closes_count_pending(&e.conn).unwrap(),
            1,
            "close requeued"
        );
        let liqs = db::liqs_pending(&e.conn, 8).unwrap();
        assert_eq!(liqs.len(), 1, "liq requeued");
        assert_eq!(liqs[0].pos_index, 7);
    }

    #[test]
    fn boot_recovery_matrix() {
        let hasher = Hasher::new();
        let genesis = L2State::new().state_root(&hasher);
        let (alice, bob) = (kp(101), kp(202));

        // (a) Fresh DB, chain at genesis -> synced.
        let e = engine(2, 4, 0);
        assert!(
            load_and_reconcile(&e.conn, &genesis, 0)
                .unwrap()
                .chain_synced
        );

        // (b) Crashed after landing: chain ahead by one, inflight matches.
        let mut e = engine(2, 4, 0);
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);
        for (i, a) in [(0u32, &alice), (1u32, &bob)] {
            let acct = e.state.accounts.get(i).unwrap();
            db::upsert_leaf(&e.conn, i, &a.pk_x(), acct.cash, acct.coll, acct.nonce).unwrap();
        }
        e.submit_tx(transfer(&alice, &bob, 1_000, 0)).unwrap();
        e.try_build_batch(250_000_000).unwrap().unwrap();
        let landed_root = db::get_batch(&e.conn, 1).unwrap().unwrap().new_root;
        let boot = load_and_reconcile(&e.conn, &landed_root, 1).unwrap();
        assert!(boot.chain_synced, "finish-confirm path");

        // (c) Chain ahead by one with NO matching inflight -> halt.
        let e = engine(2, 4, 0);
        assert!(load_and_reconcile(&e.conn, &fr_from_u64(9), 1)
            .unwrap_err()
            .contains("manual repair"));

        // (d) Batch-number divergence -> halt.
        let e = engine(2, 4, 0);
        assert!(load_and_reconcile(&e.conn, &genesis, 5)
            .unwrap_err()
            .contains("someone else"));

        // (e) Same batch num, different root -> halt.
        let e = engine(2, 4, 0);
        db::upsert_leaf(&e.conn, 0, &alice.pk_x(), 42, 0, 0).unwrap();
        assert!(load_and_reconcile(&e.conn, &genesis, 0)
            .unwrap_err()
            .contains("refusing to batch"));

        // (f) Interrupted prove: batch deleted, inputs requeued, synced.
        let mut e = engine(2, 4, 0);
        fund(&mut e, 0, &alice, 1_000_000);
        fund(&mut e, 1, &bob, 500_000);
        for (i, a) in [(0u32, &alice), (1u32, &bob)] {
            let acct = e.state.accounts.get(i).unwrap();
            db::upsert_leaf(&e.conn, i, &a.pk_x(), acct.cash, acct.coll, acct.nonce).unwrap();
        }
        let chain_root = e.state.state_root(&hasher);
        e.submit_tx(transfer(&alice, &bob, 1_000, 0)).unwrap();
        e.try_build_batch(250_000_000).unwrap().unwrap(); // status 'proving', then "crash"
        let boot = load_and_reconcile(&e.conn, &chain_root, 0).unwrap();
        assert!(boot.chain_synced);
        assert!(
            db::inflight_batch(&e.conn).unwrap().is_none(),
            "interrupted prove cleared"
        );
        assert_eq!(
            db::mempool_count_pending(&e.conn).unwrap(),
            1,
            "inputs requeued"
        );
    }

    /// Issue #1 M5: when the on-chain queue head advances past rows that are
    /// still 'pending' locally, the contract refunded them (only our own
    /// batches consume entries, and those rows are 'batching'/'consumed') —
    /// they must leave the pending set so builds stop including them.
    #[test]
    fn refunded_deposits_are_retired() {
        let (carol, dave) = (kp(303), kp(404));
        let mut e = engine(4, 4, 3600);
        e.observed_deposits(vec![
            (0, 0, carol.pk_x(), 700),
            (0, 1, dave.pk_x(), 800),
            (1, 0, dave.pk_x(), 900),
        ])
        .unwrap();
        assert_eq!(db::deposits_count_pending(&e.conn).unwrap(), 3);

        // Cash head advanced past seq 0 (refunded); coll head untouched.
        e.observed_queue_heads([1, 0]).unwrap();
        assert_eq!(db::deposits_count_pending(&e.conn).unwrap(), 2);

        // 'batching' rows are NOT touched: a head advanced by our own
        // in-flight batch must not retire its inputs.
        db::deposits_set_status(&e.conn, &[(0, 1)], "batching", Some(1)).unwrap();
        e.observed_queue_heads([2, 0]).unwrap();
        let rows = db::deposits_pending(&e.conn, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].asset, rows[0].seq), (1, 0));
    }

    /// Issue #1 L12: intent listings require a fresh signature by the
    /// queried key; garbage or stale auth is rejected.
    #[test]
    fn intent_listing_requires_auth() {
        let e = engine(2, 4, 3600);
        let alice = kp(101);
        let hasher = Hasher::new();
        let now = db::now() as u64;

        let auth_for = |ts: u64| {
            let msg = harness::batch::auth_message(&hasher, alice.pk_x(), ts);
            let sig = sign_with_nonce(&hasher, &alice, msg, ark_grumpkin::Fr::from(4242u64));
            let (lo, hi) = sig.s_limbs();
            WireAuth {
                ts,
                pk_y: fr_hex(&alice.pk_y()),
                r_x: fr_hex(&sig.r_x),
                r_y: fr_hex(&sig.r_y),
                s_lo: fr_hex(&lo),
                s_hi: fr_hex(&hi),
            }
        };

        // Valid, fresh auth lists (empty) intents.
        let ok = e
            .get_intents(&fr_hex(&alice.pk_x()), &auth_for(now))
            .unwrap();
        assert!(ok["incoming"].as_array().unwrap().is_empty());

        // Stale timestamp rejected even with a valid signature over it.
        match e.get_intents(&fr_hex(&alice.pk_x()), &auth_for(now - 3600)) {
            Err(ApiError::BadField(f)) => assert!(f.contains("auth ts")),
            other => panic!("expected stale-ts rejection, got {other:?}"),
        }

        // A signature over the right message by the WRONG key is rejected.
        let mallory = kp(999);
        let msg = harness::batch::auth_message(&hasher, alice.pk_x(), now);
        let sig = sign_with_nonce(&hasher, &mallory, msg, ark_grumpkin::Fr::from(77u64));
        let (lo, hi) = sig.s_limbs();
        let forged = WireAuth {
            ts: now,
            pk_y: fr_hex(&alice.pk_y()),
            r_x: fr_hex(&sig.r_x),
            r_y: fr_hex(&sig.r_y),
            s_lo: fr_hex(&lo),
            s_hi: fr_hex(&hi),
        };
        match e.get_intents(&fr_hex(&alice.pk_x()), &forged) {
            Err(ApiError::BadSignature) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }
}
