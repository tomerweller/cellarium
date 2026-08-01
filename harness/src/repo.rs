//! Repo positions: the position tree, open messages, and the combined-state
//! batch builder (M2+). Mirrors circuits/lib/src/{repo,repo_batch}.nr exactly
//! — same hash layouts (DOMAIN_POS/OPEN), same application order (deposits →
//! opens → payments), same padding conventions.

use crate::batch::{
    build_batch, BatchWitness, BuildError, DepositEntry, DepositRequest, SignedTx, TxEntry,
};
use crate::keys::{pad_signature, pk_from_coords, verify, Signature};
use crate::settle::{
    apply_close, apply_liq, pad_close, pad_liq, CloseEntry, CloseRequest, LiqEntry, LiqRequest,
    SettleError,
};
use crate::poseidon::{fr_from_u64, Fr, Hasher, FR_ZERO};
use crate::tree::{Account, Tree, DEPTH, N_LEAVES};
use serde::{Deserialize, Serialize};

pub const DOMAIN_POS: u64 = 8;
pub const DOMAIN_OPEN: u64 = 9;
pub const DOMAIN_CLOSE: u64 = 10;

/// One open repo position (PLAN.md 1.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Position {
    pub borrower_pk_x: Fr,
    pub lender_pk_x: Fr,
    pub cash: u64,
    pub coll: u64,
    pub rate_bps: u32,
    pub haircut_bps: u32,
    pub open_ts: u64,
    pub maturity_ts: u64,
}

pub fn term_hash(hasher: &Hasher, p: &Position) -> Fr {
    hasher.hash(&[
        fr_from_u64(p.rate_bps as u64),
        fr_from_u64(p.haircut_bps as u64),
        fr_from_u64(p.open_ts),
        fr_from_u64(p.maturity_ts),
    ])
}

pub fn amt_hash(hasher: &Hasher, cash: u64, coll: u64) -> Fr {
    hasher.hash2(fr_from_u64(cash), fr_from_u64(coll))
}

pub fn pos_leaf(hasher: &Hasher, p: &Position) -> Fr {
    let ta = hasher.hash2(term_hash(hasher, p), amt_hash(hasher, p.cash, p.coll));
    hasher.hash(&[fr_from_u64(DOMAIN_POS), p.borrower_pk_x, p.lender_pk_x, ta])
}

/// The bilateral open signing message (binds the full term sheet + both
/// account nonces; PLAN.md 1.3 / 6.3).
pub fn open_message(
    hasher: &Hasher,
    p: &Position,
    borrower_nonce: u64,
    lender_nonce: u64,
) -> Fr {
    let inner = hasher.hash(&[
        term_hash(hasher, p),
        amt_hash(hasher, p.cash, p.coll),
        fr_from_u64(borrower_nonce),
        fr_from_u64(lender_nonce),
    ]);
    hasher.hash(&[fr_from_u64(DOMAIN_OPEN), p.borrower_pk_x, p.lender_pk_x, inner])
}

/// Combined state root: P2([account_root, position_root]).
pub fn state_root(hasher: &Hasher, acct_root: Fr, pos_root: Fr) -> Fr {
    hasher.hash2(acct_root, pos_root)
}

/// Depth-8 position tree; same node/empty conventions as the account tree.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct PosTree {
    pub slots: std::collections::BTreeMap<u32, Position>,
}

impl PosTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn leaf_value(hasher: &Hasher, p: Option<&Position>) -> Fr {
        match p {
            None => FR_ZERO,
            Some(p) => pos_leaf(hasher, p),
        }
    }

    fn level0(&self, hasher: &Hasher) -> Vec<Fr> {
        (0..N_LEAVES as u32)
            .map(|i| Self::leaf_value(hasher, self.slots.get(&i)))
            .collect()
    }

    pub fn root(&self, hasher: &Hasher) -> Fr {
        let mut level = self.level0(hasher);
        while level.len() > 1 {
            level = level.chunks(2).map(|p| hasher.hash2(p[0], p[1])).collect();
        }
        level[0]
    }

    pub fn path(&self, hasher: &Hasher, index: u32) -> [Fr; DEPTH] {
        assert!((index as usize) < N_LEAVES);
        let mut siblings = [FR_ZERO; DEPTH];
        let mut level = self.level0(hasher);
        let mut idx = index as usize;
        for sibling in siblings.iter_mut() {
            *sibling = level[idx ^ 1];
            level = level.chunks(2).map(|p| hasher.hash2(p[0], p[1])).collect();
            idx >>= 1;
        }
        siblings
    }

    pub fn get(&self, index: u32) -> Option<&Position> {
        self.slots.get(&index)
    }

    pub fn set(&mut self, index: u32, p: Position) {
        assert!((index as usize) < N_LEAVES);
        self.slots.insert(index, p);
    }

    pub fn remove(&mut self, index: u32) -> Option<Position> {
        self.slots.remove(&index)
    }

    /// Lowest empty slot (find-first allocation).
    pub fn free_index(&self) -> Option<u32> {
        (0..N_LEAVES as u32).find(|i| !self.slots.contains_key(i))
    }
}

/// The sequencer's full L2 state: both trees.
#[derive(Default, Debug)]
pub struct L2State {
    pub accounts: Tree,
    pub positions: PosTree,
}

impl L2State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state_root(&self, hasher: &Hasher) -> Fr {
        state_root(hasher, self.accounts.root(hasher), self.positions.root(hasher))
    }
}

/// A fully signed repo open as received over the wire (both signatures).
#[derive(Debug, Clone)]
pub struct OpenRequest {
    pub position: Position,
    pub borrower_pk_y: Fr,
    pub lender_pk_y: Fr,
    pub borrower_nonce: u64,
    pub lender_nonce: u64,
    pub borrower_sig: Signature,
    pub lender_sig: Signature,
}

/// Circuit witness entry for one open (mirrors repo.nr OpenWitness).
#[derive(Debug, Clone)]
pub struct OpenEntry {
    pub borrower_pk_x: Fr,
    pub borrower_pk_y: Fr,
    pub borrower_index: u32,
    pub borrower_cash: u64,
    pub borrower_coll: u64,
    pub borrower_nonce: u64,
    pub borrower_siblings: [Fr; DEPTH],
    pub lender_pk_x: Fr,
    pub lender_pk_y: Fr,
    pub lender_index: u32,
    pub lender_cash: u64,
    pub lender_coll: u64,
    pub lender_nonce: u64,
    pub lender_siblings: [Fr; DEPTH],
    pub cash: u64,
    pub coll: u64,
    pub rate_bps: u32,
    pub haircut_bps: u32,
    pub open_ts: u64,
    pub maturity_ts: u64,
    pub pos_index: u32,
    pub pos_old_leaf: Fr,
    pub pos_siblings: [Fr; DEPTH],
    pub borrower_sig: Signature,
    pub lender_sig: Signature,
    pub is_active: bool,
}

/// Typed admission errors for opens (extends batch::BuildError semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    BorrowerNotFound { open_index: usize },
    LenderNotFound { open_index: usize },
    SameParty { open_index: usize },
    NonceMismatch { open_index: usize, role: &'static str, expected: u64, got: u64 },
    InsufficientCash { open_index: usize, available: u64, needed: u64 },
    InsufficientColl { open_index: usize, available: u64, needed: u64 },
    BadSignature { open_index: usize, role: &'static str },
    ZeroAmount { open_index: usize },
    BadTerms { open_index: usize },
    /// open_ts postdates the batch (issue #1 M4): the circuit rejects it, and
    /// letting it through would make the close unprovable until maturity.
    FutureOpenTs { open_index: usize },
    Undercollateralized { open_index: usize },
    PositionsFull { open_index: usize },
    ReservedPaddingPk { open_index: usize },
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for OpenError {}

#[derive(Debug)]
pub enum RepoBuildError {
    Payments(BuildError),
    Open(OpenError),
    /// From the closes loop (index = position in the closes slice).
    Close(SettleError),
    /// From the defaults/liquidations loop (index = position in the liqs slice).
    Liq(SettleError),
}

impl std::fmt::Display for RepoBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoBuildError::Payments(e) => write!(f, "{e}"),
            RepoBuildError::Open(e) => write!(f, "{e}"),
            RepoBuildError::Close(e) => write!(f, "{e}"),
            RepoBuildError::Liq(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for RepoBuildError {}

#[derive(Debug)]
pub struct RepoBatchWitness {
    pub old_state_root: Fr,
    pub new_state_root: Fr,
    pub old_acct_root: Fr,
    pub old_pos_root: Fr,
    pub deposit_hash: Fr,
    pub withdraw_hash: Fr,
    pub da_commitment: Fr,
    pub batch_ts: u64,
    pub price: u64,
    pub deposits: Vec<DepositEntry>,
    pub closes: Vec<CloseEntry>,
    pub liqs: Vec<LiqEntry>,
    pub opens: Vec<OpenEntry>,
    pub txs: Vec<TxEntry>,
    /// Slot index assigned to each ACTIVE open, in order (for the DA blob /
    /// position bookkeeping).
    pub open_slots: Vec<u32>,
}

/// The open record folded into the DA commitment: P2([open_msg, pos_index])
/// (binds the slot so the blob reconstructs the position tree; PLAN.md 6.3).
pub fn open_record(hasher: &Hasher, open_msg: Fr, pos_index: u32) -> Fr {
    hasher.hash2(open_msg, fr_from_u64(pos_index as u64))
}

fn pad_pk_x_bytes() -> Fr {
    let mut x = [0u8; 32];
    let hex = &crate::keys::PAD_PK_X_HEX[2..];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        x[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    x
}

/// Apply one open to the live state, producing the witness entry. The
/// account tree evolves borrower-then-lender (matching the circuit's two
/// sequential update_root calls); the position tree gets the new leaf at the
/// lowest free slot.
#[allow(clippy::too_many_arguments)]
fn apply_open(
    hasher: &Hasher,
    state: &mut L2State,
    i: usize,
    req: &OpenRequest,
    batch_ts: u64,
    price: u64,
    da_acc: &mut Fr,
) -> Result<OpenEntry, OpenError> {
    let p = &req.position;
    if p.cash == 0 || p.coll == 0 {
        return Err(OpenError::ZeroAmount { open_index: i });
    }
    if p.maturity_ts <= p.open_ts {
        return Err(OpenError::BadTerms { open_index: i });
    }
    // M3: cannot open past maturity; M4: open-time collateral adequacy
    // (coll * price * 1e4 >= cash * (1e4 + haircut) * 1e7, PLAN.md 6.1.1).
    if p.maturity_ts <= batch_ts {
        return Err(OpenError::BadTerms { open_index: i });
    }
    // Issue #1 M4: mirrors the circuit's open_ts <= batch_ts constraint.
    if p.open_ts > batch_ts {
        return Err(OpenError::FutureOpenTs { open_index: i });
    }
    let coll_value = (p.coll as u128) * (price as u128) * 10_000;
    let required = (p.cash as u128) * (10_000 + p.haircut_bps as u128) * 10_000_000;
    if coll_value < required {
        return Err(OpenError::Undercollateralized { open_index: i });
    }
    if p.borrower_pk_x == p.lender_pk_x {
        return Err(OpenError::SameParty { open_index: i });
    }
    let pad_x = pad_pk_x_bytes();
    if p.borrower_pk_x == pad_x || p.lender_pk_x == pad_x {
        return Err(OpenError::ReservedPaddingPk { open_index: i });
    }

    let borrower_index = state
        .accounts
        .find(&p.borrower_pk_x)
        .ok_or(OpenError::BorrowerNotFound { open_index: i })?;
    let lender_index = state
        .accounts
        .find(&p.lender_pk_x)
        .ok_or(OpenError::LenderNotFound { open_index: i })?;

    let borrower = state.accounts.get(borrower_index).cloned().unwrap();
    let lender = state.accounts.get(lender_index).cloned().unwrap();
    if borrower.nonce != req.borrower_nonce {
        return Err(OpenError::NonceMismatch {
            open_index: i,
            role: "borrower",
            expected: borrower.nonce,
            got: req.borrower_nonce,
        });
    }
    if lender.nonce != req.lender_nonce {
        return Err(OpenError::NonceMismatch {
            open_index: i,
            role: "lender",
            expected: lender.nonce,
            got: req.lender_nonce,
        });
    }
    if lender.cash < p.cash {
        return Err(OpenError::InsufficientCash {
            open_index: i,
            available: lender.cash,
            needed: p.cash,
        });
    }
    if borrower.coll < p.coll {
        return Err(OpenError::InsufficientColl {
            open_index: i,
            available: borrower.coll,
            needed: p.coll,
        });
    }
    // Borrower cash credit must not overflow u64.
    if borrower.cash.checked_add(p.cash).is_none() {
        return Err(OpenError::BadTerms { open_index: i });
    }

    // Both signatures over the open message.
    let msg = open_message(hasher, p, req.borrower_nonce, req.lender_nonce);
    let b_pk = pk_from_coords(&p.borrower_pk_x, &req.borrower_pk_y)
        .ok_or(OpenError::BadSignature { open_index: i, role: "borrower" })?;
    if !verify(hasher, &b_pk, msg, &req.borrower_sig) {
        return Err(OpenError::BadSignature { open_index: i, role: "borrower" });
    }
    let l_pk = pk_from_coords(&p.lender_pk_x, &req.lender_pk_y)
        .ok_or(OpenError::BadSignature { open_index: i, role: "lender" })?;
    if !verify(hasher, &l_pk, msg, &req.lender_sig) {
        return Err(OpenError::BadSignature { open_index: i, role: "lender" });
    }

    let pos_index = state
        .positions
        .free_index()
        .ok_or(OpenError::PositionsFull { open_index: i })?;

    // Witness snapshots BEFORE mutation, applied in circuit order.
    let (borrower_siblings, _) = state.accounts.path(hasher, borrower_index);
    state.accounts.set(
        borrower_index,
        Account {
            pk_x: p.borrower_pk_x,
            cash: borrower.cash + p.cash,
            coll: borrower.coll - p.coll,
            nonce: borrower.nonce + 1,
        },
    );
    let (lender_siblings, _) = state.accounts.path(hasher, lender_index);
    state.accounts.set(
        lender_index,
        Account {
            pk_x: p.lender_pk_x,
            cash: lender.cash - p.cash,
            coll: lender.coll,
            nonce: lender.nonce + 1,
        },
    );
    let pos_siblings = state.positions.path(hasher, pos_index);
    state.positions.set(pos_index, p.clone());

    *da_acc = crate::batch::fold3(hasher, crate::batch::DOMAIN_DA, *da_acc, open_record(hasher, msg, pos_index));

    Ok(OpenEntry {
        borrower_pk_x: p.borrower_pk_x,
        borrower_pk_y: req.borrower_pk_y,
        borrower_index,
        borrower_cash: borrower.cash,
        borrower_coll: borrower.coll,
        borrower_nonce: borrower.nonce,
        borrower_siblings,
        lender_pk_x: p.lender_pk_x,
        lender_pk_y: req.lender_pk_y,
        lender_index,
        lender_cash: lender.cash,
        lender_coll: lender.coll,
        lender_nonce: lender.nonce,
        lender_siblings,
        cash: p.cash,
        coll: p.coll,
        rate_bps: p.rate_bps,
        haircut_bps: p.haircut_bps,
        open_ts: p.open_ts,
        maturity_ts: p.maturity_ts,
        pos_index,
        pos_old_leaf: FR_ZERO,
        pos_siblings,
        borrower_sig: req.borrower_sig.clone(),
        lender_sig: req.lender_sig.clone(),
        is_active: true,
    })
}

/// Identity-padding open entry against the CURRENT state (slot 0 accounts,
/// slot 0 position leaf raw).
fn pad_open(hasher: &Hasher, state: &L2State) -> OpenEntry {
    let slot0 = state.accounts.get(0).cloned();
    let (acct_sibs, _) = state.accounts.path(hasher, 0);
    let pos_old_leaf = PosTree::leaf_value(hasher, state.positions.get(0));
    let pos_sibs = state.positions.path(hasher, 0);
    let pad_sig = pad_signature(hasher);
    OpenEntry {
        borrower_pk_x: slot0.as_ref().map(|a| a.pk_x).unwrap_or(FR_ZERO),
        borrower_pk_y: FR_ZERO,
        borrower_index: 0,
        borrower_cash: slot0.as_ref().map(|a| a.cash).unwrap_or(0),
        borrower_coll: slot0.as_ref().map(|a| a.coll).unwrap_or(0),
        borrower_nonce: slot0.as_ref().map(|a| a.nonce).unwrap_or(0),
        borrower_siblings: acct_sibs,
        lender_pk_x: slot0.as_ref().map(|a| a.pk_x).unwrap_or(FR_ZERO),
        lender_pk_y: FR_ZERO,
        lender_index: 0,
        lender_cash: slot0.as_ref().map(|a| a.cash).unwrap_or(0),
        lender_coll: slot0.as_ref().map(|a| a.coll).unwrap_or(0),
        lender_nonce: slot0.as_ref().map(|a| a.nonce).unwrap_or(0),
        lender_siblings: acct_sibs,
        cash: 0,
        coll: 0,
        rate_bps: 0,
        haircut_bps: 0,
        open_ts: 0,
        maturity_ts: 0,
        pos_index: 0,
        pos_old_leaf,
        pos_siblings: pos_sibs,
        borrower_sig: pad_sig.clone(),
        lender_sig: pad_sig,
        is_active: false,
    }
}

/// Build a full repo batch witness: deposits → opens → payments, evolving
/// both trees of `state` in place (callers clone first, as with build_batch).
#[allow(clippy::too_many_arguments)]
pub fn build_repo_batch(
    hasher: &Hasher,
    state: &mut L2State,
    slots: (usize, usize, usize, usize, usize), // (D, C, L, O, T)
    deposits: &[DepositRequest],
    closes: &[CloseRequest],
    liqs: &[LiqRequest],
    opens: &[OpenRequest],
    txs: &[SignedTx],
    batch_ts: u64,
    price: u64,
) -> Result<RepoBatchWitness, RepoBuildError> {
    let (d_slots, c_slots, l_slots, o_slots, t_slots) = slots;
    if opens.len() > o_slots || closes.len() > c_slots || liqs.len() > l_slots {
        return Err(RepoBuildError::Payments(BuildError::TooManyEntries));
    }
    let old_acct_root = state.accounts.root(hasher);
    let old_pos_root = state.positions.root(hasher);
    let old_state_root = state_root(hasher, old_acct_root, old_pos_root);

    // Deposits ride the payments builder against the account tree only
    // (its DA fold contribution is zero — deposits are on-chain data).
    let dep_witness: BatchWitness = build_batch(
        hasher,
        &mut state.accounts,
        d_slots,
        0,
        deposits,
        &[],
    )
    .map_err(RepoBuildError::Payments)?;

    // Closes, then defaults/liquidations (freed slots become reusable by
    // opens), accumulating the DA fold from zero.
    let mut da_acc = FR_ZERO;
    let mut close_entries = Vec::new();
    for (i, req) in closes.iter().enumerate() {
        let entry = apply_close(hasher, state, i, req, batch_ts, &mut da_acc)
            .map_err(RepoBuildError::Close)?;
        close_entries.push(entry);
    }
    while close_entries.len() < c_slots {
        close_entries.push(pad_close(hasher, state));
    }
    let mut liq_entries = Vec::new();
    for (i, req) in liqs.iter().enumerate() {
        let entry = apply_liq(hasher, state, i, req, batch_ts, price, &mut da_acc)
            .map_err(RepoBuildError::Liq)?;
        liq_entries.push(entry);
    }
    while liq_entries.len() < l_slots {
        liq_entries.push(pad_liq(hasher, state));
    }

    // Opens (against both trees).
    let mut open_entries = Vec::new();
    let mut open_slots = Vec::new();
    for (i, req) in opens.iter().enumerate() {
        let entry = apply_open(hasher, state, i, req, batch_ts, price, &mut da_acc)
            .map_err(RepoBuildError::Open)?;
        open_slots.push(entry.pos_index);
        open_entries.push(entry);
    }
    while open_entries.len() < o_slots {
        open_entries.push(pad_open(hasher, state));
    }

    // Payments last; their builder folds tx messages into ITS da accumulator
    // starting from zero, so re-fold on top of the opens' accumulator.
    let pay_witness: BatchWitness =
        build_batch(hasher, &mut state.accounts, 0, t_slots, &[], txs)
            .map_err(RepoBuildError::Payments)?;
    for t in txs {
        let msg = crate::batch::tx_message(
            hasher,
            t.from_pk_x,
            t.to_field,
            t.asset,
            t.amount,
            t.nonce,
            t.is_withdraw,
        );
        da_acc = crate::batch::fold3(hasher, crate::batch::DOMAIN_DA, da_acc, msg);
    }

    let new_acct_root = state.accounts.root(hasher);
    let new_pos_root = state.positions.root(hasher);
    Ok(RepoBatchWitness {
        old_state_root,
        new_state_root: state_root(hasher, new_acct_root, new_pos_root),
        old_acct_root,
        old_pos_root,
        deposit_hash: dep_witness.deposit_hash,
        withdraw_hash: pay_witness.withdraw_hash,
        da_commitment: da_acc,
        batch_ts,
        price,
        deposits: dep_witness.deposits,
        closes: close_entries,
        liqs: liq_entries,
        opens: open_entries,
        txs: pay_witness.txs,
        open_slots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{sign_with_nonce, Keypair};
    use crate::settle::{close_message, CloseRequest, LiqRequest};
    use crate::tree::Asset;
    use ark_grumpkin::Fr as Scalar;

    fn kp(sk: u64) -> Keypair {
        Keypair::from_sk(Scalar::from(sk))
    }

    const SLOTS: (usize, usize, usize, usize, usize) = (4, 2, 2, 2, 4);
    const PRICE: u64 = 250_000_000;
    const T0: u64 = 1_700_000_000;

    /// Sum of (cash, coll) across accounts AND open positions — the PLAN §3
    /// conservation quantity (deposits/withdrawals are zero in these
    /// batches, so it must be constant across every repo op).
    fn totals(state: &L2State) -> (u128, u128) {
        let mut cash: u128 = state.accounts.leaves.values().map(|a| a.cash as u128).sum();
        let mut coll: u128 = state.accounts.leaves.values().map(|a| a.coll as u128).sum();
        for p in state.positions.slots.values() {
            // The position holds the collateral; the cash claim is not an
            // asset (the borrower already has the cash).
            coll += p.coll as u128;
            let _ = &mut cash;
        }
        (cash, coll)
    }

    fn signed_open(
        hasher: &Hasher,
        p: &Position,
        borrower: &Keypair,
        lender: &Keypair,
        b_nonce: u64,
        l_nonce: u64,
        k: u64,
    ) -> OpenRequest {
        let msg = open_message(hasher, p, b_nonce, l_nonce);
        OpenRequest {
            position: p.clone(),
            borrower_pk_y: borrower.pk_y(),
            lender_pk_y: lender.pk_y(),
            borrower_nonce: b_nonce,
            lender_nonce: l_nonce,
            borrower_sig: sign_with_nonce(hasher, borrower, msg, Scalar::from(k)),
            lender_sig: sign_with_nonce(hasher, lender, msg, Scalar::from(k + 1)),
        }
    }

    /// Full lifecycle across four batches — open, close, re-open, default,
    /// re-open, liquidate — asserting per-asset value conservation and slot
    /// reuse at every step (PLAN §3).
    #[test]
    fn repo_lifecycle_conserves_value_and_reuses_slots() {
        let hasher = Hasher::new();
        let (lender, borrower) = (kp(101), kp(202));
        let mut state = L2State::new();
        state.accounts.set(0, Account { pk_x: lender.pk_x(), cash: 50_000_000, coll: 0, nonce: 0 });
        state.accounts.set(1, Account { pk_x: borrower.pk_x(), cash: 10_000_000, coll: 20_000_000, nonce: 0 });
        let before = totals(&state);

        let terms = Position {
            borrower_pk_x: borrower.pk_x(),
            lender_pk_x: lender.pk_x(),
            cash: 5_000_000,
            coll: 10_000_000,
            rate_bps: 430,
            haircut_bps: 200,
            open_ts: T0,
            maturity_ts: T0 + 86_400,
        };

        // Batch 1: open.
        let open = signed_open(&hasher, &terms, &borrower, &lender, 0, 0, 11);
        let w1 = build_repo_batch(&hasher, &mut state, SLOTS, &[], &[], &[], &[open], &[], T0 + 10, PRICE)
            .unwrap();
        assert_eq!(w1.open_slots, vec![0]);
        assert_eq!(totals(&state), before, "open must conserve both assets");

        // Batch 2: borrower closes 6h in; interest moves cash borrower->lender.
        let close_msg = close_message(&hasher, 0, &terms, 1);
        let close = CloseRequest {
            pos_index: 0,
            borrower_pk_y: borrower.pk_y(),
            borrower_nonce: 1,
            sig: sign_with_nonce(&hasher, &borrower, close_msg, Scalar::from(21u64)),
        };
        build_repo_batch(&hasher, &mut state, SLOTS, &[], &[close], &[], &[], &[], T0 + 21_600, PRICE)
            .unwrap();
        assert_eq!(totals(&state), before, "close must conserve both assets");
        assert!(state.positions.slots.is_empty());
        let intr = crate::settle::interest(5_000_000, 430, 21_590).unwrap();
        assert_eq!(state.accounts.get(0).unwrap().cash, 50_000_000 + intr);

        // Batch 3: re-open into the FREED slot, then let it default.
        let mut terms2 = terms.clone();
        terms2.open_ts = T0 + 22_000;
        terms2.maturity_ts = T0 + 22_100;
        let open2 = signed_open(&hasher, &terms2, &borrower, &lender, 2, 1, 31);
        let w3 = build_repo_batch(&hasher, &mut state, SLOTS, &[], &[], &[], &[open2], &[], T0 + 22_050, PRICE)
            .unwrap();
        assert_eq!(w3.open_slots, vec![0], "freed slot must be reused (find-first)");
        build_repo_batch(
            &hasher, &mut state, SLOTS,
            &[], &[], &[LiqRequest { pos_index: 0, is_liquidation: false }], &[], &[],
            T0 + 23_000, PRICE,
        )
        .unwrap();
        assert_eq!(totals(&state), before, "default must conserve both assets");
        // Lender took the collateral.
        assert_eq!(state.accounts.get(0).unwrap().coll, 10_000_000);

        // Batch 4: open once more and liquidate on a price crash.
        let mut terms3 = terms.clone();
        terms3.open_ts = T0 + 24_000;
        terms3.maturity_ts = T0 + 100_000;
        let open3 = signed_open(&hasher, &terms3, &borrower, &lender, 3, 2, 41);
        build_repo_batch(&hasher, &mut state, SLOTS, &[], &[], &[], &[open3], &[], T0 + 24_010, PRICE)
            .unwrap();
        let crash = 3_000_000; // well past the half-haircut breach
        build_repo_batch(
            &hasher, &mut state, SLOTS,
            &[], &[], &[LiqRequest { pos_index: 0, is_liquidation: true }], &[], &[],
            T0 + 24_100, crash,
        )
        .unwrap();
        assert_eq!(totals(&state), before, "liquidation must conserve both assets");
        assert_eq!(state.accounts.get(0).unwrap().coll, 20_000_000);
        assert!(state.positions.slots.is_empty());
    }

    /// Watcher-shaped negatives: the builder must refuse a default before
    /// maturity and a liquidation at a healthy price.
    #[test]
    fn settle_preconditions_enforced_at_build() {
        let hasher = Hasher::new();
        let (lender, borrower) = (kp(101), kp(202));
        let mut state = L2State::new();
        state.accounts.set(0, Account { pk_x: lender.pk_x(), cash: 50_000_000, coll: 0, nonce: 0 });
        state.accounts.set(1, Account { pk_x: borrower.pk_x(), cash: 0, coll: 20_000_000, nonce: 0 });
        let terms = Position {
            borrower_pk_x: borrower.pk_x(),
            lender_pk_x: lender.pk_x(),
            cash: 5_000_000,
            coll: 10_000_000,
            rate_bps: 430,
            haircut_bps: 200,
            open_ts: T0,
            maturity_ts: T0 + 86_400,
        };
        let open = signed_open(&hasher, &terms, &borrower, &lender, 0, 0, 51);
        build_repo_batch(&hasher, &mut state, SLOTS, &[], &[], &[], &[open], &[], T0 + 10, PRICE)
            .unwrap();

        // Default before maturity: refused.
        let clone = |s: &L2State| L2State {
            accounts: Tree { leaves: s.accounts.leaves.clone() },
            positions: PosTree { slots: s.positions.slots.clone() },
        };
        let err = build_repo_batch(
            &hasher, &mut clone(&state), SLOTS,
            &[], &[], &[LiqRequest { pos_index: 0, is_liquidation: false }], &[], &[],
            T0 + 100, PRICE,
        )
        .unwrap_err();
        assert!(matches!(err, RepoBuildError::Liq(crate::settle::SettleError::NotPastMaturity { .. })));

        // Liquidation at a healthy price: refused.
        let err = build_repo_batch(
            &hasher, &mut clone(&state), SLOTS,
            &[], &[], &[LiqRequest { pos_index: 0, is_liquidation: true }], &[], &[],
            T0 + 100, PRICE,
        )
        .unwrap_err();
        assert!(matches!(err, RepoBuildError::Liq(crate::settle::SettleError::MarginHealthy { .. })));
    }
}
