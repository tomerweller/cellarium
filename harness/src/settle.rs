//! Repo settlement (M3/M4): borrower-signed close, permissionless
//! default/liquidation, and the interest computation. Mirrors
//! circuits/lib/src/settle.nr exactly (u128 arithmetic for interest,
//! fixture-tested against the circuit).

use crate::batch::{fold3, DOMAIN_DA};
use crate::keys::{pad_signature, pk_from_coords, verify, Signature};
use crate::poseidon::{fr_from_u64, Fr, Hasher, FR_ZERO};
use crate::repo::{pos_leaf, L2State, PosTree, Position, DOMAIN_CLOSE};
use crate::tree::{Account, DEPTH};

/// 10^4 * 360 * 86400 (bps scale x ACT/360 year in seconds).
pub const INTEREST_DENOM: u128 = 311_040_000_000;

/// interest = floor(cash * rate_bps * elapsed / DENOM) in u128 (fits: u64 *
/// u32 * u64 < 2^160 needs u128 care — checked math; realistic values are
/// far smaller). Mirrors the circuit's floor-division constraint. `None` on
/// u128 product overflow or an interest above u64 — such terms are
/// unprovable anyway (the circuit's assert_u64 on interest fails), and a
/// panic here would kill the engine thread (issue #1 L7).
pub fn interest(cash: u64, rate_bps: u32, elapsed_secs: u64) -> Option<u64> {
    // cash * rate <= 2^64 * 2^32 = 2^96; * elapsed can exceed u128 only for
    // absurd elapsed (< 2^32 secs = 136 years is safe: 96+32 = 128).
    let product = (cash as u128)
        .checked_mul(rate_bps as u128)?
        .checked_mul(elapsed_secs as u128)?;
    u64::try_from(product / INTEREST_DENOM).ok()
}

/// The close signing message: P2([DOMAIN_CLOSE, pos_index, pos_leaf, nonce]).
pub fn close_message(
    hasher: &Hasher,
    pos_index: u32,
    position: &Position,
    borrower_nonce: u64,
) -> Fr {
    let leaf = pos_leaf(hasher, position);
    hasher.hash(&[
        fr_from_u64(DOMAIN_CLOSE),
        fr_from_u64(pos_index as u64),
        leaf,
        fr_from_u64(borrower_nonce),
    ])
}

/// The DA record for a default/liquidation: P2([pos_index, is_liquidation]).
pub fn liq_record(hasher: &Hasher, pos_index: u32, is_liquidation: bool) -> Fr {
    hasher.hash2(
        fr_from_u64(pos_index as u64),
        fr_from_u64(is_liquidation as u64),
    )
}

/// Margin-breach predicate at the batch price, division-free (PLAN.md 6.1.1):
/// coll * price * 2e4 < cash * (2e4 + haircut_bps) * 1e7.
pub fn margin_breached(position: &Position, price: u64) -> bool {
    let lhs = (position.coll as u128) * (price as u128) * 20_000;
    let rhs = (position.cash as u128) * (20_000 + position.haircut_bps as u128) * 10_000_000;
    lhs < rhs
}

/// A borrower-signed close request as received over the wire.
#[derive(Debug, Clone)]
pub struct CloseRequest {
    pub pos_index: u32,
    pub borrower_pk_y: Fr,
    pub borrower_nonce: u64,
    pub sig: Signature,
}

/// A permissionless default/liquidation the watcher enqueues.
#[derive(Debug, Clone)]
pub struct LiqRequest {
    pub pos_index: u32,
    pub is_liquidation: bool,
}

#[derive(Debug, Clone)]
pub struct CloseEntry {
    pub position: Position,
    pub pos_index: u32,
    pub pos_old_leaf: Fr,
    pub pos_siblings: [Fr; DEPTH],
    pub borrower_pk_y: Fr,
    pub borrower_index: u32,
    pub borrower_cash: u64,
    pub borrower_coll: u64,
    pub borrower_nonce: u64,
    pub borrower_siblings: [Fr; DEPTH],
    pub lender_index: u32,
    pub lender_cash: u64,
    pub lender_coll: u64,
    pub lender_nonce: u64,
    pub lender_siblings: [Fr; DEPTH],
    pub interest: u64,
    pub sig: Signature,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct LiqEntry {
    pub position: Position,
    pub pos_index: u32,
    pub pos_old_leaf: Fr,
    pub pos_siblings: [Fr; DEPTH],
    pub lender_index: u32,
    pub lender_cash: u64,
    pub lender_coll: u64,
    pub lender_nonce: u64,
    pub lender_siblings: [Fr; DEPTH],
    pub is_liquidation: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleError {
    PositionNotFound {
        index: usize,
    },
    BorrowerNotFound {
        index: usize,
    },
    LenderNotFound {
        index: usize,
    },
    NonceMismatch {
        index: usize,
        expected: u64,
        got: u64,
    },
    BadSignature {
        index: usize,
    },
    PastMaturity {
        index: usize,
    },
    NotPastMaturity {
        index: usize,
    },
    MarginHealthy {
        index: usize,
    },
    InsufficientCash {
        index: usize,
        available: u64,
        needed: u64,
    },
    BalanceOverflow {
        index: usize,
    },
    /// The position's open_ts postdates batch_ts (issue #1 M4): elapsed
    /// would underflow and the close is unprovable in-circuit.
    FutureOpenTs {
        index: usize,
    },
    /// cash * rate * elapsed overflows or interest exceeds u64 (issue #1
    /// L7): unprovable terms; must not panic the engine thread.
    InterestOverflow {
        index: usize,
    },
}

impl std::fmt::Display for SettleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SettleError {}

/// Apply one close to the live state, producing the witness entry.
pub fn apply_close(
    hasher: &Hasher,
    state: &mut L2State,
    i: usize,
    req: &CloseRequest,
    batch_ts: u64,
    da_acc: &mut Fr,
) -> Result<CloseEntry, SettleError> {
    let position = state
        .positions
        .get(req.pos_index)
        .cloned()
        .ok_or(SettleError::PositionNotFound { index: i })?;
    if batch_ts > position.maturity_ts {
        return Err(SettleError::PastMaturity { index: i });
    }
    let borrower_index = state
        .accounts
        .find(&position.borrower_pk_x)
        .ok_or(SettleError::BorrowerNotFound { index: i })?;
    let lender_index = state
        .accounts
        .find(&position.lender_pk_x)
        .ok_or(SettleError::LenderNotFound { index: i })?;
    let borrower = state.accounts.get(borrower_index).cloned().unwrap();
    let lender = state.accounts.get(lender_index).cloned().unwrap();
    if borrower.nonce != req.borrower_nonce {
        return Err(SettleError::NonceMismatch {
            index: i,
            expected: borrower.nonce,
            got: req.borrower_nonce,
        });
    }

    let msg = close_message(hasher, req.pos_index, &position, req.borrower_nonce);
    let pk = pk_from_coords(&position.borrower_pk_x, &req.borrower_pk_y)
        .ok_or(SettleError::BadSignature { index: i })?;
    if !verify(hasher, &pk, msg, &req.sig) {
        return Err(SettleError::BadSignature { index: i });
    }

    // Circuit mirror (issue #1 M4): elapsed = batch_ts - open_ts must not
    // underflow; settle.nr's assert_u64(elapsed) makes such a close
    // unprovable, so building it would only burn a prove cycle.
    let elapsed = batch_ts
        .checked_sub(position.open_ts)
        .ok_or(SettleError::FutureOpenTs { index: i })?;
    let intr = interest(position.cash, position.rate_bps, elapsed)
        .ok_or(SettleError::InterestOverflow { index: i })?;
    let repay = position
        .cash
        .checked_add(intr)
        .ok_or(SettleError::BalanceOverflow { index: i })?;
    if borrower.cash < repay {
        return Err(SettleError::InsufficientCash {
            index: i,
            available: borrower.cash,
            needed: repay,
        });
    }
    let b_new_coll = borrower
        .coll
        .checked_add(position.coll)
        .ok_or(SettleError::BalanceOverflow { index: i })?;
    let l_new_cash = lender
        .cash
        .checked_add(repay)
        .ok_or(SettleError::BalanceOverflow { index: i })?;

    // Witness snapshots BEFORE mutation, applied in circuit order:
    // borrower update -> lender update -> position zeroed.
    let (borrower_siblings, _) = state.accounts.path(hasher, borrower_index);
    state.accounts.set(
        borrower_index,
        Account {
            pk_x: position.borrower_pk_x,
            cash: borrower.cash - repay,
            coll: b_new_coll,
            nonce: borrower.nonce + 1,
        },
    );
    let (lender_siblings, _) = state.accounts.path(hasher, lender_index);
    state.accounts.set(
        lender_index,
        Account {
            pk_x: position.lender_pk_x,
            cash: l_new_cash,
            coll: lender.coll,
            nonce: lender.nonce,
        },
    );
    let pos_siblings = state.positions.path(hasher, req.pos_index);
    state.positions.remove(req.pos_index);

    *da_acc = fold3(hasher, DOMAIN_DA, *da_acc, msg);

    Ok(CloseEntry {
        position: position.clone(),
        pos_index: req.pos_index,
        pos_old_leaf: FR_ZERO, // unused on the active path
        pos_siblings,
        borrower_pk_y: req.borrower_pk_y,
        borrower_index,
        borrower_cash: borrower.cash,
        borrower_coll: borrower.coll,
        borrower_nonce: borrower.nonce,
        borrower_siblings,
        lender_index,
        lender_cash: lender.cash,
        lender_coll: lender.coll,
        lender_nonce: lender.nonce,
        lender_siblings,
        interest: intr,
        sig: req.sig.clone(),
        is_active: true,
    })
}

/// Apply one default/liquidation to the live state.
pub fn apply_liq(
    hasher: &Hasher,
    state: &mut L2State,
    i: usize,
    req: &LiqRequest,
    batch_ts: u64,
    price: u64,
    da_acc: &mut Fr,
) -> Result<LiqEntry, SettleError> {
    let position = state
        .positions
        .get(req.pos_index)
        .cloned()
        .ok_or(SettleError::PositionNotFound { index: i })?;
    if req.is_liquidation {
        if !margin_breached(&position, price) {
            return Err(SettleError::MarginHealthy { index: i });
        }
    } else if batch_ts <= position.maturity_ts {
        return Err(SettleError::NotPastMaturity { index: i });
    }
    let lender_index = state
        .accounts
        .find(&position.lender_pk_x)
        .ok_or(SettleError::LenderNotFound { index: i })?;
    let lender = state.accounts.get(lender_index).cloned().unwrap();
    let l_new_coll = lender
        .coll
        .checked_add(position.coll)
        .ok_or(SettleError::BalanceOverflow { index: i })?;

    let (lender_siblings, _) = state.accounts.path(hasher, lender_index);
    state.accounts.set(
        lender_index,
        Account {
            pk_x: position.lender_pk_x,
            cash: lender.cash,
            coll: l_new_coll,
            nonce: lender.nonce,
        },
    );
    let pos_siblings = state.positions.path(hasher, req.pos_index);
    state.positions.remove(req.pos_index);

    *da_acc = fold3(
        hasher,
        DOMAIN_DA,
        *da_acc,
        liq_record(hasher, req.pos_index, req.is_liquidation),
    );

    Ok(LiqEntry {
        position: position.clone(),
        pos_index: req.pos_index,
        pos_old_leaf: FR_ZERO,
        pos_siblings,
        lender_index,
        lender_cash: lender.cash,
        lender_coll: lender.coll,
        lender_nonce: lender.nonce,
        lender_siblings,
        is_liquidation: req.is_liquidation,
        is_active: true,
    })
}

/// Identity-padding close entry against the CURRENT state.
pub fn pad_close(hasher: &Hasher, state: &L2State) -> CloseEntry {
    let slot0 = state.accounts.get(0).cloned();
    let (acct_sibs, _) = state.accounts.path(hasher, 0);
    let pos_old_leaf = PosTree::leaf_value(hasher, state.positions.get(0));
    let pos_sibs = state.positions.path(hasher, 0);
    let a = |f: fn(&Account) -> u64| slot0.as_ref().map(f).unwrap_or(0);
    CloseEntry {
        position: Position {
            borrower_pk_x: slot0.as_ref().map(|x| x.pk_x).unwrap_or(FR_ZERO),
            lender_pk_x: slot0.as_ref().map(|x| x.pk_x).unwrap_or(FR_ZERO),
            cash: 0,
            coll: 0,
            rate_bps: 0,
            haircut_bps: 0,
            open_ts: 0,
            maturity_ts: 0,
        },
        pos_index: 0,
        pos_old_leaf,
        pos_siblings: pos_sibs,
        borrower_pk_y: FR_ZERO,
        borrower_index: 0,
        borrower_cash: a(|x| x.cash),
        borrower_coll: a(|x| x.coll),
        borrower_nonce: a(|x| x.nonce),
        borrower_siblings: acct_sibs,
        lender_index: 0,
        lender_cash: a(|x| x.cash),
        lender_coll: a(|x| x.coll),
        lender_nonce: a(|x| x.nonce),
        lender_siblings: acct_sibs,
        interest: 0,
        sig: pad_signature(hasher),
        is_active: false,
    }
}

/// Identity-padding default/liquidation entry against the CURRENT state.
pub fn pad_liq(hasher: &Hasher, state: &L2State) -> LiqEntry {
    let slot0 = state.accounts.get(0).cloned();
    let (acct_sibs, _) = state.accounts.path(hasher, 0);
    let pos_old_leaf = PosTree::leaf_value(hasher, state.positions.get(0));
    let pos_sibs = state.positions.path(hasher, 0);
    let a = |f: fn(&Account) -> u64| slot0.as_ref().map(f).unwrap_or(0);
    LiqEntry {
        position: Position {
            borrower_pk_x: slot0.as_ref().map(|x| x.pk_x).unwrap_or(FR_ZERO),
            lender_pk_x: slot0.as_ref().map(|x| x.pk_x).unwrap_or(FR_ZERO),
            cash: 0,
            coll: 0,
            rate_bps: 0,
            haircut_bps: 0,
            open_ts: 0,
            maturity_ts: 0,
        },
        pos_index: 0,
        pos_old_leaf,
        pos_siblings: pos_sibs,
        lender_index: 0,
        lender_cash: a(|x| x.cash),
        lender_coll: a(|x| x.coll),
        lender_nonce: a(|x| x.nonce),
        lender_siblings: acct_sibs,
        is_liquidation: false,
        is_active: false,
    }
}
