//! SQLite persistence. Conventions: Fr values as strict 0x-hex (hexutil),
//! amounts as decimal TEXT (u64 range exceeds SQLite's i64), timestamps as
//! unix seconds. WAL + synchronous=FULL: rows written before irreversible
//! actions (proving, submitting) are the crash-recovery ground truth.

use crate::hexutil::{fr_hex, parse_fr};
use harness::poseidon::Fr;
use rusqlite::{params, Connection, OptionalExtension};

pub type DbResult<T> = Result<T, rusqlite::Error>;

pub const SCHEMA_VERSION: i64 = 4;

pub fn open(path: &std::path::Path) -> DbResult<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> DbResult<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= SCHEMA_VERSION {
        return Ok(());
    }
    // v1 (single-asset payments) state is not migratable: the leaf layout
    // changed, so a v1 DB belongs to a different rollup instance anyway
    // (new circuit == new VK == fresh contract). Refuse rather than corrupt.
    if version != 0 {
        panic!("sequencer DB schema v{version} is incompatible with v{SCHEMA_VERSION}; delete the DB and re-sync against the (new) contract");
    }
    conn.execute_batch(
        r#"
        BEGIN;
        CREATE TABLE IF NOT EXISTS meta (
          key   TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS leaves (
          idx     INTEGER PRIMARY KEY,
          pk_x    TEXT NOT NULL UNIQUE,
          cash    TEXT NOT NULL,
          coll    TEXT NOT NULL,
          nonce   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mempool (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          from_pk_x     TEXT NOT NULL,
          from_pk_y     TEXT NOT NULL,
          to_field      TEXT NOT NULL,
          withdraw_dest TEXT,
          asset         INTEGER NOT NULL,
          amount        TEXT NOT NULL,
          nonce         INTEGER NOT NULL,
          is_withdraw   INTEGER NOT NULL,
          sig_r_x  TEXT NOT NULL,
          sig_r_y  TEXT NOT NULL,
          sig_s_lo TEXT NOT NULL,
          sig_s_hi TEXT NOT NULL,
          status      TEXT NOT NULL DEFAULT 'pending',
          batch_num   INTEGER,
          reject_reason TEXT,
          received_at INTEGER NOT NULL,
          UNIQUE(from_pk_x, nonce)
        );
        CREATE TABLE IF NOT EXISTS deposits (
          asset       INTEGER NOT NULL,
          seq         INTEGER NOT NULL,
          pk_x        TEXT NOT NULL,
          amount      TEXT NOT NULL,
          status      TEXT NOT NULL DEFAULT 'pending',
          batch_num   INTEGER,
          observed_at INTEGER NOT NULL,
          PRIMARY KEY (asset, seq)
        );
        CREATE TABLE IF NOT EXISTS positions (
          slot          INTEGER PRIMARY KEY,
          borrower_pk_x TEXT NOT NULL,
          lender_pk_x   TEXT NOT NULL,
          cash          TEXT NOT NULL,
          coll          TEXT NOT NULL,
          rate_bps      INTEGER NOT NULL,
          haircut_bps   INTEGER NOT NULL,
          open_ts       INTEGER NOT NULL,
          maturity_ts   INTEGER NOT NULL,
          opened_batch  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intents (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          initiator     TEXT NOT NULL CHECK (initiator IN ('borrower','lender')),
          borrower_pk_x TEXT NOT NULL,
          borrower_pk_y TEXT NOT NULL,
          lender_pk_x   TEXT NOT NULL,
          lender_pk_y   TEXT NOT NULL,
          cash          TEXT NOT NULL,
          coll          TEXT NOT NULL,
          rate_bps      INTEGER NOT NULL,
          haircut_bps   INTEGER NOT NULL,
          open_ts       INTEGER NOT NULL,
          maturity_ts   INTEGER NOT NULL,
          borrower_nonce INTEGER NOT NULL,
          lender_nonce  INTEGER NOT NULL,
          sig_r_x  TEXT NOT NULL,
          sig_r_y  TEXT NOT NULL,
          sig_s_lo TEXT NOT NULL,
          sig_s_hi TEXT NOT NULL,
          status      TEXT NOT NULL DEFAULT 'open',
          created_at  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS opens (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          intent_id     INTEGER,
          borrower_pk_x TEXT NOT NULL,
          borrower_pk_y TEXT NOT NULL,
          lender_pk_x   TEXT NOT NULL,
          lender_pk_y   TEXT NOT NULL,
          cash          TEXT NOT NULL,
          coll          TEXT NOT NULL,
          rate_bps      INTEGER NOT NULL,
          haircut_bps   INTEGER NOT NULL,
          open_ts       INTEGER NOT NULL,
          maturity_ts   INTEGER NOT NULL,
          borrower_nonce INTEGER NOT NULL,
          lender_nonce  INTEGER NOT NULL,
          b_sig_r_x  TEXT NOT NULL,
          b_sig_r_y  TEXT NOT NULL,
          b_sig_s_lo TEXT NOT NULL,
          b_sig_s_hi TEXT NOT NULL,
          l_sig_r_x  TEXT NOT NULL,
          l_sig_r_y  TEXT NOT NULL,
          l_sig_s_lo TEXT NOT NULL,
          l_sig_s_hi TEXT NOT NULL,
          status      TEXT NOT NULL DEFAULT 'pending',
          batch_num   INTEGER,
          reject_reason TEXT,
          received_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS closes (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          pos_index     INTEGER NOT NULL,
          borrower_pk_x TEXT NOT NULL,
          borrower_pk_y TEXT NOT NULL,
          borrower_nonce INTEGER NOT NULL,
          sig_r_x  TEXT NOT NULL,
          sig_r_y  TEXT NOT NULL,
          sig_s_lo TEXT NOT NULL,
          sig_s_hi TEXT NOT NULL,
          status      TEXT NOT NULL DEFAULT 'pending',
          batch_num   INTEGER,
          reject_reason TEXT,
          received_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS liqs (
          pos_index     INTEGER PRIMARY KEY,
          is_liquidation INTEGER NOT NULL,
          status      TEXT NOT NULL DEFAULT 'pending',
          batch_num   INTEGER,
          reject_reason TEXT,
          created_at  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS batches (
          batch_num     INTEGER PRIMARY KEY,
          old_root      TEXT NOT NULL,
          new_root      TEXT NOT NULL,
          deposit_count_cash INTEGER NOT NULL,
          deposit_count_coll INTEGER NOT NULL,
          batch_ts      INTEGER NOT NULL,
          price         TEXT NOT NULL,
          da_commitment TEXT NOT NULL,
          blob_json     TEXT NOT NULL,
          envelope_json TEXT NOT NULL,
          proof         BLOB,
          status  TEXT NOT NULL,
          tx_hash TEXT,
          created_at INTEGER NOT NULL,
          confirmed_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          pk_x TEXT NOT NULL,
          batch_num INTEGER NOT NULL,
          kind TEXT NOT NULL,
          counterparty TEXT,
          asset INTEGER NOT NULL DEFAULT 0,
          amount TEXT NOT NULL,
          nonce INTEGER,
          ts INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS history_pk ON history(pk_x, id DESC);
        PRAGMA user_version = 4;
        COMMIT;
        "#,
    )
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------- meta ----------

pub fn meta_get(conn: &Connection, key: &str) -> DbResult<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()
}

pub fn meta_set(conn: &Connection, key: &str, value: &str) -> DbResult<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn meta_get_u64(conn: &Connection, key: &str) -> DbResult<u64> {
    Ok(meta_get(conn, key)?.and_then(|v| v.parse().ok()).unwrap_or(0))
}

// ---------- leaves ----------

pub fn load_leaves(conn: &Connection) -> DbResult<Vec<(u32, Fr, u64, u64, u64)>> {
    let mut stmt = conn.prepare("SELECT idx, pk_x, cash, coll, nonce FROM leaves")?;
    let rows = stmt.query_map([], |r| {
        let idx: u32 = r.get(0)?;
        let pk_x: String = r.get(1)?;
        let cash: String = r.get(2)?;
        let coll: String = r.get(3)?;
        let nonce: i64 = r.get(4)?;
        Ok((idx, pk_x, cash, coll, nonce))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (idx, pk_x, cash, coll, nonce) = row?;
        out.push((
            idx,
            parse_fr(&pk_x).expect("db pk_x corrupt"),
            cash.parse().expect("db cash corrupt"),
            coll.parse().expect("db coll corrupt"),
            nonce as u64,
        ));
    }
    Ok(out)
}

pub fn upsert_leaf(conn: &Connection, idx: u32, pk_x: &Fr, cash: u64, coll: u64, nonce: u64) -> DbResult<()> {
    conn.execute(
        "INSERT INTO leaves(idx, pk_x, cash, coll, nonce) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(idx) DO UPDATE SET pk_x = excluded.pk_x,
           cash = excluded.cash, coll = excluded.coll, nonce = excluded.nonce",
        params![idx, fr_hex(pk_x), cash.to_string(), coll.to_string(), nonce as i64],
    )?;
    Ok(())
}

// ---------- mempool ----------

#[derive(Debug, Clone)]
#[allow(dead_code)] // status/received_at mirror DB columns; not all read yet
pub struct MempoolRow {
    pub id: i64,
    pub from_pk_x: Fr,
    pub from_pk_y: Fr,
    pub to_field: Fr,
    pub withdraw_dest: Option<String>,
    pub asset: u32,
    pub amount: u64,
    pub nonce: u64,
    pub is_withdraw: bool,
    pub sig_r_x: Fr,
    pub sig_r_y: Fr,
    pub sig_s_lo: Fr,
    pub sig_s_hi: Fr,
    pub status: String,
    pub received_at: i64,
}

fn mempool_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MempoolRow> {
    let get_fr = |i: usize| -> rusqlite::Result<Fr> {
        let s: String = r.get(i)?;
        Ok(parse_fr(&s).expect("db fr corrupt"))
    };
    Ok(MempoolRow {
        id: r.get(0)?,
        from_pk_x: get_fr(1)?,
        from_pk_y: get_fr(2)?,
        to_field: get_fr(3)?,
        withdraw_dest: r.get(4)?,
        asset: r.get::<_, i64>(5)? as u32,
        amount: r.get::<_, String>(6)?.parse().expect("db amount corrupt"),
        nonce: r.get::<_, i64>(7)? as u64,
        is_withdraw: r.get::<_, i64>(8)? != 0,
        sig_r_x: get_fr(9)?,
        sig_r_y: get_fr(10)?,
        sig_s_lo: get_fr(11)?,
        sig_s_hi: get_fr(12)?,
        status: r.get(13)?,
        received_at: r.get(14)?,
    })
}

const MEMPOOL_COLS: &str = "id, from_pk_x, from_pk_y, to_field, withdraw_dest, asset, amount, nonce, \
                            is_withdraw, sig_r_x, sig_r_y, sig_s_lo, sig_s_hi, status, received_at";

#[allow(clippy::too_many_arguments)]
pub fn insert_mempool(
    conn: &Connection,
    from_pk_x: &Fr,
    from_pk_y: &Fr,
    to_field: &Fr,
    withdraw_dest: Option<&str>,
    asset: u32,
    amount: u64,
    nonce: u64,
    is_withdraw: bool,
    sig: [&Fr; 4],
) -> DbResult<i64> {
    conn.execute(
        "INSERT INTO mempool(from_pk_x, from_pk_y, to_field, withdraw_dest, asset, amount, nonce,
                             is_withdraw, sig_r_x, sig_r_y, sig_s_lo, sig_s_hi, received_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            fr_hex(from_pk_x),
            fr_hex(from_pk_y),
            fr_hex(to_field),
            withdraw_dest,
            asset as i64,
            amount.to_string(),
            nonce as i64,
            is_withdraw as i64,
            fr_hex(sig[0]),
            fr_hex(sig[1]),
            fr_hex(sig[2]),
            fr_hex(sig[3]),
            now(),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn mempool_find(conn: &Connection, from_pk_x: &Fr, nonce: u64) -> DbResult<Option<(i64, String)>> {
    conn.query_row(
        "SELECT id, status FROM mempool WHERE from_pk_x = ?1 AND nonce = ?2",
        params![fr_hex(from_pk_x), nonce as i64],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

/// Pending txs in arrival order (per-sender nonce order falls out of the
/// UNIQUE(from,nonce) admission rule + arrival ordering).
pub fn mempool_pending(conn: &Connection, limit: usize) -> DbResult<Vec<MempoolRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {MEMPOOL_COLS} FROM mempool WHERE status = 'pending' ORDER BY id LIMIT ?1"
    ))?;
    let rows = stmt.query_map([limit as i64], |r| mempool_row(r))?;
    rows.collect()
}

pub fn mempool_pending_for(conn: &Connection, from_pk_x: &Fr) -> DbResult<Vec<MempoolRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {MEMPOOL_COLS} FROM mempool
         WHERE from_pk_x = ?1 AND status IN ('pending','batching') ORDER BY nonce"
    ))?;
    let rows = stmt.query_map([fr_hex(from_pk_x)], |r| mempool_row(r))?;
    rows.collect()
}

pub fn mempool_count_pending(conn: &Connection) -> DbResult<u64> {
    conn.query_row(
        "SELECT COUNT(*) FROM mempool WHERE status = 'pending'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )
}

pub fn mempool_oldest_pending_age(conn: &Connection) -> DbResult<Option<i64>> {
    conn.query_row(
        "SELECT MIN(received_at) FROM mempool WHERE status = 'pending'",
        [],
        |r| r.get::<_, Option<i64>>(0),
    )
    .map(|min| min.map(|m| now() - m))
}

pub fn mempool_set_status(conn: &Connection, ids: &[i64], status: &str, batch_num: Option<u64>, reason: Option<&str>) -> DbResult<()> {
    for id in ids {
        conn.execute(
            "UPDATE mempool SET status = ?1, batch_num = ?2, reject_reason = ?3 WHERE id = ?4",
            params![status, batch_num.map(|b| b as i64), reason, id],
        )?;
    }
    Ok(())
}

// ---------- deposits ----------

#[derive(Debug, Clone)]
#[allow(dead_code)] // status mirrors a DB column; not read by consumers yet
pub struct DepositRow {
    pub asset: u32,
    pub seq: u64,
    pub pk_x: Fr,
    pub amount: u64,
    pub status: String,
}

pub fn insert_deposit(conn: &Connection, asset: u32, seq: u64, pk_x: &Fr, amount: u64) -> DbResult<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO deposits(asset, seq, pk_x, amount, observed_at) VALUES (?1,?2,?3,?4,?5)",
        params![asset as i64, seq as i64, fr_hex(pk_x), amount.to_string(), now()],
    )?;
    Ok(n > 0)
}

/// Pending deposits ordered cash-queue-prefix first, then coll (the fold
/// order the contract recomputes), FIFO within each asset. NOTE: because a
/// batch must consume a contiguous PREFIX of each on-chain queue, the limit
/// must never split an asset's pending run mid-way out of seq order — the
/// ORDER BY asset, seq guarantees this.
pub fn deposits_pending(conn: &Connection, limit: usize) -> DbResult<Vec<DepositRow>> {
    let mut stmt = conn.prepare(
        "SELECT asset, seq, pk_x, amount, status FROM deposits WHERE status = 'pending'
         ORDER BY asset, seq LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit as i64], |r| {
        Ok(DepositRow {
            asset: r.get::<_, i64>(0)? as u32,
            seq: r.get::<_, i64>(1)? as u64,
            pk_x: parse_fr(&r.get::<_, String>(2)?).expect("db pk_x corrupt"),
            amount: r.get::<_, String>(3)?.parse().expect("db amount corrupt"),
            status: r.get(4)?,
        })
    })?;
    rows.collect()
}

pub fn deposits_count_pending(conn: &Connection) -> DbResult<u64> {
    conn.query_row("SELECT COUNT(*) FROM deposits WHERE status = 'pending'", [], |r| {
        r.get::<_, i64>(0).map(|v| v as u64)
    })
}

pub fn deposits_pending_pk(conn: &Connection, pk_x: &Fr) -> DbResult<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM deposits WHERE pk_x = ?1 AND status IN ('pending','batching')",
        [fr_hex(pk_x)],
        |r| r.get::<_, i64>(0).map(|v| v > 0),
    )
}

pub fn deposits_oldest_pending_age(conn: &Connection) -> DbResult<Option<i64>> {
    conn.query_row(
        "SELECT MIN(observed_at) FROM deposits WHERE status = 'pending'",
        [],
        |r| r.get::<_, Option<i64>>(0),
    )
    .map(|min| min.map(|m| now() - m))
}

pub fn deposits_set_status(conn: &Connection, keys: &[(u32, u64)], status: &str, batch_num: Option<u64>) -> DbResult<()> {
    for (asset, seq) in keys {
        conn.execute(
            "UPDATE deposits SET status = ?1, batch_num = ?2 WHERE asset = ?3 AND seq = ?4",
            params![status, batch_num.map(|b| b as i64), *asset as i64, *seq as i64],
        )?;
    }
    Ok(())
}

// ---------- batches ----------

#[derive(Debug, Clone)]
pub struct BatchRow {
    pub batch_num: u64,
    pub old_root: Fr,
    pub new_root: Fr,
    pub deposit_count_cash: u32,
    pub deposit_count_coll: u32,
    pub batch_ts: u64,
    pub price: u64,
    pub da_commitment: Fr,
    pub blob_json: String,
    pub envelope_json: String,
    pub proof: Option<Vec<u8>>,
    pub status: String,
    pub tx_hash: Option<String>,
    pub created_at: i64,
    pub confirmed_at: Option<i64>,
}

fn batch_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<BatchRow> {
    Ok(BatchRow {
        batch_num: r.get::<_, i64>(0)? as u64,
        old_root: parse_fr(&r.get::<_, String>(1)?).expect("db root corrupt"),
        new_root: parse_fr(&r.get::<_, String>(2)?).expect("db root corrupt"),
        deposit_count_cash: r.get::<_, i64>(3)? as u32,
        deposit_count_coll: r.get::<_, i64>(4)? as u32,
        batch_ts: r.get::<_, i64>(5)? as u64,
        price: r.get::<_, String>(6)?.parse().expect("db price corrupt"),
        da_commitment: parse_fr(&r.get::<_, String>(7)?).expect("db da corrupt"),
        blob_json: r.get(8)?,
        envelope_json: r.get(9)?,
        proof: r.get(10)?,
        status: r.get(11)?,
        tx_hash: r.get(12)?,
        created_at: r.get(13)?,
        confirmed_at: r.get(14)?,
    })
}

const BATCH_COLS: &str = "batch_num, old_root, new_root, deposit_count_cash, deposit_count_coll, \
                          batch_ts, price, da_commitment, blob_json, envelope_json, proof, status, \
                          tx_hash, created_at, confirmed_at";

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
pub fn insert_batch(
    conn: &Connection,
    batch_num: u64,
    old_root: &Fr,
    new_root: &Fr,
    deposit_count_cash: u32,
    deposit_count_coll: u32,
    batch_ts: u64,
    price: u64,
    da_commitment: &Fr,
    blob_json: &str,
    envelope_json: &str,
) -> DbResult<()> {
    conn.execute(
        "INSERT INTO batches(batch_num, old_root, new_root, deposit_count_cash, deposit_count_coll,
                             batch_ts, price, da_commitment, blob_json, envelope_json, status, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'proving',?11)",
        params![
            batch_num as i64,
            fr_hex(old_root),
            fr_hex(new_root),
            deposit_count_cash as i64,
            deposit_count_coll as i64,
            batch_ts as i64,
            price.to_string(),
            fr_hex(da_commitment),
            blob_json,
            envelope_json,
            now(),
        ],
    )?;
    Ok(())
}

/// Remove a failed batch row so its batch_num (PRIMARY KEY) can be reused by
/// the rebuild — a lingering 'failed' row would make the next insert_batch
/// hit the UNIQUE constraint and wedge batching permanently.
pub fn delete_batch(conn: &Connection, batch_num: u64) -> DbResult<()> {
    conn.execute("DELETE FROM batches WHERE batch_num = ?1", [batch_num as i64])?;
    Ok(())
}

pub fn get_batch(conn: &Connection, batch_num: u64) -> DbResult<Option<BatchRow>> {
    conn.query_row(
        &format!("SELECT {BATCH_COLS} FROM batches WHERE batch_num = ?1"),
        [batch_num as i64],
        |r| batch_row(r),
    )
    .optional()
}

/// The single non-terminal batch, if any.
pub fn inflight_batch(conn: &Connection) -> DbResult<Option<BatchRow>> {
    conn.query_row(
        &format!(
            "SELECT {BATCH_COLS} FROM batches WHERE status NOT IN ('confirmed','failed')
             ORDER BY batch_num DESC LIMIT 1"
        ),
        [],
        |r| batch_row(r),
    )
    .optional()
}

pub fn batch_set_status(conn: &Connection, batch_num: u64, status: &str) -> DbResult<()> {
    conn.execute(
        "UPDATE batches SET status = ?1 WHERE batch_num = ?2",
        params![status, batch_num as i64],
    )?;
    Ok(())
}

pub fn batch_set_proof(conn: &Connection, batch_num: u64, proof: &[u8], envelope_json: &str) -> DbResult<()> {
    conn.execute(
        "UPDATE batches SET proof = ?1, envelope_json = ?2, status = 'proved' WHERE batch_num = ?3",
        params![proof, envelope_json, batch_num as i64],
    )?;
    Ok(())
}

pub fn batch_set_submitted(conn: &Connection, batch_num: u64, tx_hash: Option<&str>) -> DbResult<()> {
    conn.execute(
        "UPDATE batches SET status = 'submitted', tx_hash = ?1 WHERE batch_num = ?2",
        params![tx_hash, batch_num as i64],
    )?;
    Ok(())
}

pub fn batch_list(conn: &Connection, limit: usize) -> DbResult<Vec<BatchRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {BATCH_COLS} FROM batches ORDER BY batch_num DESC LIMIT ?1"
    ))?;
    let rows = stmt.query_map([limit as i64], |r| batch_row(r))?;
    rows.collect()
}

// ---------- history ----------

#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub batch_num: Option<u64>,
    pub kind: String,
    pub counterparty: Option<String>,
    pub asset: u32,
    pub amount: String,
    pub nonce: Option<u64>,
    pub status: String,
    pub ts: i64,
}

#[allow(clippy::too_many_arguments)]
pub fn insert_history(
    conn: &Connection,
    pk_x: &Fr,
    batch_num: u64,
    kind: &str,
    counterparty: Option<&str>,
    asset: u32,
    amount: u64,
    nonce: Option<u64>,
) -> DbResult<()> {
    conn.execute(
        "INSERT INTO history(pk_x, batch_num, kind, counterparty, asset, amount, nonce, ts)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            fr_hex(pk_x),
            batch_num as i64,
            kind,
            counterparty,
            asset as i64,
            amount.to_string(),
            nonce.map(|n| n as i64),
            now(),
        ],
    )?;
    Ok(())
}

pub fn history_for(conn: &Connection, pk_x: &Fr, limit: usize) -> DbResult<Vec<HistoryEntry>> {
    let mut out = Vec::new();
    // Confirmed history.
    let mut stmt = conn.prepare(
        "SELECT id, batch_num, kind, counterparty, asset, amount, nonce, ts FROM history
         WHERE pk_x = ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![fr_hex(pk_x), limit as i64], |r| {
        Ok(HistoryEntry {
            id: r.get(0)?,
            batch_num: Some(r.get::<_, i64>(1)? as u64),
            kind: r.get(2)?,
            counterparty: r.get(3)?,
            asset: r.get::<_, i64>(4)? as u32,
            amount: r.get(5)?,
            nonce: r.get::<_, Option<i64>>(6)?.map(|n| n as u64),
            status: "batched".into(),
            ts: r.get(7)?,
        })
    })?;
    for row in rows {
        out.push(row?);
    }
    // Live mempool entries (pending/batching/rejected) for this sender.
    let mut stmt = conn.prepare(
        "SELECT id, to_field, withdraw_dest, asset, amount, nonce, is_withdraw, status, reject_reason, received_at
         FROM mempool WHERE from_pk_x = ?1 AND status != 'included' ORDER BY id DESC",
    )?;
    let rows = stmt.query_map([fr_hex(pk_x)], |r| {
        let is_withdraw: bool = r.get::<_, i64>(6)? != 0;
        let to_field: String = r.get(1)?;
        let withdraw_dest: Option<String> = r.get(2)?;
        let status: String = r.get(7)?;
        Ok(HistoryEntry {
            id: r.get(0)?,
            batch_num: None,
            kind: if is_withdraw { "withdraw".into() } else { "transfer_out".into() },
            counterparty: if is_withdraw { withdraw_dest } else { Some(to_field) },
            asset: r.get::<_, i64>(3)? as u32,
            amount: r.get(4)?,
            nonce: Some(r.get::<_, i64>(5)? as u64),
            status: if status == "batching" { "pending".into() } else { status },
            ts: r.get(9)?,
        })
    })?;
    for row in rows {
        out.push(row?);
    }
    out.sort_by(|a, b| b.ts.cmp(&a.ts).then(b.id.cmp(&a.id)));
    Ok(out)
}

// ---------- intents / opens / positions (M2) ----------

/// One row shape shared by intents (single sig) and opens (both sigs).
#[derive(Debug, Clone, serde::Serialize)]
pub struct IntentRow {
    pub id: i64,
    pub initiator: String,
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
    pub sig: [String; 4],
    pub status: String,
    pub created_at: i64,
}

#[allow(clippy::too_many_arguments)]
pub fn insert_intent(conn: &Connection, r: &IntentRow) -> DbResult<i64> {
    conn.execute(
        "INSERT INTO intents(initiator, borrower_pk_x, borrower_pk_y, lender_pk_x, lender_pk_y,
                             cash, coll, rate_bps, haircut_bps, open_ts, maturity_ts,
                             borrower_nonce, lender_nonce, sig_r_x, sig_r_y, sig_s_lo, sig_s_hi,
                             created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        params![
            r.initiator, r.borrower_pk_x, r.borrower_pk_y, r.lender_pk_x, r.lender_pk_y,
            r.cash, r.coll, r.rate_bps as i64, r.haircut_bps as i64,
            r.open_ts as i64, r.maturity_ts as i64,
            r.borrower_nonce as i64, r.lender_nonce as i64,
            r.sig[0], r.sig[1], r.sig[2], r.sig[3], now(),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn intent_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<IntentRow> {
    Ok(IntentRow {
        id: r.get(0)?,
        initiator: r.get(1)?,
        borrower_pk_x: r.get(2)?,
        borrower_pk_y: r.get(3)?,
        lender_pk_x: r.get(4)?,
        lender_pk_y: r.get(5)?,
        cash: r.get(6)?,
        coll: r.get(7)?,
        rate_bps: r.get::<_, i64>(8)? as u32,
        haircut_bps: r.get::<_, i64>(9)? as u32,
        open_ts: r.get::<_, i64>(10)? as u64,
        maturity_ts: r.get::<_, i64>(11)? as u64,
        borrower_nonce: r.get::<_, i64>(12)? as u64,
        lender_nonce: r.get::<_, i64>(13)? as u64,
        sig: [r.get(14)?, r.get(15)?, r.get(16)?, r.get(17)?],
        status: r.get(18)?,
        created_at: r.get(19)?,
    })
}

const INTENT_COLS: &str = "id, initiator, borrower_pk_x, borrower_pk_y, lender_pk_x, lender_pk_y, \
                           cash, coll, rate_bps, haircut_bps, open_ts, maturity_ts, \
                           borrower_nonce, lender_nonce, sig_r_x, sig_r_y, sig_s_lo, sig_s_hi, \
                           status, created_at";

pub fn get_intent(conn: &Connection, id: i64) -> DbResult<Option<IntentRow>> {
    conn.query_row(
        &format!("SELECT {INTENT_COLS} FROM intents WHERE id = ?1"),
        [id],
        intent_row,
    )
    .optional()
}

/// Open intents where the given pk is the COUNTERPARTY (the party that has
/// not signed yet) — the privacy-filtered listing (PLAN.md 1.8 / 6.2).
pub fn intents_for_counterparty(conn: &Connection, pk_x: &str) -> DbResult<Vec<IntentRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {INTENT_COLS} FROM intents WHERE status = 'open' AND
           ((initiator = 'borrower' AND lender_pk_x = ?1) OR
            (initiator = 'lender' AND borrower_pk_x = ?1))
         ORDER BY id DESC"
    ))?;
    let rows = stmt.query_map([pk_x], intent_row)?;
    rows.collect()
}

/// Open intents CREATED by the given pk (so initiators can see their own).
pub fn intents_by_initiator(conn: &Connection, pk_x: &str) -> DbResult<Vec<IntentRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {INTENT_COLS} FROM intents WHERE status = 'open' AND
           ((initiator = 'borrower' AND borrower_pk_x = ?1) OR
            (initiator = 'lender' AND lender_pk_x = ?1))
         ORDER BY id DESC"
    ))?;
    let rows = stmt.query_map([pk_x], intent_row)?;
    rows.collect()
}

pub fn intent_set_status(conn: &Connection, id: i64, status: &str) -> DbResult<()> {
    conn.execute("UPDATE intents SET status = ?1 WHERE id = ?2", params![status, id])?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct OpenRow {
    pub id: i64,
    pub borrower_pk_x: Fr,
    pub borrower_pk_y: Fr,
    pub lender_pk_x: Fr,
    pub lender_pk_y: Fr,
    pub cash: u64,
    pub coll: u64,
    pub rate_bps: u32,
    pub haircut_bps: u32,
    pub open_ts: u64,
    pub maturity_ts: u64,
    pub borrower_nonce: u64,
    pub lender_nonce: u64,
    pub b_sig: [Fr; 4],
    pub l_sig: [Fr; 4],
    pub status: String,
}

#[allow(clippy::too_many_arguments)]
pub fn insert_open(
    conn: &Connection,
    intent_id: Option<i64>,
    row: &OpenRow,
) -> DbResult<i64> {
    conn.execute(
        "INSERT INTO opens(intent_id, borrower_pk_x, borrower_pk_y, lender_pk_x, lender_pk_y,
                           cash, coll, rate_bps, haircut_bps, open_ts, maturity_ts,
                           borrower_nonce, lender_nonce,
                           b_sig_r_x, b_sig_r_y, b_sig_s_lo, b_sig_s_hi,
                           l_sig_r_x, l_sig_r_y, l_sig_s_lo, l_sig_s_hi, received_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
        params![
            intent_id,
            fr_hex(&row.borrower_pk_x), fr_hex(&row.borrower_pk_y),
            fr_hex(&row.lender_pk_x), fr_hex(&row.lender_pk_y),
            row.cash.to_string(), row.coll.to_string(),
            row.rate_bps as i64, row.haircut_bps as i64,
            row.open_ts as i64, row.maturity_ts as i64,
            row.borrower_nonce as i64, row.lender_nonce as i64,
            fr_hex(&row.b_sig[0]), fr_hex(&row.b_sig[1]), fr_hex(&row.b_sig[2]), fr_hex(&row.b_sig[3]),
            fr_hex(&row.l_sig[0]), fr_hex(&row.l_sig[1]), fr_hex(&row.l_sig[2]), fr_hex(&row.l_sig[3]),
            now(),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn open_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<OpenRow> {
    let get_fr = |i: usize| -> rusqlite::Result<Fr> {
        let s: String = r.get(i)?;
        Ok(parse_fr(&s).expect("db fr corrupt"))
    };
    Ok(OpenRow {
        id: r.get(0)?,
        borrower_pk_x: get_fr(1)?,
        borrower_pk_y: get_fr(2)?,
        lender_pk_x: get_fr(3)?,
        lender_pk_y: get_fr(4)?,
        cash: r.get::<_, String>(5)?.parse().expect("db cash corrupt"),
        coll: r.get::<_, String>(6)?.parse().expect("db coll corrupt"),
        rate_bps: r.get::<_, i64>(7)? as u32,
        haircut_bps: r.get::<_, i64>(8)? as u32,
        open_ts: r.get::<_, i64>(9)? as u64,
        maturity_ts: r.get::<_, i64>(10)? as u64,
        borrower_nonce: r.get::<_, i64>(11)? as u64,
        lender_nonce: r.get::<_, i64>(12)? as u64,
        b_sig: [get_fr(13)?, get_fr(14)?, get_fr(15)?, get_fr(16)?],
        l_sig: [get_fr(17)?, get_fr(18)?, get_fr(19)?, get_fr(20)?],
        status: r.get(21)?,
    })
}

const OPEN_COLS: &str = "id, borrower_pk_x, borrower_pk_y, lender_pk_x, lender_pk_y, \
                         cash, coll, rate_bps, haircut_bps, open_ts, maturity_ts, \
                         borrower_nonce, lender_nonce, \
                         b_sig_r_x, b_sig_r_y, b_sig_s_lo, b_sig_s_hi, \
                         l_sig_r_x, l_sig_r_y, l_sig_s_lo, l_sig_s_hi, status";

pub fn opens_pending(conn: &Connection, limit: usize) -> DbResult<Vec<OpenRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {OPEN_COLS} FROM opens WHERE status = 'pending' ORDER BY id LIMIT ?1"
    ))?;
    let rows = stmt.query_map([limit as i64], open_row)?;
    rows.collect()
}

pub fn opens_pending_for(conn: &Connection, pk_x: &Fr) -> DbResult<u64> {
    conn.query_row(
        "SELECT COUNT(*) FROM opens WHERE status IN ('pending','batching')
           AND (borrower_pk_x = ?1 OR lender_pk_x = ?1)",
        [fr_hex(pk_x)],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )
}

pub fn opens_count_pending(conn: &Connection) -> DbResult<u64> {
    conn.query_row("SELECT COUNT(*) FROM opens WHERE status = 'pending'", [], |r| {
        r.get::<_, i64>(0).map(|v| v as u64)
    })
}

pub fn opens_oldest_pending_age(conn: &Connection) -> DbResult<Option<i64>> {
    conn.query_row(
        "SELECT MIN(received_at) FROM opens WHERE status = 'pending'",
        [],
        |r| r.get::<_, Option<i64>>(0),
    )
    .map(|min| min.map(|m| now() - m))
}

pub fn opens_set_status(
    conn: &Connection,
    ids: &[i64],
    status: &str,
    batch_num: Option<u64>,
    reason: Option<&str>,
) -> DbResult<()> {
    for id in ids {
        conn.execute(
            "UPDATE opens SET status = ?1, batch_num = ?2, reject_reason = ?3 WHERE id = ?4",
            params![status, batch_num.map(|b| b as i64), reason, id],
        )?;
    }
    Ok(())
}

// -- positions (confirmed L2 state, mirrors harness PosTree) --

#[derive(Debug, Clone)]
pub struct PositionRow {
    pub slot: u32,
    pub borrower_pk_x: Fr,
    pub lender_pk_x: Fr,
    pub cash: u64,
    pub coll: u64,
    pub rate_bps: u32,
    pub haircut_bps: u32,
    pub open_ts: u64,
    pub maturity_ts: u64,
}

pub fn upsert_position(conn: &Connection, p: &PositionRow, batch_num: u64) -> DbResult<()> {
    conn.execute(
        "INSERT INTO positions(slot, borrower_pk_x, lender_pk_x, cash, coll, rate_bps,
                               haircut_bps, open_ts, maturity_ts, opened_batch)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(slot) DO UPDATE SET borrower_pk_x = excluded.borrower_pk_x,
           lender_pk_x = excluded.lender_pk_x, cash = excluded.cash, coll = excluded.coll,
           rate_bps = excluded.rate_bps, haircut_bps = excluded.haircut_bps,
           open_ts = excluded.open_ts, maturity_ts = excluded.maturity_ts,
           opened_batch = excluded.opened_batch",
        params![
            p.slot as i64,
            fr_hex(&p.borrower_pk_x),
            fr_hex(&p.lender_pk_x),
            p.cash.to_string(),
            p.coll.to_string(),
            p.rate_bps as i64,
            p.haircut_bps as i64,
            p.open_ts as i64,
            p.maturity_ts as i64,
            batch_num as i64,
        ],
    )?;
    Ok(())
}

pub fn delete_position(conn: &Connection, slot: u32) -> DbResult<()> {
    conn.execute("DELETE FROM positions WHERE slot = ?1", [slot as i64])?;
    Ok(())
}

pub fn load_positions(conn: &Connection) -> DbResult<Vec<PositionRow>> {
    let mut stmt = conn.prepare(
        "SELECT slot, borrower_pk_x, lender_pk_x, cash, coll, rate_bps, haircut_bps,
                open_ts, maturity_ts FROM positions",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(PositionRow {
            slot: r.get::<_, i64>(0)? as u32,
            borrower_pk_x: parse_fr(&r.get::<_, String>(1)?).expect("db pk corrupt"),
            lender_pk_x: parse_fr(&r.get::<_, String>(2)?).expect("db pk corrupt"),
            cash: r.get::<_, String>(3)?.parse().expect("db cash corrupt"),
            coll: r.get::<_, String>(4)?.parse().expect("db coll corrupt"),
            rate_bps: r.get::<_, i64>(5)? as u32,
            haircut_bps: r.get::<_, i64>(6)? as u32,
            open_ts: r.get::<_, i64>(7)? as u64,
            maturity_ts: r.get::<_, i64>(8)? as u64,
        })
    })?;
    rows.collect()
}

// ---------- closes / liqs (M3) ----------

#[derive(Debug, Clone)]
pub struct CloseRow {
    pub id: i64,
    pub pos_index: u32,
    pub borrower_pk_x: Fr,
    pub borrower_pk_y: Fr,
    pub borrower_nonce: u64,
    pub sig: [Fr; 4],
}

pub fn insert_close(conn: &Connection, row: &CloseRow) -> DbResult<i64> {
    conn.execute(
        "INSERT INTO closes(pos_index, borrower_pk_x, borrower_pk_y, borrower_nonce,
                            sig_r_x, sig_r_y, sig_s_lo, sig_s_hi, received_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            row.pos_index as i64,
            fr_hex(&row.borrower_pk_x),
            fr_hex(&row.borrower_pk_y),
            row.borrower_nonce as i64,
            fr_hex(&row.sig[0]), fr_hex(&row.sig[1]), fr_hex(&row.sig[2]), fr_hex(&row.sig[3]),
            now(),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn closes_pending(conn: &Connection, limit: usize) -> DbResult<Vec<CloseRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, pos_index, borrower_pk_x, borrower_pk_y, borrower_nonce,
                sig_r_x, sig_r_y, sig_s_lo, sig_s_hi
         FROM closes WHERE status = 'pending' ORDER BY id LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit as i64], |r| {
        let get_fr = |i: usize| -> rusqlite::Result<Fr> {
            let s: String = r.get(i)?;
            Ok(parse_fr(&s).expect("db fr corrupt"))
        };
        Ok(CloseRow {
            id: r.get(0)?,
            pos_index: r.get::<_, i64>(1)? as u32,
            borrower_pk_x: get_fr(2)?,
            borrower_pk_y: get_fr(3)?,
            borrower_nonce: r.get::<_, i64>(4)? as u64,
            sig: [get_fr(5)?, get_fr(6)?, get_fr(7)?, get_fr(8)?],
        })
    })?;
    rows.collect()
}

pub fn closes_pending_for(conn: &Connection, pk_x: &Fr) -> DbResult<u64> {
    conn.query_row(
        "SELECT COUNT(*) FROM closes WHERE status IN ('pending','batching') AND borrower_pk_x = ?1",
        [fr_hex(pk_x)],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )
}

pub fn closes_count_pending(conn: &Connection) -> DbResult<u64> {
    conn.query_row("SELECT COUNT(*) FROM closes WHERE status = 'pending'", [], |r| {
        r.get::<_, i64>(0).map(|v| v as u64)
    })
}

pub fn closes_oldest_pending_age(conn: &Connection) -> DbResult<Option<i64>> {
    conn.query_row("SELECT MIN(received_at) FROM closes WHERE status = 'pending'", [], |r| {
        r.get::<_, Option<i64>>(0)
    })
    .map(|min| min.map(|m| now() - m))
}

pub fn closes_set_status(
    conn: &Connection,
    ids: &[i64],
    status: &str,
    batch_num: Option<u64>,
    reason: Option<&str>,
) -> DbResult<()> {
    for id in ids {
        conn.execute(
            "UPDATE closes SET status = ?1, batch_num = ?2, reject_reason = ?3 WHERE id = ?4",
            params![status, batch_num.map(|b| b as i64), reason, id],
        )?;
    }
    Ok(())
}

/// Enqueue a watcher-detected default/liquidation; idempotent per slot.
pub fn insert_liq(conn: &Connection, pos_index: u32, is_liquidation: bool) -> DbResult<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO liqs(pos_index, is_liquidation, created_at) VALUES (?1,?2,?3)",
        params![pos_index as i64, is_liquidation as i64, now()],
    )?;
    Ok(n > 0)
}

#[derive(Debug, Clone)]
pub struct LiqRow {
    pub pos_index: u32,
    pub is_liquidation: bool,
}

pub fn liqs_pending(conn: &Connection, limit: usize) -> DbResult<Vec<LiqRow>> {
    let mut stmt = conn.prepare(
        "SELECT pos_index, is_liquidation FROM liqs WHERE status = 'pending' ORDER BY pos_index LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit as i64], |r| {
        Ok(LiqRow {
            pos_index: r.get::<_, i64>(0)? as u32,
            is_liquidation: r.get::<_, i64>(1)? != 0,
        })
    })?;
    rows.collect()
}

pub fn liqs_count_pending(conn: &Connection) -> DbResult<u64> {
    conn.query_row("SELECT COUNT(*) FROM liqs WHERE status = 'pending'", [], |r| {
        r.get::<_, i64>(0).map(|v| v as u64)
    })
}

pub fn liqs_set_status(
    conn: &Connection,
    slots: &[u32],
    status: &str,
    batch_num: Option<u64>,
    reason: Option<&str>,
) -> DbResult<()> {
    for slot in slots {
        conn.execute(
            "UPDATE liqs SET status = ?1, batch_num = ?2, reject_reason = ?3 WHERE pos_index = ?4",
            params![status, batch_num.map(|b| b as i64), reason, *slot as i64],
        )?;
    }
    Ok(())
}

/// Drop a rejected/settled liq row so a future breach can re-enqueue the slot.
pub fn delete_liq(conn: &Connection, pos_index: u32) -> DbResult<()> {
    conn.execute("DELETE FROM liqs WHERE pos_index = ?1", [pos_index as i64])?;
    Ok(())
}
