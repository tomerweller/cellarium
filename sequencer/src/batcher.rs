//! Batch pipeline driver. Ticks on an interval; when the engine says a batch
//! is ready it runs the blocking prove (bb) off the async runtime, then
//! submits and confirms. The engine owns all state; this loop only
//! orchestrates the irreversible steps and hands results back.
//!
//! State machine (per batch row, owned by the engine):
//!   building -> proving -> proved -> submitting -> submitted -> confirmed
//!                      \-> failed (inputs requeued)

use crate::config::Config;
use crate::engine::{ApiError, BatchJob, Command};
use crate::hexutil::fr_hex;
use crate::stellar::StellarClient;
use harness::poseidon::Fr;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tokio::sync::oneshot;

/// A proof binds its claimed batch_ts, and the contract only accepts
/// claimed >= ledger - 60s. Once an inflight batch's ts lags further than
/// this, resubmission can NEVER land it — fail + requeue is the only way
/// forward. 90s = the 60s window plus submission/ledger slack.
const TS_WINDOW_LAPSED_SECS: u64 = 90;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn run(
    engine: mpsc::Sender<Command>,
    client: Arc<dyn StellarClient>,
    cfg: Config,
) {
    // Resume any batch left mid-pipeline by a crash before the normal loop.
    if let Some((batch_num, status, batch_ts, new_root)) = inflight(&engine).await {
        tracing::info!(batch_num, %status, "resuming inflight batch on boot");
        resume(&engine, &client, &cfg, batch_num, &status, batch_ts, new_root).await;
    }

    let mut interval = tokio::time::interval(Duration::from_secs(cfg.tick_secs));
    loop {
        interval.tick().await;

        // Self-heal a wedged inflight batch (e.g. submission kept failing
        // until its timestamp window lapsed): confirm it if it actually
        // landed, otherwise fail + requeue so a fresh batch can build.
        if let Some((batch_num, status, batch_ts, new_root)) = inflight(&engine).await {
            if matches!(status.as_str(), "proved" | "submitting" | "submitted")
                && now_secs().saturating_sub(batch_ts) > TS_WINDOW_LAPSED_SECS
            {
                match landed(&client, batch_num, &new_root).await {
                    Some(Landed::Ours) => {
                        let _ = ask(&engine, |r| Command::ConfirmBatch(batch_num, r)).await;
                    }
                    Some(Landed::Foreign(chain_root)) => {
                        halt_on_foreign_root(batch_num, &new_root, &chain_root);
                    }
                    Some(Landed::No) => {
                        tracing::warn!(
                            batch_num,
                            batch_ts,
                            "inflight batch's timestamp window lapsed; rebuilding"
                        );
                        fail(&engine, batch_num, "timestamp window lapsed").await;
                    }
                    None => {} // chain unreachable; try again next tick
                }
            }
        }

        // Fetch the oracle price for this tick: the 7th public input must be
        // exactly what the contract will read at submission.
        let c = client.clone();
        let (price, price_ts) = match tokio::task::spawn_blocking(move || c.oracle_price()).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::warn!(%e, "oracle price fetch failed; skipping tick");
                continue;
            }
            Err(e) => {
                tracing::error!(%e, "oracle price task panicked");
                continue;
            }
        };
        // Mock-oracle heartbeat (PLAN §3: every batch needs a fresh price;
        // the operator controls the mock oracle). Re-stamp the SAME value
        // well before the contract's 5-minute staleness bound so proving/
        // submission never races it. Requires ORACLE_ADMIN_SECRET.
        if cfg.oracle_admin_secret.is_some() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now.saturating_sub(price_ts) > 150 {
                let c = client.clone();
                match tokio::task::spawn_blocking(move || c.refresh_oracle_price(price)).await {
                    Ok(Ok(())) => tracing::info!(price, "oracle heartbeat: price re-stamped"),
                    Ok(Err(e)) => tracing::warn!(%e, "oracle heartbeat failed"),
                    Err(e) => tracing::error!(%e, "oracle heartbeat task panicked"),
                }
            }
        }
        match try_build(&engine, price).await {
            Ok(Some(job)) => {
                run_pipeline(&engine, &client, &cfg, job).await;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(%e, "try_build_batch failed"),
        }
    }
}

async fn run_pipeline(
    engine: &mpsc::Sender<Command>,
    client: &Arc<dyn StellarClient>,
    cfg: &Config,
    job: BatchJob,
) {
    let batch_num = job.batch_num;

    // --- prove (blocking; off the async runtime) ---
    let pkg = cfg.circuit_pkg.clone();
    let toml = job.prover_toml.clone();
    let proof_result = tokio::task::spawn_blocking(move || {
        std::env::set_var("STAGE_FIXTURES", "0");
        let out_dir = harness::prover::prove(&pkg, &toml)?;
        let proof = std::fs::read(out_dir.join("proof"))?;
        let public_inputs = std::fs::read(out_dir.join("public_inputs"))?;
        Ok::<_, std::io::Error>((proof, public_inputs))
    })
    .await;

    let (proof, public_inputs) = match proof_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            fail(engine, batch_num, &format!("prove failed: {e}")).await;
            return;
        }
        Err(e) => {
            fail(engine, batch_num, &format!("prove task panicked: {e}")).await;
            return;
        }
    };

    // --- validate + record proof; check bb PIs equal the built ones ---
    let envelope_json = match record_proof(engine, batch_num, proof, public_inputs).await {
        Ok(env) => env,
        Err(e) => {
            fail(engine, batch_num, &format!("record proof failed: {e}")).await;
            return;
        }
    };

    submit_and_confirm(engine, client, cfg, batch_num, job.new_root, envelope_json).await;
}

async fn submit_and_confirm(
    engine: &mpsc::Sender<Command>,
    client: &Arc<dyn StellarClient>,
    cfg: &Config,
    batch_num: u64,
    new_root: Fr,
    envelope_json: String,
) {
    // Mark submitting BEFORE the CLI call so a crash mid-send is detectable.
    if let Err(e) = ask(engine, |r| Command::MarkSubmitting(batch_num, r)).await {
        tracing::error!(batch_num, %e, "mark submitting failed");
        return;
    }

    let c = client.clone();
    let env = envelope_json.clone();
    let submit = tokio::task::spawn_blocking(move || c.submit_batch(&env)).await;
    match submit {
        Ok(Ok(())) => {
            let _ = ask(engine, |r| Command::MarkSubmitted(batch_num, None, r)).await;
        }
        Ok(Err(e)) => {
            // Submission may or may not have landed; confirm by polling root.
            tracing::warn!(batch_num, %e, "submit_batch returned error; verifying via root");
        }
        Err(e) => tracing::error!(batch_num, %e, "submit task panicked"),
    }

    confirm(engine, client, cfg, batch_num, new_root).await;
}

/// Whether the chain has advanced to this batch, and if so whether the root
/// it landed on is OURS. `None` means the chain was unreachable this attempt.
enum Landed {
    Ours,
    /// Counter advanced but the root is not this batch's new_root: someone
    /// else moved the state (issue #1 H2).
    Foreign(Fr),
    No,
}

async fn landed(
    client: &Arc<dyn StellarClient>,
    batch_num: u64,
    new_root: &Fr,
) -> Option<Landed> {
    let c = client.clone();
    let chain_bn = tokio::task::spawn_blocking(move || c.batch_num()).await.ok()?.ok()?;
    if chain_bn < batch_num {
        return Some(Landed::No);
    }
    let c = client.clone();
    let chain_root = tokio::task::spawn_blocking(move || c.root()).await.ok()?.ok()?;
    if chain_root == *new_root {
        Some(Landed::Ours)
    } else {
        Some(Landed::Foreign(chain_root))
    }
}

/// A foreign batch advanced the chain: confirming ours would diverge local
/// state from the chain, and every future proof (bound to our stale
/// old_root) would fail verification anyway. Halt loudly; boot
/// reconciliation refuses to run until the operator sorts out who else is
/// submitting (should be impossible with the operator pinned on-chain).
fn halt_on_foreign_root(batch_num: u64, new_root: &Fr, chain_root: &Fr) -> ! {
    tracing::error!(
        batch_num,
        expected_root = %fr_hex(new_root),
        chain_root = %fr_hex(chain_root),
        "chain advanced to a root we did not produce; refusing to confirm — halting"
    );
    std::process::exit(1);
}

/// Poll the chain until its ROOT equals this batch's new_root (the counter
/// alone is not proof our batch landed — issue #1 H2), then tell the engine
/// to apply the batch. Bounded retries; on timeout the batch stays
/// 'submitted' and boot recovery re-checks it.
async fn confirm(
    engine: &mpsc::Sender<Command>,
    client: &Arc<dyn StellarClient>,
    cfg: &Config,
    batch_num: u64,
    new_root: Fr,
) {
    for attempt in 0..30u32 {
        tokio::time::sleep(Duration::from_secs(cfg.tick_secs)).await;
        match landed(client, batch_num, &new_root).await {
            Some(Landed::Ours) => {
                match ask(engine, |r| Command::ConfirmBatch(batch_num, r)).await {
                    Ok(()) => tracing::info!(batch_num, "batch confirmed on chain"),
                    Err(e) => tracing::error!(batch_num, %e, "confirm apply failed"),
                }
                return;
            }
            Some(Landed::Foreign(chain_root)) => {
                halt_on_foreign_root(batch_num, &new_root, &chain_root);
            }
            Some(Landed::No) | None => {
                tracing::debug!(batch_num, attempt, "awaiting confirmation");
            }
        }
    }
    tracing::warn!(batch_num, "confirmation timed out; boot recovery will re-check");
}

async fn resume(
    engine: &mpsc::Sender<Command>,
    client: &Arc<dyn StellarClient>,
    cfg: &Config,
    batch_num: u64,
    status: &str,
    batch_ts: u64,
    new_root: Fr,
) {
    match status {
        // Proof exists; re-submitting is safe (proof binds old_root, a
        // double-land fails verification) — go straight to submit+confirm.
        // EXCEPT when the proof's timestamp window has lapsed: it can never
        // land, so check whether it already did and otherwise rebuild.
        "proved" | "submitting" | "submitted"
            if now_secs().saturating_sub(batch_ts) > TS_WINDOW_LAPSED_SECS =>
        {
            match landed(client, batch_num, &new_root).await {
                Some(Landed::Ours) => {
                    let _ = ask(engine, |r| Command::ConfirmBatch(batch_num, r)).await;
                }
                Some(Landed::Foreign(chain_root)) => {
                    halt_on_foreign_root(batch_num, &new_root, &chain_root);
                }
                Some(Landed::No) | None => {
                    tracing::warn!(batch_num, batch_ts, "resume: timestamp window lapsed; rebuilding");
                    fail(engine, batch_num, "timestamp window lapsed").await;
                }
            }
        }
        "proved" | "submitting" | "submitted" => {
            let envelope = match ask(engine, |r| Command::MarkSubmitting(batch_num, r)).await {
                Ok(env) => env,
                Err(e) => {
                    tracing::error!(batch_num, %e, "resume mark submitting failed");
                    return;
                }
            };
            submit_and_confirm(engine, client, cfg, batch_num, new_root, envelope).await;
        }
        other => {
            // 'proving' and anything else pre-proof: the prove artifacts are
            // gone; fail + requeue (boot reconcile may already have done this).
            tracing::warn!(batch_num, status = other, "resume: failing pre-proof batch");
            fail(engine, batch_num, "interrupted before proof").await;
        }
    }
}

// ---- engine command helpers ----

async fn inflight(engine: &mpsc::Sender<Command>) -> Option<(u64, String, u64, Fr)> {
    let (tx, rx) = oneshot::channel();
    engine.send(Command::GetInflight(tx)).ok()?;
    rx.await.ok().flatten()
}

async fn try_build(engine: &mpsc::Sender<Command>, price: u64) -> Result<Option<BatchJob>, ApiError> {
    ask_r(engine, |r| Command::TryBuildBatch(price, r)).await
}

async fn record_proof(
    engine: &mpsc::Sender<Command>,
    batch_num: u64,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<String, ApiError> {
    let (tx, rx) = oneshot::channel();
    engine
        .send(Command::RecordProof { batch_num, proof, public_inputs, reply: tx })
        .map_err(|_| ApiError::Internal("engine offline".into()))?;
    rx.await.map_err(|_| ApiError::Internal("engine dropped reply".into()))?
}

async fn fail(engine: &mpsc::Sender<Command>, batch_num: u64, reason: &str) {
    let _ = ask(engine, |r| Command::FailBatch(batch_num, reason.to_string(), r)).await;
}

async fn ask<T, F>(engine: &mpsc::Sender<Command>, build: F) -> Result<T, ApiError>
where
    F: FnOnce(oneshot::Sender<Result<T, ApiError>>) -> Command,
{
    let (tx, rx) = oneshot::channel();
    engine
        .send(build(tx))
        .map_err(|_| ApiError::Internal("engine offline".into()))?;
    rx.await.map_err(|_| ApiError::Internal("engine dropped reply".into()))?
}

async fn ask_r<T, F>(engine: &mpsc::Sender<Command>, build: F) -> Result<T, ApiError>
where
    F: FnOnce(oneshot::Sender<Result<T, ApiError>>) -> Command,
{
    ask(engine, build).await
}
