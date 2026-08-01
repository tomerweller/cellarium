//! Deposit watcher: polls the contract's per-asset FIFO queues (dep_tail + a
//! local cursor per asset) rather than getEvents, which has an RPC retention
//! window a downed sequencer could miss. Queue seqs are exactly-once by
//! construction; the engine dedupes via INSERT OR IGNORE, so a restart with a
//! stale cursor is harmless.

use crate::engine::Command;
use crate::stellar::StellarClient;
use harness::poseidon::Fr;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tokio::sync::oneshot;

pub async fn run(
    engine: mpsc::Sender<Command>,
    client: Arc<dyn StellarClient>,
    tick_secs: u64,
    mut cursors: [u64; 2],
) {
    let mut interval = tokio::time::interval(Duration::from_secs(tick_secs));
    loop {
        interval.tick().await;

        // Refund detection (issue #1 M5): the contract's refund_deposit
        // advances the queue head without a batch. Report the heads so the
        // engine can retire still-'pending' rows the chain already refunded.
        let mut heads = [0u64; 2];
        let mut heads_ok = true;
        for asset in 0..2u32 {
            let c = client.clone();
            match tokio::task::spawn_blocking(move || c.dep_head(asset)).await {
                Ok(Ok(h)) => heads[asset as usize] = h,
                Ok(Err(e)) => {
                    tracing::warn!(asset, %e, "dep_head poll failed");
                    heads_ok = false;
                }
                Err(e) => {
                    tracing::error!(asset, %e, "dep_head task panicked");
                    heads_ok = false;
                }
            }
        }
        if heads_ok {
            let (tx, rx) = oneshot::channel();
            if engine.send(Command::ObservedQueueHeads(heads, tx)).is_err() {
                return;
            }
            let _ = rx.await;
        }

        for asset in 0..2u32 {
            let cursor = cursors[asset as usize];
            let c = client.clone();
            let tail = match tokio::task::spawn_blocking(move || c.dep_tail(asset)).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    tracing::warn!(asset, %e, "dep_tail poll failed");
                    continue;
                }
                Err(e) => {
                    tracing::error!(asset, %e, "dep_tail task panicked");
                    continue;
                }
            };
            if tail <= cursor {
                continue;
            }

            let mut observed: Vec<(u32, u64, Fr, u64)> = Vec::new();
            for seq in cursor..tail {
                let c = client.clone();
                match tokio::task::spawn_blocking(move || c.get_pending_deposit(asset, seq)).await {
                    Ok(Ok((pk_x, amount))) => observed.push((asset, seq, pk_x, amount)),
                    Ok(Err(e)) => {
                        tracing::warn!(asset, seq, %e, "get_pending_deposit failed; will retry next tick");
                        break;
                    }
                    Err(e) => {
                        tracing::error!(asset, seq, %e, "get_pending_deposit task panicked");
                        break;
                    }
                }
            }

            if observed.is_empty() {
                continue;
            }
            let advance_to = cursor + observed.len() as u64;
            if report(&engine, observed).await {
                cursors[asset as usize] = advance_to;
            }
        }
    }
}

/// Report observed deposits to the engine, awaiting its ack.
async fn report(engine: &mpsc::Sender<Command>, deposits: Vec<(u32, u64, Fr, u64)>) -> bool {
    let (tx, rx) = oneshot::channel();
    if engine.send(Command::ObservedDeposits(deposits, tx)).is_err() {
        return false;
    }
    matches!(rx.await, Ok(Ok(())))
}
