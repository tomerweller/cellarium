mod api;
mod batcher;
mod config;
mod db;
mod engine;
mod hexutil;
mod stellar;
mod watcher;

use config::Config;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sequencer=info,tower_http=warn".into()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // One-shot subcommands (need no config/env), used by the bootstrap
    // scripts and the container's auto-bootstrap entrypoint.
    match std::env::args().nth(1).as_deref() {
        // Combined genesis: P2([empty account root, empty position root]).
        Some("genesis-root") => {
            let hasher = harness::poseidon::Hasher::new();
            let state = harness::repo::L2State::new();
            println!("{}", hexutil::fr_hex(&state.state_root(&hasher)));
            return Ok(());
        }
        // The SQLite schema version this binary requires. Part of the
        // deployment compatibility fingerprint: a bump means the on-volume
        // DB must be reset (db::migrate refuses to open older versions).
        Some("schema-version") => {
            println!("{}", db::SCHEMA_VERSION);
            return Ok(());
        }
        _ => {}
    }

    let cfg = Config::from_env()?;
    tracing::info!(contract = %cfg.contract_id, circuit = %cfg.circuit_pkg, "starting Cellarium sequencer");

    let conn = db::open(&cfg.db_path).map_err(|e| format!("db open: {e}"))?;

    // Chain client + boot reconciliation (contract is the source of truth).
    let client: Arc<dyn stellar::StellarClient> =
        Arc::new(stellar::CliClient::new(&cfg).map_err(|e| format!("stellar client: {e}"))?);
    let chain_root = client.root().map_err(|e| format!("read root: {e}"))?;
    let chain_batch_num = client.batch_num().map_err(|e| format!("read batch_num: {e}"))?;
    let dep_cursors = [
        // Cursors persist in meta; default to 0 on a fresh DB.
        db::meta_get_u64(&conn, "dep_cursor_0").map_err(|e| e.to_string())?,
        db::meta_get_u64(&conn, "dep_cursor_1").map_err(|e| e.to_string())?,
    ];

    let boot = engine::load_and_reconcile(&conn, &chain_root, chain_batch_num)?;
    tracing::info!(
        chain_batch_num,
        chain_synced = boot.chain_synced,
        "reconciled local state against chain"
    );

    let engine = engine::spawn(cfg.clone(), conn, boot.state, boot.chain_synced);

    // Background tasks: deposit watcher + batch pipeline. Their handles are
    // supervised below — silent task death must not leave a healthy-looking
    // HTTP server running (issue #10).
    let health = Arc::new(api::Health::default());
    let watcher_task = tokio::spawn(watcher::run(
        engine.clone(),
        client.clone(),
        cfg.tick_secs,
        dep_cursors,
        health.clone(),
    ));
    let batcher_task =
        tokio::spawn(batcher::run(engine.clone(), client.clone(), cfg.clone(), health.clone()));

    // HTTP server.
    let state = api::AppState { engine, cfg: cfg.clone(), health };
    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr)
        .await
        .map_err(|e| format!("bind {}: {e}", cfg.listen_addr))?;
    tracing::info!(addr = %cfg.listen_addr, "listening");
    // ConnectInfo gives the rate limiter a spoof-proof fallback identity
    // when no trusted proxy header is present (issue #20).
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    // Supervise: the watcher and batcher loop forever, so their future
    // resolving means the task panicked or was aborted. Exit non-zero and
    // let the platform restart the whole process — restarting only the task
    // would hide whatever corrupted it.
    tokio::select! {
        res = server => res.map_err(|e| format!("serve: {e}")),
        res = watcher_task => Err(format!("watcher task exited unexpectedly: {res:?}")),
        res = batcher_task => Err(format!("batcher task exited unexpectedly: {res:?}")),
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
