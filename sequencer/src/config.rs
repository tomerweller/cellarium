use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub rpc_url: String,
    pub network_passphrase: String,
    pub contract_id: String,
    /// Cash (XLM) custody token contract.
    pub token_id: String,
    /// Collateral (tUST) custody token contract.
    pub tust_id: String,
    /// S... secret key of the sequencer's Stellar account (pays batch fees).
    pub sequencer_secret: String,
    /// G... public address (optional; derived from an identity if absent).
    pub sequencer_address: Option<String>,
    pub db_path: PathBuf,
    pub listen_addr: String,
    /// Max seconds the oldest pending tx/deposit waits before a batch fires.
    pub batch_max_wait_secs: u64,
    /// Watcher/batcher poll interval.
    pub tick_secs: u64,
    /// Hard deadline for read/simulate/key CLI subprocesses (issue #11).
    pub cli_timeout_secs: u64,
    /// Hard deadline for transaction-sending CLI subprocesses (sign+send+confirm).
    pub submit_timeout_secs: u64,
    /// Circuit package to prove (fixed shape D=4/O=2/T=4 for batch_repo).
    pub circuit_pkg: String,
    pub deposit_slots: usize,
    pub close_slots: usize,
    pub liq_slots: usize,
    pub open_slots: usize,
    pub tx_slots: usize,
    /// Mock price oracle contract (read every build; PLAN.md 1.5/1.6).
    pub oracle_id: String,
    /// Optional oracle admin secret: when set, the batcher re-stamps the
    /// current price whenever it approaches the contract's 5-minute
    /// staleness bound (the mock oracle needs a heartbeat; PLAN.md §3).
    pub oracle_admin_secret: Option<String>,
}

fn var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing required env var {name}"))
}

fn var_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let circuit_pkg = var_or("CIRCUIT_PKG", "batch_repo");
        let (deposit_slots, close_slots, liq_slots, open_slots, tx_slots) =
            match circuit_pkg.as_str() {
                "batch_repo" => (4, 2, 2, 2, 4),
                other => return Err(format!("unknown CIRCUIT_PKG {other}")),
            };
        Ok(Config {
            rpc_url: var_or("RPC_URL", "https://soroban-testnet.stellar.org"),
            network_passphrase: var_or("NETWORK_PASSPHRASE", "Test SDF Network ; September 2015"),
            contract_id: var("CONTRACT_ID")?,
            token_id: var("TOKEN_ID")?,
            tust_id: var("TUST_ID")?,
            sequencer_secret: var("SEQUENCER_SECRET")?,
            sequencer_address: std::env::var("SEQUENCER_ADDRESS").ok(),
            db_path: PathBuf::from(var_or("DB_PATH", "sequencer.db")),
            listen_addr: var_or("LISTEN_ADDR", "0.0.0.0:8080"),
            batch_max_wait_secs: var_or("BATCH_MAX_WAIT_SECS", "30").parse().map_err(|_| "bad BATCH_MAX_WAIT_SECS")?,
            tick_secs: var_or("TICK_SECS", "5").parse().map_err(|_| "bad TICK_SECS")?,
            cli_timeout_secs: var_or("CLI_TIMEOUT_SECS", "30").parse().map_err(|_| "bad CLI_TIMEOUT_SECS")?,
            submit_timeout_secs: var_or("SUBMIT_TIMEOUT_SECS", "180").parse().map_err(|_| "bad SUBMIT_TIMEOUT_SECS")?,
            circuit_pkg,
            deposit_slots,
            close_slots,
            liq_slots,
            open_slots,
            tx_slots,
            oracle_id: var("ORACLE_ID")?,
            oracle_admin_secret: std::env::var("ORACLE_ADMIN_SECRET").ok().filter(|s| !s.is_empty()),
        })
    }
}
