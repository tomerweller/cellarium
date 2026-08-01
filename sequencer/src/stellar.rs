//! Chain access via the stellar CLI (proven pattern from scripts/e2e_local.sh)
//! plus raw JSON-RPC for transaction polling. The trait isolates a future
//! swap to a native RPC client.

use crate::hexutil::{parse_fr, HexError};
use harness::poseidon::Fr;
use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Total subprocess deadline expirations since boot (readiness/diagnostics).
pub static TIMEOUT_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("cli: {0}")]
    Cli(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout: {what} exceeded {secs}s")]
    Timeout { what: String, secs: u64 },
}

/// Run `cmd` to completion with a hard deadline. On expiry the child is
/// killed and reaped — a hung CLI/RPC subprocess must never wedge the
/// watcher, batcher, or boot sequence (issue #11).
fn run_with_timeout(mut cmd: Command, what: &str, timeout: Duration) -> Result<Output, ChainError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    // Drain pipes on threads so a chatty child can't block on a full pipe
    // while we poll for exit.
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
                return Err(ChainError::Timeout {
                    what: what.to_string(),
                    secs: timeout.as_secs(),
                });
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

impl From<HexError> for ChainError {
    fn from(e: HexError) -> Self {
        ChainError::Parse(format!("{e:?}"))
    }
}

pub trait StellarClient: Send + Sync {
    fn root(&self) -> Result<Fr, ChainError>;
    fn batch_num(&self) -> Result<u64, ChainError>;
    /// Current oracle price (XLM-per-tUST x 1e7) and its set-timestamp;
    /// the price is bound as the 7th public input, so the witness must use
    /// exactly what the contract will read.
    fn oracle_price(&self) -> Result<(u64, u64), ChainError>;
    /// Re-stamp the oracle with `price` (same value, fresh ledger timestamp).
    /// Requires the oracle admin identity; no-op capability check is the
    /// caller's job.
    fn refresh_oracle_price(&self, price: u64) -> Result<(), ChainError>;
    fn dep_tail(&self, asset: u32) -> Result<u64, ChainError>;
    /// First unconsumed queue seq. The watcher reports it so the engine can
    /// mark refunded entries (contract refund_deposit advances the head
    /// without a batch — issue #1 M5).
    fn dep_head(&self, asset: u32) -> Result<u64, ChainError>;
    fn get_pending_deposit(&self, asset: u32, seq: u64) -> Result<(Fr, u64), ChainError>;
    /// Sign + send submit_batch with the envelope JSON; returns when the CLI
    /// exits (success implies the tx was applied on-chain).
    fn submit_batch(&self, envelope_json: &str) -> Result<(), ChainError>;
}

/// Read (root, batch_num) as a self-consistent pair (issue #40): each CLI
/// call simulates against whatever ledger is current, so a batch landing
/// between the two reads would hand boot reconciliation an impossible
/// root/counter combination. Re-read the root after the counter and accept
/// only when both root observations agree.
pub fn consistent_root_and_batch(
    client: &dyn StellarClient,
    attempts: u32,
) -> Result<(Fr, u64), ChainError> {
    let mut root = client.root()?;
    for attempt in 0..attempts {
        let batch_num = client.batch_num()?;
        let root_after = client.root()?;
        if root_after == root {
            return Ok((root, batch_num));
        }
        tracing::info!(attempt, "chain advanced between boot reads; retrying");
        root = root_after;
    }
    Err(ChainError::Cli(format!(
        "chain root kept changing across {attempts} boot read attempts"
    )))
}

/// Identity name the secret is registered under at boot. The raw S… secret
/// must never appear on a CLI argv (visible in `ps`/audit logs — issue #2
/// H4); it reaches the CLI exactly once, via environment, at registration.
const IDENTITY: &str = "cellarium-seq-runtime";
/// Oracle admin identity (registered only when ORACLE_ADMIN_SECRET is set).
const ORACLE_IDENTITY: &str = "cellarium-oracle-runtime";

pub struct CliClient {
    pub rpc_url: String,
    pub network_passphrase: String,
    pub contract_id: String,
    pub oracle_id: String,
    pub sequencer_address: String,
    pub has_oracle_admin: bool,
    /// Deadline for read/simulate and local key operations.
    pub cli_timeout: Duration,
    /// Deadline for transaction-sending invocations (sign+send+confirm).
    pub submit_timeout: Duration,
}

impl CliClient {
    pub fn new(cfg: &crate::config::Config) -> Result<Self, ChainError> {
        let cli_timeout = Duration::from_secs(cfg.cli_timeout_secs);
        let submit_timeout = Duration::from_secs(cfg.submit_timeout_secs);
        // Register the runtime identity from the secret — idempotently
        // (--overwrite tolerates a prior boot). The secret travels via env,
        // never argv; every later invoke uses the identity NAME.
        let mut cmd = Command::new("stellar");
        cmd.args(["keys", "add", IDENTITY, "--secret-key", "--overwrite"])
            .env("SOROBAN_SECRET_KEY", &cfg.sequencer_secret)
            .env("STELLAR_SECRET_KEY", &cfg.sequencer_secret);
        let o = run_with_timeout(cmd, "keys add", cli_timeout)?;
        if !o.status.success() {
            return Err(ChainError::Cli(format!(
                "cannot register sequencer identity: {}",
                String::from_utf8_lossy(&o.stderr)
            )));
        }
        // Prefer the explicitly-provided public address (bootstrap knows it);
        // otherwise read it back from the registered identity.
        let sequencer_address = match &cfg.sequencer_address {
            Some(addr) if !addr.is_empty() => addr.clone(),
            _ => {
                let mut cmd = Command::new("stellar");
                cmd.args(["keys", "address", IDENTITY]);
                let o = run_with_timeout(cmd, "keys address", cli_timeout)?;
                if !o.status.success() {
                    return Err(ChainError::Cli(format!(
                        "cannot resolve sequencer address: {}",
                        String::from_utf8_lossy(&o.stderr)
                    )));
                }
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            }
        };
        // Register the oracle admin identity if provided (same env-only
        // secret handling as the sequencer identity).
        let has_oracle_admin = if let Some(secret) = &cfg.oracle_admin_secret {
            let mut cmd = Command::new("stellar");
            cmd.args([
                "keys",
                "add",
                ORACLE_IDENTITY,
                "--secret-key",
                "--overwrite",
            ])
            .env("SOROBAN_SECRET_KEY", secret)
            .env("STELLAR_SECRET_KEY", secret);
            let o = run_with_timeout(cmd, "keys add (oracle)", cli_timeout)?;
            if !o.status.success() {
                return Err(ChainError::Cli(format!(
                    "cannot register oracle admin identity: {}",
                    String::from_utf8_lossy(&o.stderr)
                )));
            }
            true
        } else {
            false
        };
        Ok(CliClient {
            rpc_url: cfg.rpc_url.clone(),
            network_passphrase: cfg.network_passphrase.clone(),
            contract_id: cfg.contract_id.clone(),
            oracle_id: cfg.oracle_id.clone(),
            sequencer_address,
            has_oracle_admin,
            cli_timeout,
            submit_timeout,
        })
    }

    fn invoke_on(
        &self,
        contract: &str,
        send: bool,
        func_and_args: &[&str],
    ) -> Result<String, ChainError> {
        let mut cmd = Command::new("stellar");
        cmd.args([
            "contract",
            "invoke",
            "--id",
            contract,
            "--rpc-url",
            &self.rpc_url,
            "--network-passphrase",
            &self.network_passphrase,
            "--source-account",
            IDENTITY,
        ]);
        if !send {
            cmd.arg("--send=no");
        }
        cmd.arg("--");
        cmd.args(func_and_args);
        let what = format!("invoke {}", func_and_args.first().unwrap_or(&"?"));
        let timeout = if send {
            self.submit_timeout
        } else {
            self.cli_timeout
        };
        let out = run_with_timeout(cmd, &what, timeout)?;
        if !out.status.success() {
            return Err(ChainError::Cli(format!(
                "invoke {:?} failed: {}",
                func_and_args.first(),
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn invoke(&self, send: bool, func_and_args: &[&str]) -> Result<String, ChainError> {
        self.invoke_on(&self.contract_id.clone(), send, func_and_args)
    }

    fn read_u64(&self, func: &str) -> Result<u64, ChainError> {
        let out = self.invoke(false, &[func])?;
        out.trim_matches('"')
            .parse()
            .map_err(|_| ChainError::Parse(format!("{func} -> {out:?}")))
    }
}

impl StellarClient for CliClient {
    fn root(&self) -> Result<Fr, ChainError> {
        let out = self.invoke(false, &["root"])?;
        let hexstr = out.trim_matches('"');
        Ok(parse_fr(&format!("0x{hexstr}"))?)
    }

    fn batch_num(&self) -> Result<u64, ChainError> {
        self.read_u64("batch_num")
    }

    fn oracle_price(&self) -> Result<(u64, u64), ChainError> {
        let out = self.invoke_on(&self.oracle_id.clone(), false, &["lastprice"])?;
        let v: serde_json::Value =
            serde_json::from_str(&out).map_err(|e| ChainError::Parse(e.to_string()))?;
        let num = |field: &str| -> Result<u64, ChainError> {
            let s = match &v[field] {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                other => return Err(ChainError::Parse(format!("oracle {field}: {other}"))),
            };
            s.parse()
                .map_err(|_| ChainError::Parse(format!("oracle {field}: {s}")))
        };
        Ok((num("price")?, num("timestamp")?))
    }

    fn refresh_oracle_price(&self, price: u64) -> Result<(), ChainError> {
        if !self.has_oracle_admin {
            return Err(ChainError::Cli(
                "no oracle admin identity configured".into(),
            ));
        }
        let mut cmd = Command::new("stellar");
        cmd.args([
            "contract",
            "invoke",
            "--id",
            &self.oracle_id,
            "--rpc-url",
            &self.rpc_url,
            "--network-passphrase",
            &self.network_passphrase,
            "--source-account",
            ORACLE_IDENTITY,
            "--",
            "set_price",
            "--price",
            &price.to_string(),
        ]);
        let out = run_with_timeout(cmd, "oracle set_price", self.submit_timeout)?;
        if !out.status.success() {
            return Err(ChainError::Cli(format!(
                "oracle refresh failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    fn dep_tail(&self, asset: u32) -> Result<u64, ChainError> {
        let out = self.invoke(false, &["dep_tail", "--asset", &asset.to_string()])?;
        out.trim_matches('"')
            .parse()
            .map_err(|_| ChainError::Parse(format!("dep_tail({asset}) -> {out:?}")))
    }

    fn dep_head(&self, asset: u32) -> Result<u64, ChainError> {
        let out = self.invoke(false, &["dep_head", "--asset", &asset.to_string()])?;
        out.trim_matches('"')
            .parse()
            .map_err(|_| ChainError::Parse(format!("dep_head({asset}) -> {out:?}")))
    }

    fn get_pending_deposit(&self, asset: u32, seq: u64) -> Result<(Fr, u64), ChainError> {
        let out = self.invoke(
            false,
            &[
                "get_pending_deposit",
                "--asset",
                &asset.to_string(),
                "--seq",
                &seq.to_string(),
            ],
        )?;
        let v: serde_json::Value =
            serde_json::from_str(&out).map_err(|e| ChainError::Parse(e.to_string()))?;
        let pk_hex = v["pk_x"]
            .as_str()
            .ok_or_else(|| ChainError::Parse(format!("deposit {seq}: {out}")))?;
        let pk_x = parse_fr(&format!("0x{pk_hex}"))?;
        let amount_str = match &v["amount"] {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            other => return Err(ChainError::Parse(format!("deposit amount: {other}"))),
        };
        let amount: u64 = amount_str
            .parse()
            .map_err(|_| ChainError::Parse(format!("deposit amount: {amount_str}")))?;
        Ok((pk_x, amount))
    }

    fn submit_batch(&self, envelope_json: &str) -> Result<(), ChainError> {
        self.invoke(
            true,
            &[
                "submit_batch",
                "--sequencer",
                &self.sequencer_address,
                "--envelope",
                envelope_json,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness::poseidon::fr_from_u64;

    /// Chain whose (root, batch_num) advance together after `advance_after`
    /// root reads — simulating a batch landing between the boot reads.
    struct AdvancingChain {
        root_reads: AtomicU64,
        advance_after: u64,
    }
    impl AdvancingChain {
        fn epoch(&self, reads: u64) -> u64 {
            if reads >= self.advance_after {
                2
            } else {
                1
            }
        }
    }
    impl StellarClient for AdvancingChain {
        fn root(&self) -> Result<Fr, ChainError> {
            let reads = self.root_reads.fetch_add(1, Ordering::Relaxed);
            Ok(fr_from_u64(self.epoch(reads + 1)))
        }
        fn batch_num(&self) -> Result<u64, ChainError> {
            Ok(self.epoch(self.root_reads.load(Ordering::Relaxed)))
        }
        fn oracle_price(&self) -> Result<(u64, u64), ChainError> {
            Err(ChainError::Cli("unused".into()))
        }
        fn refresh_oracle_price(&self, _price: u64) -> Result<(), ChainError> {
            Err(ChainError::Cli("unused".into()))
        }
        fn dep_tail(&self, _asset: u32) -> Result<u64, ChainError> {
            Err(ChainError::Cli("unused".into()))
        }
        fn dep_head(&self, _asset: u32) -> Result<u64, ChainError> {
            Err(ChainError::Cli("unused".into()))
        }
        fn get_pending_deposit(&self, _asset: u32, _seq: u64) -> Result<(Fr, u64), ChainError> {
            Err(ChainError::Cli("unused".into()))
        }
        fn submit_batch(&self, _envelope_json: &str) -> Result<(), ChainError> {
            Err(ChainError::Cli("unused".into()))
        }
    }

    /// Issue #40: a batch landing between the root and counter reads must
    /// not produce a mismatched pair — the retry converges on epoch 2.
    #[test]
    fn boot_reads_converge_when_chain_advances_between_calls() {
        let chain = AdvancingChain {
            root_reads: AtomicU64::new(0),
            advance_after: 2,
        };
        let (root, batch_num) = consistent_root_and_batch(&chain, 5).unwrap();
        assert_eq!(root, fr_from_u64(2));
        assert_eq!(batch_num, 2);
    }

    #[test]
    fn boot_reads_accept_stable_chain_first_try() {
        let chain = AdvancingChain {
            root_reads: AtomicU64::new(0),
            advance_after: 0,
        };
        let (root, batch_num) = consistent_root_and_batch(&chain, 5).unwrap();
        assert_eq!(root, fr_from_u64(2));
        assert_eq!(batch_num, 2);
    }

    #[test]
    fn timeout_kills_hanging_child() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let before = TIMEOUT_COUNT.load(Ordering::Relaxed);
        let start = Instant::now();
        let err = run_with_timeout(cmd, "sleep", Duration::from_millis(200)).unwrap_err();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "child was not killed promptly"
        );
        assert!(
            matches!(err, ChainError::Timeout { .. }),
            "expected timeout, got {err:?}"
        );
        assert!(TIMEOUT_COUNT.load(Ordering::Relaxed) > before);
    }

    #[test]
    fn fast_child_output_is_captured() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out; echo err 1>&2"]);
        let out = run_with_timeout(cmd, "sh", Duration::from_secs(10)).unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "err");
    }
}
