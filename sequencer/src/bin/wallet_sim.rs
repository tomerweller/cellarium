//! Test client for the sequencer pipeline: makes L1 deposits via the stellar
//! CLI and signs/POSTs L2 transactions with the harness's Grumpkin keys.
//! Deterministic keys by small scalar so pk_x values match the repo fixtures.
//!
//! Usage (asset: 0 = cash/XLM, 1 = coll/tUST):
//!   wallet-sim pk <sk>
//!   wallet-sim deposit <l2_pk_x_hex> <asset> <amount>   (funder = SEQ key)
//!   wallet-sim send <from_sk> <to_pk_x_hex> <asset> <amount> <nonce>
//!   wallet-sim withdraw <from_sk> <dest_strkey> <asset> <amount> <nonce>
//!   wallet-sim intent <initiator_sk> <role> <counterparty_sk> <cash> <coll> <rate_bps> <haircut_bps> <term_secs>
//!     (role = borrower|lender for the INITIATOR; nonces fetched live)
//!   wallet-sim accept <acceptor_sk> <intent_id>
//!   wallet-sim close <borrower_sk> <pos_index>
//!   wallet-sim positions <pk_x_hex>
//!
//! Env: SORIBIUM_URL (default http://127.0.0.1:8080), CONTRACT_ID, SEQ_KEY
//! (stellar CLI identity name or secret), plus standard stellar network vars.

use harness::batch::tx_message;
use harness::keys::{sign, Keypair};
use harness::l1::address_to_field;
use harness::poseidon::{to_hex, Fr, Hasher};
use harness::tree::Asset;

fn seq_url() -> String {
    std::env::var("SORIBIUM_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into())
}

fn keypair(sk: u64) -> Keypair {
    Keypair::from_sk(ark_grumpkin::Fr::from(sk))
}

fn post_json(path: &str, body: &serde_json::Value) -> String {
    let url = format!("{}{}", seq_url(), path);
    let out = std::process::Command::new("curl")
        .args(["-sS", "-X", "POST", &url, "-H", "Content-Type: application/json", "-d", &body.to_string()])
        .output()
        .expect("curl");
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    println!("{s}");
    s
}

fn post_tx(body: &serde_json::Value) {
    post_json("/tx", body);
}

fn get_json(path: &str) -> serde_json::Value {
    let url = format!("{}{}", seq_url(), path);
    let out = std::process::Command::new("curl").args(["-sS", &url]).output().expect("curl");
    serde_json::from_slice(&out.stdout).expect("json")
}

/// Live pending nonce for an L2 account (0 if the account doesn't exist yet).
fn pending_nonce(pk_x_hex: &str) -> u64 {
    let v = get_json(&format!("/account/{pk_x_hex}"));
    v["pending_nonce"].as_u64().unwrap_or(0)
}

fn sig_json(sig: &harness::keys::Signature) -> serde_json::Value {
    let (s_lo, s_hi) = sig.s_limbs();
    serde_json::json!({
        "r_x": to_hex(&sig.r_x),
        "r_y": to_hex(&sig.r_y),
        "s_lo": to_hex(&s_lo),
        "s_hi": to_hex(&s_hi),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let hasher = Hasher::new();

    match cmd {
        "pk" => {
            let sk: u64 = args[2].parse().unwrap();
            let kp = keypair(sk);
            println!("pk_x={}", to_hex(&kp.pk_x()));
            println!("pk_y={}", to_hex(&kp.pk_y()));
        }
        "deposit" => {
            let l2_pk_x = &args[2];
            let asset = &args[3];
            let amount = &args[4];
            let contract = std::env::var("CONTRACT_ID").expect("CONTRACT_ID");
            let key = std::env::var("SEQ_KEY").expect("SEQ_KEY");
            let rpc = std::env::var("RPC_URL").unwrap_or_else(|_| "https://soroban-testnet.stellar.org".into());
            let pass = std::env::var("NETWORK_PASSPHRASE")
                .unwrap_or_else(|_| "Test SDF Network ; September 2015".into());
            // `from` is the sequencer's own Stellar account (the funder).
            let addr = pubkey_of(&key);
            let l2_pk_x_bare = l2_pk_x.trim_start_matches("0x");
            let status = std::process::Command::new("stellar")
                .args([
                    "contract", "invoke", "--id", &contract, "--rpc-url", &rpc,
                    "--network-passphrase", &pass, "--source-account", &key, "--",
                    "deposit", "--from", &addr, "--l2_pk_x", l2_pk_x_bare, "--asset", asset,
                    "--amount", amount,
                ])
                .status()
                .expect("stellar invoke");
            std::process::exit(status.code().unwrap_or(1));
        }
        "send" => {
            let from = keypair(args[2].parse().unwrap());
            let to: Fr = parse_hex(&args[3]);
            let asset_id: u32 = args[4].parse().unwrap();
            let asset = Asset::from_u32(asset_id).expect("asset must be 0 or 1");
            let amount: u64 = args[5].parse().unwrap();
            let nonce: u64 = args[6].parse().unwrap();
            let msg = tx_message(&hasher, from.pk_x(), to, asset, amount, nonce, false);
            let sig = sign(&hasher, &from, msg, &mut rand::thread_rng());
            post_tx(&serde_json::json!({
                "from_pk_x": to_hex(&from.pk_x()),
                "from_pk_y": to_hex(&from.pk_y()),
                "to": to_hex(&to),
                "asset": asset_id,
                "amount": amount.to_string(),
                "nonce": nonce,
                "is_withdraw": false,
                "sig": sig_json(&sig),
            }));
        }
        "withdraw" => {
            let from = keypair(args[2].parse().unwrap());
            let dest = &args[3];
            let asset_id: u32 = args[4].parse().unwrap();
            let asset = Asset::from_u32(asset_id).expect("asset must be 0 or 1");
            let amount: u64 = args[5].parse().unwrap();
            let nonce: u64 = args[6].parse().unwrap();
            let to_field = address_to_field(&hasher, dest);
            let msg = tx_message(&hasher, from.pk_x(), to_field, asset, amount, nonce, true);
            let sig = sign(&hasher, &from, msg, &mut rand::thread_rng());
            post_tx(&serde_json::json!({
                "from_pk_x": to_hex(&from.pk_x()),
                "from_pk_y": to_hex(&from.pk_y()),
                "to": dest,
                "asset": asset_id,
                "amount": amount.to_string(),
                "nonce": nonce,
                "is_withdraw": true,
                "sig": sig_json(&sig),
            }));
        }
        "intent" => {
            use harness::repo::{open_message, Position};
            let initiator = keypair(args[2].parse().unwrap());
            let role = args[3].as_str();
            let counterparty = keypair(args[4].parse().unwrap());
            let cash: u64 = args[5].parse().unwrap();
            let coll: u64 = args[6].parse().unwrap();
            let rate_bps: u32 = args[7].parse().unwrap();
            let haircut_bps: u32 = args[8].parse().unwrap();
            let term_secs: u64 = args[9].parse().unwrap();

            let (borrower, lender) = match role {
                "borrower" => (&initiator, &counterparty),
                "lender" => (&counterparty, &initiator),
                other => panic!("role must be borrower|lender, got {other}"),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let position = Position {
                borrower_pk_x: borrower.pk_x(),
                lender_pk_x: lender.pk_x(),
                cash,
                coll,
                rate_bps,
                haircut_bps,
                open_ts: now,
                maturity_ts: now + term_secs,
            };
            let borrower_nonce = pending_nonce(&to_hex(&borrower.pk_x()));
            let lender_nonce = pending_nonce(&to_hex(&lender.pk_x()));
            let msg = open_message(&hasher, &position, borrower_nonce, lender_nonce);
            let sig = sign(&hasher, &initiator, msg, &mut rand::thread_rng());
            post_json("/intent", &serde_json::json!({
                "initiator": role,
                "borrower_pk_x": to_hex(&borrower.pk_x()),
                "borrower_pk_y": to_hex(&borrower.pk_y()),
                "lender_pk_x": to_hex(&lender.pk_x()),
                "lender_pk_y": to_hex(&lender.pk_y()),
                "cash": cash.to_string(),
                "coll": coll.to_string(),
                "rate_bps": rate_bps,
                "haircut_bps": haircut_bps,
                "open_ts": now,
                "maturity_ts": now + term_secs,
                "borrower_nonce": borrower_nonce,
                "lender_nonce": lender_nonce,
                "sig": sig_json(&sig),
            }));
        }
        "accept" => {
            use harness::repo::{open_message, Position};
            let acceptor = keypair(args[2].parse().unwrap());
            let intent_id: i64 = args[3].parse().unwrap();
            // Find the intent among those awaiting OUR countersignature.
            let listing = get_json(&format!("/intents/{}", to_hex(&acceptor.pk_x())));
            let intent = listing["incoming"]
                .as_array()
                .and_then(|a| a.iter().find(|i| i["id"].as_i64() == Some(intent_id)))
                .unwrap_or_else(|| panic!("intent {intent_id} not found in incoming"))
                .clone();
            let position = Position {
                borrower_pk_x: parse_hex(intent["borrower_pk_x"].as_str().unwrap()),
                lender_pk_x: parse_hex(intent["lender_pk_x"].as_str().unwrap()),
                cash: intent["cash"].as_str().unwrap().parse().unwrap(),
                coll: intent["coll"].as_str().unwrap().parse().unwrap(),
                rate_bps: intent["rate_bps"].as_u64().unwrap() as u32,
                haircut_bps: intent["haircut_bps"].as_u64().unwrap() as u32,
                open_ts: intent["open_ts"].as_u64().unwrap(),
                maturity_ts: intent["maturity_ts"].as_u64().unwrap(),
            };
            let msg = open_message(
                &hasher,
                &position,
                intent["borrower_nonce"].as_u64().unwrap(),
                intent["lender_nonce"].as_u64().unwrap(),
            );
            let sig = sign(&hasher, &acceptor, msg, &mut rand::thread_rng());
            post_json(
                &format!("/intent/{intent_id}/accept"),
                &serde_json::json!({ "sig": sig_json(&sig) }),
            );
        }
        "close" => {
            use harness::repo::Position;
            use harness::settle::close_message;
            let borrower = keypair(args[2].parse().unwrap());
            let pos_index: u32 = args[3].parse().unwrap();
            let listing = get_json(&format!("/positions/{}", to_hex(&borrower.pk_x())));
            let pos = listing["positions"]
                .as_array()
                .and_then(|a| a.iter().find(|p| p["slot"].as_u64() == Some(pos_index as u64)))
                .unwrap_or_else(|| panic!("position {pos_index} not found"))
                .clone();
            let position = Position {
                borrower_pk_x: parse_hex(pos["borrower_pk_x"].as_str().unwrap()),
                lender_pk_x: parse_hex(pos["lender_pk_x"].as_str().unwrap()),
                cash: pos["cash"].as_str().unwrap().parse().unwrap(),
                coll: pos["coll"].as_str().unwrap().parse().unwrap(),
                rate_bps: pos["rate_bps"].as_u64().unwrap() as u32,
                haircut_bps: pos["haircut_bps"].as_u64().unwrap() as u32,
                open_ts: pos["open_ts"].as_u64().unwrap(),
                maturity_ts: pos["maturity_ts"].as_u64().unwrap(),
            };
            let nonce = pending_nonce(&to_hex(&borrower.pk_x()));
            let msg = close_message(&hasher, pos_index, &position, nonce);
            let sig = sign(&hasher, &borrower, msg, &mut rand::thread_rng());
            post_json("/close", &serde_json::json!({
                "pos_index": pos_index,
                "borrower_pk_x": to_hex(&borrower.pk_x()),
                "borrower_pk_y": to_hex(&borrower.pk_y()),
                "nonce": nonce,
                "sig": sig_json(&sig),
            }));
        }
        "positions" => {
            let v = get_json(&format!("/positions/{}", &args[2]));
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        _ => {
            eprintln!("usage: wallet-sim pk|deposit|send|withdraw|intent|accept|positions ...");
            std::process::exit(2);
        }
    }
}

fn parse_hex(s: &str) -> Fr {
    let body = s.trim_start_matches("0x");
    let bytes = hex::decode(body).expect("hex");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn pubkey_of(key: &str) -> String {
    // `key` is a stellar CLI identity name; resolve to its G-address.
    let out = std::process::Command::new("stellar")
        .args(["keys", "address", key])
        .output()
        .expect("stellar keys address");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}
