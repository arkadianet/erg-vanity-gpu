//! erg-boxid-vanity: vanity Ergo box-ID / token-ID grinder.
//!
//! Milestone 1 (this binary): prove byte-exact box-ID reproduction against
//! live chain data:
//!   1. fetch unconfirmed transactions from a public node
//!   2. for every output box: GET /utxo/byIdBinary/{id} -> canonical bytes
//!   3. check blake2b256(bytes) == id          (formula)
//!   4. parse the same JSON via ergo-lib and re-serialize -> must equal
//!      the node's raw bytes                   (serializer parity)

use clap::{Parser, Subcommand};
use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use sigma_util::hash::blake2b256_hash;
use std::time::Instant;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    mode: Option<Mode>,
    /// Node base URL (public mainnet nodes work)
    #[arg(long, default_value = "http://213.239.193.208:9053")]
    node: String,
    /// How many mempool transactions to sample
    #[arg(long, default_value_t = 5)]
    txs: usize,
}

fn http_get(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // HTTPS: delegate to the system curl (TLS without extra dependencies).
    if let Some(rest) = url.strip_prefix("https://") {
        use std::process::{Command, Stdio};
        let host = rest.split('/').next().ok_or("bad url")?;
        let out = Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "25",
                "--fail-with-body",
                "-H",
                &format!("Host: {host}"),
                "-H",
                "Accept: */*",
                url,
            ])
            .stderr(Stdio::inherit())
            .output()?;
        if !out.status.success() {
            return Err(format!(
                "HTTPS GET {url} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        return Ok(out.stdout);
    }
    // Minimal HTTP/1.0 GET - avoids adding a network dependency for now.
    use std::io::{Read, Write};
    let (host, port, path) = url
        .strip_prefix("http://")
        .map(|rest| {
            let (authority, p) = rest.split_once('/').unwrap_or((rest, ""));
            let (h, po) = authority
                .split_once(':')
                .map_or((authority, "80"), |(a, b)| (a, b));
            (
                h.to_string(),
                po.parse::<u16>().unwrap_or(80),
                format!("/{}", p),
            )
        })
        .ok_or("only http:// supported")?;
    let mut stream = std::net::TcpStream::connect((host.as_str(), port))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: erg-boxid-vanity\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    // Split headers/body on first \r\n\r\n; handle chunked encoding minimally.
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("bad http response")?;
    let head = String::from_utf8_lossy(&raw[..sep]).to_string();
    let mut body = raw[sep + 4..].to_vec();
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body = dechunk(&body)?;
    }
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("??")
        .to_string();
    if !status.starts_with('2') {
        return Err(format!("HTTP {status} for {url}").into());
    }
    Ok(body)
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    loop {
        let line_end = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("bad chunk header")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&b[..line_end])?
                .trim()
                .split(';')
                .next()
                .unwrap_or("0"),
            16,
        )?;
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        out.extend_from_slice(&b[start..start + size]);
        b = &b[start + size + 2..];
    }
    Ok(out)
}

#[derive(Subcommand)]
enum Mode {
    /// Verify against a node's mempool inputs (needs reachable node)
    Node,
    /// Verify against explorer full-box JSON (HTTPS, most reliable)
    Explorer {
        #[arg(long, default_value = "https://api.ergoplatform.com")]
        api: String,
        #[arg(long, default_value_t = 25)]
        boxes: usize,
    },
}

/// Explorer-based verification: full box JSON -> ergo-lib parse -> serialize
/// -> blake2b256 == boxId. HTTPS only, no node needed.
fn verify_explorer(api: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    // 1. gather real box ids from recently minted tokens
    let list_url = format!("{api}/api/v1/tokens?limit={count}");
    let tokens: serde_json::Value = serde_json::from_slice(&http_get(&list_url)?)?;
    let mut ids: Vec<String> = Vec::new();
    if let Some(items) = tokens["items"].as_array() {
        for t in items {
            if let Some(id) = t["boxId"].as_str() {
                ids.push(id.to_string());
            }
        }
    }
    println!("verifying {} boxes via {api}", ids.len());

    let (mut ok, mut bad) = (0usize, 0usize);
    for id in &ids {
        let url = format!("{api}/api/v1/boxes/{id}");
        let raw_json = http_get(&url)?;
        let value: serde_json::Value = serde_json::from_slice(&raw_json)?;
        let expect = hex::decode(id)?;
        match serde_json::from_value::<ErgoBox>(value.clone()) {
            Ok(box_parsed) => match box_parsed.sigma_serialize_bytes() {
                Ok(bytes) => {
                    let h = blake2b256_hash(&bytes);
                    if h.as_slice() == expect.as_slice() {
                        ok += 1;
                        print!(".");
                    } else {
                        bad += 1;
                        eprintln!(
                            "\nMISMATCH {}: hash={} id={}",
                            id,
                            hex::encode(h.as_slice()),
                            id
                        );
                    }
                }
                Err(e) => {
                    bad += 1;
                    eprintln!("\nserialize error {id}: {e}");
                }
            },
            Err(e) => {
                bad += 1;
                eprintln!("\nparse error {id}: {e}");
            }
        }
    }
    println!("\n{ok} verified, {bad} failed");
    if ok > 0 && bad == 0 {
        println!("MILESTONE 1 VERIFIED (explorer path): blake2b256(canonical box bytes) == boxId");
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cli = Cli::parse();
    if std::env::var("ERG_BV_MODE").as_deref() == Ok("explorer") {
        cli.mode = Some(Mode::Explorer {
            api: "https://api.ergoplatform.com".into(),
            boxes: 25,
        });
    }
    let _ = &cli;
    run(&cli)
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let node = cli.node.trim_end_matches('/');
    if let Some(Mode::Explorer { api, boxes }) = &cli.mode {
        return verify_explorer(api, *boxes);
    }
    let _ = node;

    // Mempool txs -> their INPUT boxIds -> those boxes are still live UTXOs,
    // so /utxo/byIdBinary serves their canonical bytes even on UTXO-pruned
    // nodes. Each box then gets two independent checks against its id:
    //   formula:    blake2b256(bytes) == id
    //   serializer: ergo-lib parse(bytes) -> serialize(bytes) == bytes
    let url = format!("{node}/transactions/unconfirmed?limit={}", cli.txs);
    println!("fetching {url}");
    let mempool: serde_json::Value = serde_json::from_slice(&http_get(&url)?)?;
    let mut wanted: Vec<String> = Vec::new();
    if let Some(txs) = mempool.as_array() {
        for tx in txs {
            if let Some(inputs) = tx.get("inputs").and_then(|v| v.as_array()) {
                for i in inputs {
                    if let Some(id) = i.get("boxId").and_then(|v| v.as_str()) {
                        if !wanted.contains(&id.to_string()) {
                            wanted.push(id.to_string());
                        }
                    }
                }
            }
        }
    }
    wanted.truncate(cli.txs * 8);
    println!("distinct input boxes to verify: {}", wanted.len());

    let mut boxes_checked = 0usize;
    let mut formula_ok = 0usize;
    let mut serializer_ok = 0usize;
    let mut failures = 0usize;

    for id_str in &wanted {
        {
            let id_str = id_str.as_str();
            // Node returns the canonical raw bytes for this box.
            let bin_url = format!("{node}/utxo/byIdBinary/{id_str}");
            let Ok(bin_resp) = http_get(&bin_url) else {
                eprintln!("  [{id_str}] byIdBinary fetch failed");
                failures += 1;
                continue;
            };
            let bin_json: serde_json::Value = serde_json::from_slice(&bin_resp)?;
            let Some(bytes_hex) = bin_json["bytes"].as_str() else {
                eprintln!("  [{id_str}] no bytes field");
                failures += 1;
                continue;
            };
            let raw = hex::decode(bytes_hex)?;
            let t0 = Instant::now();
            let recomputed = blake2b256_hash(&raw);
            let _ = t0.elapsed(); // timing micro-bench later
            let expect = hex::decode(id_str)?;

            // Formula check: blake2b256(canonical box bytes) == advertised id.
            if recomputed.as_slice() == expect.as_slice() {
                formula_ok += 1;
            } else {
                failures += 1;
                eprintln!(
                    "  FORMULA MISMATCH {id_str}\n    got  {}\n    want {id_str}",
                    hex::encode(recomputed.as_slice())
                );
            }

            // Serializer parity: ergo-lib round-trip must equal node bytes.
            match ErgoBox::sigma_parse_bytes(&raw) {
                Ok(box_parsed) => match box_parsed.sigma_serialize_bytes() {
                    Ok(ours) if ours == raw => serializer_ok += 1,
                    other => {
                        failures += 1;
                        let len = other.as_ref().map_or(0, |v| v.len());
                        eprintln!(
                            "  SERIALIZER DIFF {id_str}: ours {}B vs node {}B",
                            len,
                            raw.len()
                        );
                    }
                },
                Err(e) => {
                    failures += 1;
                    eprintln!("  JSON parse failed for {id_str}: {e}");
                }
            }
            boxes_checked += 1;
        }
    }

    println!(
        "\n{} boxes checked: formula ok={formula_ok}, serializer-parity ok={serializer_ok}, failures={failures}",
        boxes_checked
    );
    if failures == 0 && boxes_checked > 0 {
        println!(
            "MILESTONE 1 VERIFIED: blake2b256(canonical box bytes) == boxId, and our \
             ergo-lib serialization is byte-identical to node consensus bytes."
        );
    } else if boxes_checked == 0 {
        println!("no boxes sampled - check connectivity");
    }
    Ok(())
}
