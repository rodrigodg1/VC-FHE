use ethers::middleware::SignerMiddleware;
use ethers::prelude::{Http, LocalWallet, Middleware, Provider, Signer};
use ethers::types::{Address, TransactionRequest, U64, U256};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HARDHAT_CHAIN_ID: u64 = 31337;
const HARDHAT_ACCOUNT_0: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HARDHAT_ACCOUNT_1: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

#[derive(Serialize)]
struct ProbeRow {
    mode: String,
    trial: u32,
    provider_interval_ms: u128,
    elapsed_ms: f64,
    gas_used: u64,
    block_number: u64,
    tx_hash: String,
    status: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let out_csv = std::env::var("OUT_CSV").unwrap_or_else(|_| {
        "../receipt_poll_probe_results.csv".to_string()
    });
    let trials = std::env::var("TRIALS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(3);

    if let Some(parent) = Path::new(&out_csv).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = open_csv(&out_csv)?;

    let wallet: LocalWallet = HARDHAT_ACCOUNT_0
        .parse::<LocalWallet>()?
        .with_chain_id(HARDHAT_CHAIN_ID);
    let recipient: Address = HARDHAT_ACCOUNT_1.parse()?;

    let default_provider = Provider::<Http>::try_from(rpc_url.as_str())?;
    let default_interval_ms = default_provider.get_interval().as_millis();

    let fast_provider =
        Provider::<Http>::try_from(rpc_url.as_str())?.interval(Duration::from_millis(100));
    let fast_interval_ms = fast_provider.get_interval().as_millis();

    println!("RPC URL: {}", rpc_url);
    println!(
        "Default provider interval (Provider::try_from): {} ms",
        default_interval_ms
    );
    println!(
        "Fast provider interval (Provider::try_from + interval(100ms)): {} ms",
        fast_interval_ms
    );

    run_trials(
        "try_from_default",
        default_provider,
        default_interval_ms,
        wallet.clone(),
        recipient,
        trials,
        &mut file,
    )
    .await?;

    run_trials(
        "try_from_interval_100ms",
        fast_provider,
        fast_interval_ms,
        wallet,
        recipient,
        trials,
        &mut file,
    )
    .await?;

    println!("Probe results written to {}", out_csv);
    Ok(())
}

async fn run_trials(
    mode: &str,
    provider: Provider<Http>,
    provider_interval_ms: u128,
    wallet: LocalWallet,
    recipient: Address,
    trials: u32,
    file: &mut File,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    println!("\n=== {} ===", mode);
    for trial in 1..=trials {
        let tx = TransactionRequest::pay(recipient, U256::from(1u64));
        let start = Instant::now();
        let pending = client.send_transaction(tx, None).await?;
        let tx_hash = format!("{:#x}", pending.tx_hash());
        let receipt = pending
            .await?
            .ok_or_else(|| format!("missing receipt for {}", tx_hash))?;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let gas_used = receipt.gas_used.unwrap_or_default().as_u64();
        let block_number = receipt.block_number.unwrap_or_else(U64::zero).as_u64();
        let status = if receipt.status == Some(U64::from(1u64)) {
            "success".to_string()
        } else {
            "reverted".to_string()
        };

        println!(
            "trial={} interval={}ms elapsed={:.2}ms gas={} block={} status={}",
            trial, provider_interval_ms, elapsed_ms, gas_used, block_number, status
        );

        let row = ProbeRow {
            mode: mode.to_string(),
            trial,
            provider_interval_ms,
            elapsed_ms,
            gas_used,
            block_number,
            tx_hash,
            status,
        };
        writeln!(
            file,
            "{},{},{},{:.2},{},{},{},{}",
            row.mode,
            row.trial,
            row.provider_interval_ms,
            row.elapsed_ms,
            row.gas_used,
            row.block_number,
            row.tx_hash,
            row.status
        )?;

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Ok(())
}

fn open_csv(path: &str) -> Result<File, Box<dyn std::error::Error>> {
    let exists = Path::new(path).exists();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if !exists {
        writeln!(
            file,
            "mode,trial,provider_interval_ms,elapsed_ms,gas_used,block_number,tx_hash,status"
        )?;
    }
    Ok(file)
}
