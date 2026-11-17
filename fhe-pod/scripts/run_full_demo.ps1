$ErrorActionPreference = "Stop"

Write-Host "[1/5] Running TFHE trace generator with terminal tracing..."
cargo run -p tfhe-pod-demo

Write-Host "[2/5] Installing Node dependencies if needed..."
if (-not (Test-Path "node_modules")) {
    npm install
}

Write-Host "[3/5] Running EVM protocol tests..."
npm run test:evm

Write-Host "[4/5] Running local dispute-game demo..."
npm run demo:evm

Write-Host "[5/5] Running Hardhat honest-vs-dishonest dispute demo..."
npm run demo:hardhat

Write-Host "Full demo completed."
