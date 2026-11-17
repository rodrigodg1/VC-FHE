# The orchestrator records the resolved image ID and the complete source closure.
FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS node
FROM rust:1.94.0-bookworm@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang pkg-config libssl-dev protobuf-compiler python3
ENV CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
WORKDIR /upstream
COPY upstream/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/upstream/target \
    cargo build --locked --profile release-lto-off -p kms --features insecure,testing --bin kms-server --bin kms-gen-keys --bin kms-init && \
    cargo test --locked --profile release-lto-off -p kms-core-client --features threshold_tests,tfhe/experimental-force_fft_algo_dif4 --test integration_test --no-run --message-format=json-render-diagnostics > /tmp/build.json && \
    mkdir /binaries && cp target/release-lto-off/kms-server target/release-lto-off/kms-gen-keys target/release-lto-off/kms-init /binaries/ && \
    python3 -c 'import json,shutil; a=[j["executable"] for s in open("/tmp/build.json") if (j:=json.loads(s)).get("executable") and j.get("target",{}).get("name")=="integration_test"]; assert len(a)==1; shutil.copy2(a[0],"/binaries/kms-campaign")'
RUN mkdir /build-evidence && cp Cargo.lock vcfhe-adapter.json /build-evidence/ && \
    rustc -Vv > /build-evidence/rustc.txt && cargo -V > /build-evidence/cargo.txt
FROM node AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates python3 procps curl && \
    useradd --uid 10001 --create-home campaign
COPY --from=build /binaries/ /usr/local/bin/
COPY app/ /app/
COPY --from=build /build-evidence/ /app/threshold-kms/campaign/build-evidence/
WORKDIR /app
RUN python3 threshold-kms/campaign/prepare-js.py && \
    cd BN254-Signatures && npm ci --ignore-scripts && cd ../fhe-pod && npm ci --ignore-scripts && \
    python3 /app/threshold-kms/campaign/build-profile.py --runtime /app/threshold-kms/campaign/runtime && \
    ln -s /tmp/vcfhe-compiled-contracts /app/threshold-kms/campaign/runtime/contracts/out && \
    python3 /app/threshold-kms/campaign/inventory.py && \
    chmod -R a+rX /app
ENV NODE_ENV=production RUST_LOG=warn RAYON_NUM_THREADS=1
USER 10001:10001
ENTRYPOINT ["python3", "/app/threshold-kms/campaign/container.py"]
