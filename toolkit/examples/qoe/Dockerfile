# Reference environment for the VC-FHE pipeline: Node 22.10 (Hardhat 3
# constraint), Rust (tfhe-rs), and the JS dependencies of fhe-pod and of the
# QoE examples, in one image.
#
# Build FROM THE VC-FHE REPOSITORY ROOT (the build context must be the whole
# repository):
#
#   cd VC-FHE
#   docker build -f toolkit/examples/qoe/Dockerfile -t vcfhe .
#
# Run:
#
#   docker run -it --rm vcfhe
#
# See toolkit/examples/qoe/SETUP.md for usage, cargo-cache volumes, and the
# docker-compose variant with a separate blockchain node.

FROM node:22.10.0-bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        curl \
        git \
        ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# Rust toolchain for the real-TFHE stages (tfhe-rs; Linux backend).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /workspace/VC-FHE
COPY . .

# JS dependencies: fhe-pod first (the examples reuse its Hardhat binary),
# then the QoE example runners.
RUN cd fhe-pod && npm install \
    && cd ../toolkit/examples/qoe && npm install

# Pre-fetch Rust dependencies so the first TFHE run works without network
# access. Compilation itself still happens on first use (several minutes).
RUN cd BN254-Signatures && cargo fetch \
    && cd ../fhe-pod && cargo fetch

WORKDIR /workspace/VC-FHE/toolkit/examples/qoe
CMD ["bash"]
