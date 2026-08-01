# Cellarium sequencer image.
#
# Targets linux/amd64: Barretenberg (bb) publishes only amd64-linux binaries
# for 0.87.0, so this is the portable choice for real deployment (Fly.io et
# al. run amd64). On an Apple Silicon dev box either run the sequencer
# natively (`just sequencer`) or run this image under emulation with adequate
# RAM (bb needs ~1GB for n16). Build explicitly:
#   docker build --platform linux/amd64 -t cellarium-sequencer .
FROM --platform=linux/amd64 rust:1.95-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY contracts/rollup/Cargo.toml contracts/rollup/Cargo.toml
COPY harness/Cargo.toml harness/Cargo.toml
COPY sequencer/Cargo.toml sequencer/Cargo.toml
COPY contracts contracts
COPY harness harness
COPY sequencer sequencer
RUN cargo build --release -p sequencer --bins
# Contract wasms for the auto-bootstrap entrypoint (AUTO_BOOTSTRAP=1): a
# circuit/schema-incompatible boot deploys a fresh instance from inside the
# container, so the image must carry deployable wasm for all three contracts.
RUN rustup target add wasm32v1-none \
    && cargo build --release --target wasm32v1-none -p rollup -p tust -p oracle

FROM --platform=linux/amd64 debian:bookworm-slim AS tools
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates tar gzip git \
    && rm -rf /var/lib/apt/lists/*
# Pinned toolchain (same versions/commits as the repo's CI + Phase A).
ENV NARGO_VERSION=1.0.0-beta.11 BB_VERSION=0.87.0 STELLAR_VERSION=27.0.0
RUN curl -fsSL "https://raw.githubusercontent.com/noir-lang/noirup/c3bc9922bf7eeafdaba08fb6518776c4ba263a8c/install" -o /tmp/noirup.sh \
    && bash /tmp/noirup.sh \
    && /root/.nargo/bin/noirup -v "$NARGO_VERSION"
RUN curl -fsSL "https://raw.githubusercontent.com/AztecProtocol/aztec-packages/073ea66ad92c53ebbf7be70d28973a68a8628942/barretenberg/bbup/install" -o /tmp/bbup.sh \
    && bash /tmp/bbup.sh \
    && /root/.bb/bbup -v "$BB_VERSION"
RUN curl -fsSL "https://github.com/stellar/stellar-cli/releases/download/v${STELLAR_VERSION}/stellar-cli-${STELLAR_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
    | tar -xz -C /usr/local/bin stellar

# trixie (glibc 2.41): the bb amd64 binary requires GLIBC >= 2.38 /
# GLIBCXX >= 3.4.31, newer than bookworm's 2.36.
FROM --platform=linux/amd64 debian:trixie-slim AS runtime
# git: nargo clones the noir-lang/poseidon dependency when compiling circuits.
# libdbus-1-3: the stellar CLI links it (keyring integration).
# jq: bb's CRS (SRS) download helper shells out to it on first prove.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git libdbus-1-3 jq \
    && (apt-get install -y --no-install-recommends libssl3t64 || apt-get install -y --no-install-recommends libssl3) \
    && rm -rf /var/lib/apt/lists/*
# Toolchain at the paths prove.sh / prover.rs expect ($HOME/.nargo/bin, $HOME/.bb).
COPY --from=tools /root/.nargo /root/.nargo
COPY --from=tools /root/.bb /root/.bb
COPY --from=tools /usr/local/bin/stellar /usr/local/bin/stellar
ENV PATH="/root/.nargo/bin:/root/.bb:${PATH}"
COPY --from=builder /app/target/release/sequencer /usr/local/bin/sequencer
COPY --from=builder /app/target/release/wallet-sim /usr/local/bin/wallet-sim
# Ship the Noir workspace and pre-compile the circuit so runtime only runs
# execute + prove.
COPY circuits /app/circuits
# Bake the deployable circuit (CIRCUIT_PKG selects at runtime); the
# poseidon git dependency gets cloned here so runtime needs no network.
RUN cd /app/circuits && nargo compile --package batch_repo
# Warm bb's CRS cache (downloaded on first use) so runtime proving never
# needs network. write_vk pulls the same prover CRS as prove but needs no
# witness (Prover.toml is gitignored, so CI build contexts don't have one).
RUN cd /app/circuits && mkdir -p /tmp/crs-warm \
    && bb write_vk --scheme ultra_honk --oracle_hash keccak \
         --bytecode_path target/batch_repo.json --output_path /tmp/crs-warm \
    && test -s /tmp/crs-warm/vk && rm -rf /tmp/crs-warm
ENV CIRCUITS_DIR=/app/circuits
ENV DB_PATH=/data/sequencer.db
ENV LISTEN_ADDR=0.0.0.0:8080
# Contract wasms + entrypoint for opt-in self-bootstrap (AUTO_BOOTSTRAP=1):
# when the baked circuit's VK or the DB schema no longer matches the
# instance recorded on the volume, the entrypoint deploys fresh contracts,
# archives the old DB, and starts against the new instance. Without
# AUTO_BOOTSTRAP it execs the sequencer directly (docker-compose flow).
COPY --from=builder /app/target/wasm32v1-none/release/rollup.wasm /app/wasm/rollup.wasm
COPY --from=builder /app/target/wasm32v1-none/release/tust.wasm /app/wasm/tust.wasm
COPY --from=builder /app/target/wasm32v1-none/release/oracle.wasm /app/wasm/oracle.wasm
COPY scripts/docker_entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/app/entrypoint.sh"]
