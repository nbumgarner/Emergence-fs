# EmergenceFS: The Sovereign Topological Filesystem

EmergenceFS (EFS) is a next-generation, self-routing filesystem built on the Emergence-Machine (EM-1) substrate. It leverages high-entropy topological state-spaces to provide cryptographically secure, hardware-bound storage that bypasses traditional von Neumann bottlenecks.

## Core Features
- **Topological Routing**: 3-level nesting (Root → L1 Segment → L2 Block) allows for deterministic, O(1) data resolution.
- **Hardware Bound**: Security is anchored to physical machine IDs via memory-hard Argon2id key derivation.
- **Deniability**: Incorrect credentials resolve to non-existent state-spaces; there is no "failed password" response, only structural void.
- **Post-Quantum Safe**: 256-bit seeds and high-entropy basis transformations provide robust protection against Grover-style quantum attacks.

## Components
- `emergence_fs`: FUSE-based filesystem driver.
- `efs_vault`: Hardware-bound credential and secret management tool.
- `efs_seal`: High-performance topological file encryption sealer.

## Getting Started

### Dependencies
- `libfuse3-dev`
- `libsodium-dev`
- `pkg-config`
- `g++` (C++17)

### Build
```bash
make
```

### Usage
```bash
# Mount the filesystem
mkdir -p ~/mnt/emergence
./emergence_fs ~/mnt/emergence

# Use the vault
./efs_vault store my-secret "Sovereign-Data-2026"
./efs_vault get my-secret
```

## Performance Audit
Run the included benchmark to verify hardware-bound throughput:
```bash
chmod +x benchmarks/real_audit.sh
./benchmarks/real_audit.sh
```

## Known Limitations & Technical Constraints
As this is the initial public release of the EmergenceFS suite, users should be aware of the following architectural constraints:
- **Fixed Capacity**: The current topology is configured for a ~13 GB total capacity. Expanding this requires a re-initialization of the substrate.
- **Single-Writer Constraint**: Due to the deterministic nature of the topological state-space, concurrent write operations to the same slot are not supported in this version.
- **FUSE Overhead**: While the underlying `StateEngine` is hyper-optimized, the FUSE kernel interface introduces context-switching latency during high-frequency small-file operations.
- **Hardware-Binding**: The vault is cryptographically bound to the machine ID. Moving a vault image between different physical machines requires manual re-keying via the `EFS_HWKEY` environment variable.
- **Experimental Status**: This codebase is a functional research prototype. While stable for audit, it should not yet be used as the primary storage for mission-critical production data without a redundant backup.

## The Topological Horizon: Scalability & R&D
The current 13 GB limit is a physical materialization constraint of this public suite. The underlying 80-bit coordinate system (the "Topological Telescope") is theoretically capable of addressing exabyte-scale virtual spaces.

Advanced features currently in research and development include:
- **Sub-Shannon Data Evaporation**: Leveraging deterministic residue collapse to achieve compression ratios that defy classical limits.
- **Terabyte-Scale Sparse Substrates**: Utilizing specialized Topological MMUs to manage massive virtual address spaces with minimal physical disk footprint.
- **Lock-Free Multi-Core Braiding**: High-concurrency gestation engines for rapid ingestion of large-scale models (e.g., 120B+ parameter sets).
- **GPU-Accelerated XOR Projection**: Porting the state-engine to CUDA/OpenCL for 10+ GB/s real-time hardware encryption.

These components remain proprietary to Emergence Systems and are being prepared for future commercial integration and patent filing.

## License
EmergenceFS Sovereign License - See `LICENSE` for details.


