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

## License
EmergenceFS Sovereign License - See `LICENSE` for details.
