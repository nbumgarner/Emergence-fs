# EFS Vault: Topology-Native Secrets Engine

## Technical Whitepaper v1.0 — April 2026

**Emergence Systems**
Nicholas Bumgarner, Principal Architect

---

## Executive Summary

EFS Vault is a post-quantum, hardware-bound secrets engine that eliminates the
attack surfaces inherent in traditional credential management. Unlike conventional
vaults that encrypt secrets and store them in a database, EFS Vault embeds secrets
within a self-routing cryptographic topology where the data structure itself is the
security mechanism. Without the correct password and hardware key, stored secrets
do not merely become unreadable — they are structurally absent from the topology.

**Key differentiators:**
- Zero-server architecture (no daemon, no API surface, no network dependency)
- Post-quantum security (128-bit PQ level via Argon2id + 256-bit seed)
- Hardware binding (secrets tied to physical machine fingerprint)
- Deterministic credential derivation (one master secret → unlimited per-service tokens)
- Single static binary, zero runtime dependencies
- Disk image indistinguishable from random noise (7.999989/8.0 bits/byte entropy)

---

## 1. Problem Statement

### 1.1 Current Secrets Management is Broken

Modern secrets management solutions share a common architecture: a server process
holds encryption keys, accepts authenticated requests, and returns decrypted
secrets from a backend database. This architecture creates multiple attack surfaces:

| Attack Surface | HashiCorp Vault | AWS Secrets Manager | Azure Key Vault |
|---------------|-----------------|---------------------|-----------------|
| Network API | Yes (TCP 8200) | Yes (HTTPS) | Yes (HTTPS) |
| Backend database | Consul/Raft | DynamoDB | CosmosDB |
| Unsealing process | Shamir shares | AWS KMS | HSM |
| Memory exposure | Plaintext in RAM | Plaintext in RAM | Plaintext in RAM |
| Server compromise | Full exfiltration | IAM pivot | Managed identity pivot |
| Cloud dependency | Optional | Required | Required |
| Offline operation | Partial | No | No |
| Post-quantum | No | No | No |

In every case, a sufficiently privileged attacker who compromises the server or
cloud account gains access to all secrets. The encryption is a gate, not the
structure — once past it, everything is plaintext.

### 1.2 The Quantum Threat

NIST has standardized post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) and
mandated transition timelines. Current secrets management solutions rely on
RSA, ECDSA, or AES-GCM with key exchange protocols vulnerable to quantum
attack. A "harvest now, decrypt later" adversary capturing vault traffic or
database snapshots today can decrypt them once quantum computers are available.

### 1.3 Air-Gap Requirements

Defense, intelligence, critical infrastructure, and financial organizations
increasingly require secrets management that operates without network
connectivity. Cloud-dependent solutions are disqualified from classified
environments, SCIFs, and air-gapped networks.

---

## 2. Architecture

### 2.1 Topology Overview

EFS Vault is built on a self-routing cryptographic topology: an 8-level
hierarchical structure of 128-bit values where each value's top 10 bits
encode routing information that determines the traversal path through
subsequent levels.

```
Password + Hardware Key
         │
    [ Argon2id ]  ←── 64 MB memory-hard, 3 iterations, 4 threads
         │
    256-bit Seed
         │
    [ Lens Generator ]  ←── 64-round mixing per key
         │
    1,024 Lens Keys (128-bit each)
         │
    ┌────┴────┐
    │ Level 0 │  Root block: 1,024 entries, seed-derived routes
    └────┬────┘
    ┌────┴────┐
    │ Level 1 │  1,024 segment tables (eagerly allocated)
    └────┬────┘       Each: 1,024 entries = 16 KB
    ┌────┴────┐
    │ Level 2 │  Data blocks (lazily allocated, up to 1,024 per L1 slot)
    └────┬────┘       File storage, secret data
    ┌────┴────┐
    │ L3 – L7 │  Deep blocks (lazily allocated)
    └─────────┘       State engine transitions, projected execution
```

**Key property:** The topology is deterministic. The same seed always produces
the same structure. A different seed produces a completely different structure
that is cryptographically independent — there is no partial decryption, no
information leakage, no way to determine whether a given seed is "close to"
correct.

### 2.2 Secret Storage

Secrets are stored in Level 2 data blocks, addressed by topology projection:

1. Secret name is hashed to a 10-bit symbol (FNV-1a).
2. The symbol is projected through the topology's self-routing chain.
3. The projection resolves to an L1 slot, which determines the L2 data blocks.
4. Secret data is written across the L2 blocks (up to ~13 MB per secret).

With the correct seed, the projection resolves to the correct storage location.
With any other seed, it resolves to a different (empty or noise-filled) location.
The secret is not encrypted — it is **structurally absent** from the wrong topology.

### 2.3 Credential Derivation

The state engine is a 1,024-state Mealy machine with 1,024 input symbols per
state, totaling 1,048,576 transitions. Each transition carries 13 bytes of
output payload and encodes its successor state in the value's route bits.

Derivation process:
1. Build the full transition table from the seed (deterministic).
2. Feed the master secret bytes as input symbols (positions the machine at
   a secret-determined state).
3. Feed the service identifier bytes as additional input (specializes to
   this service).
4. Generate output bytes from the resulting state trajectory.

**Properties:**
- Deterministic: same (seed, secret, service) always yields the same token.
- Unique: different service names yield different tokens.
- One-way: the derived token cannot reveal the master secret.
- Revocable: rotating the master secret invalidates all derived tokens.
- No storage: derivation is computed on demand, not looked up.

### 2.4 Disk Image Security

The topology image is obfuscated with ChaCha20 using the seed as the key.
Each block receives a unique nonce derived from its full route path, ensuring
no keystream reuse. The image header contains only an 8-byte BLAKE2b-keyed
verification tag — enough to reject wrong passwords without leaking any
information about the correct one.

**Measured entropy:** 7.999989 bits/byte (theoretical maximum: 8.000000).
The image is statistically indistinguishable from random data.

---

## 3. Security Analysis

### 3.1 Post-Quantum Security

| Component | Algorithm | Classical Security | Quantum Security (Grover) |
|-----------|-----------|-------------------|--------------------------|
| Key derivation | Argon2id | 256-bit | 128-bit |
| Topology seed | 256-bit | 256-bit | 128-bit |
| Stream cipher | ChaCha20 | 256-bit | 128-bit |
| Verification | BLAKE2b | 256-bit | 128-bit |
| State engine | Topology-projected | 256-bit seed | 128-bit |

The system's security reduces entirely to the Argon2id-derived seed. Grover's
algorithm provides at most a quadratic speedup against symmetric primitives,
yielding a 128-bit post-quantum security level — meeting NIST's Category 1
requirement and exceeding the practical quantum threat horizon.

**No public-key cryptography is used.** There are no RSA keys, no elliptic
curves, no lattice parameters to break. The system is purely symmetric,
making it immune to Shor's algorithm entirely.

### 3.2 Hardware Binding

The hardware key (default: first non-loopback NIC MAC address) is used as the
Argon2id salt. This binds the topology to a specific machine — copying the
image file to another machine produces noise, not secrets.

For portability, users specify a custom hardware key. This enables controlled
migration: copy the image, provide the same password and custom key, and the
topology resolves correctly.

### 3.3 Memory-Hard KDF

Argon2id with 64 MB memory cost makes GPU/ASIC brute-force attacks economically
infeasible. At current cloud GPU pricing (~$0.50/GPU-hour), a brute-force
attack against a 6-word passphrase (77-bit entropy) would cost approximately
$10^12 — exceeding the GDP of most nations.

### 3.4 Attack Surface Comparison

| Attack Vector | Traditional Vault | EFS Vault |
|--------------|-------------------|-----------|
| Network exploitation | API server exposed | No network surface |
| Database breach | Backend (Consul/DDB) | No database |
| Memory dump | Plaintext in RAM | Secrets in topology, paged on demand |
| Side-channel (timing) | API response timing | Local process only |
| Stolen disk image | Encrypted (AES-GCM) | Indistinguishable from noise |
| Cloud account compromise | Full access | No cloud dependency |
| Supply chain | Server + deps | Single static binary |
| Quantum (Shor) | Breaks TLS/key exchange | No public-key crypto used |
| Quantum (Grover) | 128-bit for AES-256 | 128-bit (same) |

---

## 4. Compliance Mapping

### 4.1 NIST SP 800-171 (CUI Protection)

| Control | Requirement | EFS Vault |
|---------|------------|-----------|
| 3.1.13 | Encrypt CUI in transit | N/A (no network) |
| 3.1.19 | Encrypt CUI at rest | Topology obfuscation (ChaCha20) |
| 3.5.3 | Multi-factor authentication | Password + hardware key |
| 3.13.8 | Cryptographic mechanisms | Argon2id + ChaCha20 + BLAKE2b |
| 3.13.11 | FIPS-validated crypto | ChaCha20/BLAKE2b (NIST-approved primitives) |

### 4.2 FIPS 140-3 Path

EFS Vault uses NIST-approved primitives (ChaCha20, BLAKE2b) through libsodium.
A FIPS 140-3 validated deployment would substitute the libsodium calls with a
FIPS-validated cryptographic module (e.g., AWS-LC FIPS, OpenSSL FIPS provider).
The topology architecture itself requires no modification.

### 4.3 PCI-DSS v4.0

| Requirement | Description | EFS Vault |
|-------------|------------|-----------|
| 3.5.1 | Restrict access to cryptographic keys | Hardware-bound, password-protected |
| 3.6.1 | Key management procedures | Version tracking, rotation support |
| 3.7.1 | Key rotation | Built-in rotate command with version history |
| 4.1 | Strong crypto for transmission | N/A (no network transmission) |

### 4.4 FedRAMP / DoD IL4-IL6

EFS Vault's zero-server, air-gapped architecture is inherently compatible with
FedRAMP High and DoD Impact Levels 4-6. No cloud components need authorization.
The binary runs entirely in the customer's boundary.

---

## 5. Performance

Benchmarks on AMD EPYC 7R13 (c6a.xlarge), Ubuntu 22.04:

| Operation | Time | Notes |
|-----------|------|-------|
| Vault open (existing) | ~1.2s | Argon2id dominates |
| Vault open (new) | ~1.2s | Argon2id + topology init |
| Store secret | <1ms | After vault is open |
| Retrieve secret | <1ms | After vault is open |
| Derive token | ~8s | Builds 1M-transition state machine |
| TOTP code | ~8s | Same state machine build |
| Save image | ~50ms | 16 MB ChaCha20 obfuscation |
| Image size (base) | 16 MB | Root + L1 segment tables |
| Image size (1000 secrets) | ~30 MB | Proportional to data |

Derivation time is dominated by the one-time state engine build (1,048,576
transitions). For latency-sensitive deployments, the engine can be cached
across operations in a daemon mode (roadmap).

---

## 6. Deployment Models

### 6.1 CLI (Current)

Single static binary. No installation, no configuration, no daemon.

```bash
# CI/CD pipeline integration
export DB_URL=$(EFS_PASSWORD=$VAULT_PW EFS_HWKEY=$HW efs_vault -q get db-prod)
```

### 6.2 Sidecar (Roadmap)

Unix domain socket listener that holds the topology open and serves secrets
to local processes. Eliminates per-request Argon2id cost.

### 6.3 SDK (Roadmap)

C/C++ library (libefs_vault) for direct integration. Header-only topology
engine for embedded systems.

### 6.4 HSM Integration (Roadmap)

Hardware Security Module integration for hardware key derivation. Compatible
with PKCS#11 and AWS CloudHSM.

---

## 7. Competitive Analysis

### 7.1 vs HashiCorp Vault Enterprise

| Dimension | HashiCorp Vault | EFS Vault |
|-----------|----------------|-----------|
| Architecture | Client-server | Single binary |
| Backend | Consul/Raft/DB | Topology image file |
| Network surface | TCP 8200 + Consul | None |
| Unsealing | Shamir shares / auto-unseal | Password + hardware key |
| Post-quantum | No | Yes (128-bit PQ) |
| Air-gapped | Partial | Full |
| Credential derivation | No (static secrets only) | Yes (topology state engine) |
| Pricing (250 seats) | ~$250K/year | $120K/year |
| Dependencies | Go runtime, Consul, TLS certs | None (static binary) |

### 7.2 vs AWS Secrets Manager

| Dimension | AWS SM | EFS Vault |
|-----------|--------|-----------|
| Cloud dependency | Required (AWS) | None |
| Air-gapped | No | Yes |
| Cost (1000 secrets) | ~$4,800/year + API calls | $0 (under $3M) or license |
| Hardware binding | No | Yes |
| Post-quantum | No | Yes |
| Vendor lock-in | High | None |

### 7.3 vs CyberArk

| Dimension | CyberArk | EFS Vault |
|-----------|----------|-----------|
| Architecture | Server + agents | Single binary |
| Deployment time | Weeks-months | Minutes |
| Air-gapped | Partial (on-prem) | Full |
| Post-quantum | No | Yes |
| Pricing | $500K-$2M+ | $120K-$480K |
| Complexity | High (50+ components) | Minimal (1 binary) |

---

## 8. Roadmap

| Quarter | Feature |
|---------|---------|
| Q2 2026 | EFS Vault 1.0 GA, Enterprise licensing |
| Q3 2026 | Sidecar daemon mode, Kubernetes secrets driver |
| Q4 2026 | C/C++ SDK (libefs_vault), Python bindings |
| Q1 2027 | FIPS 140-3 validation (Level 1) |
| Q2 2027 | HSM integration (PKCS#11, CloudHSM) |
| Q3 2027 | Multi-vault federation, audit logging |
| Q4 2027 | FIPS 140-3 Level 2 (tamper-evident) |

---

## 9. About Emergence Systems

Emergence Systems builds cryptographic infrastructure where the data structure
is the security mechanism. Founded by Nicholas Bumgarner, the company's core
technology — the self-routing topology — represents a fundamental advance in
how secrets, credentials, and sensitive data are stored and computed.

**Contact:**
- Licensing: licensing@emergence.systems
- Technical: engineering@emergence.systems  
- Web: https://emergence.systems

---

*This document contains forward-looking statements about product features and
timelines. Actual results may vary. Cryptographic claims are based on current
understanding of the referenced algorithms and may be affected by future
cryptanalytic advances.*
