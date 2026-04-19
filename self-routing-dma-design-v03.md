# Self-Routing DMA State Machine
## Design Document v0.3

---

## Core Concept

The CPU is not a compute engine. It is an address generator.
DMA is not a data mover. It is the execution engine.
The data is not passive. It routes itself.

---

## Target Hardware

**Dell Precision T7400**
- Dual Xeon (Harpertown), 3 GHz, 8 cores total
- Instruction set: SSE4.1 (128-bit XMM registers)
- NOTE: No AVX/AVX-512 support. "512-bit wide" is not
  available on this chipset. The widest native register
  is 128-bit via SSE. This is fine — 128-bit values
  map perfectly to one XMM register each.
- DDR2 ECC RAM
- Chipset: Intel 5400 (Seaburg)

**Core Allocation**
- Core 0: Address engine (tight bitwise loop, lives in L1)
- Core 1: Frame controller + pressure monitor
- Cores 2-7: Available for user workloads / mesh nodes

---

## Boot Sequence: Seed Derivation

### The Boot Prompt

```
EmergenceOS Boot v0.1
=====================

Password: ********

Hardware Key
  Auto-detected: A7F3-91CB-D4E8-B2C1
  [ENTER to accept, or type custom key]

Hardware Key: _
```

**Three modes:**
1. Press ENTER → accept auto-detected HWID (daily use)
2. Type a custom key → use any arbitrary string (portable mode)
3. Paste old HWID → migrate data from previous hardware

### Seed Derivation

```cpp
#include <cstdint>
#include <cstring>

struct SeedState {
    uint64_t hi;
    uint64_t lo;
};  // 128-bit seed

struct SeedDerivation {
    static constexpr uint32_t ROUNDS = 250000; // ~1-2 sec on 3GHz Xeon

    static SeedState derive(const uint8_t* password, size_t pw_len,
                            const uint8_t* hwkey, size_t hk_len) {

        // FNV-1a into two 64-bit halves
        uint64_t hi = 0xCBF29CE484222325ULL; // FNV offset basis
        uint64_t lo = 0x100000001B3ULL;       // FNV prime as second seed

        for (size_t i = 0; i < pw_len; i++) {
            hi ^= password[i];
            hi *= 0x100000001B3ULL;
            lo ^= password[i];
            lo *= 0x00000100000001B3ULL;
        }
        for (size_t i = 0; i < hk_len; i++) {
            hi ^= hwkey[i];
            hi *= 0x100000001B3ULL;
            lo ^= hwkey[i];
            lo *= 0x00000100000001B3ULL;
        }

        // Key stretching
        for (uint32_t r = 0; r < ROUNDS; r++) {
            hi = ((hi << 31) | (hi >> 33)) ^ (lo * 0x9E3779B97F4A7C15ULL);
            lo = ((lo << 29) | (lo >> 35)) ^ (hi * 0x517CC1B727220A95ULL);
        }

        return {hi, lo};
    }
};
```

### Security Properties

**Same password + same key = same topology every boot.**
Perfectly reproducible. No key file on disk.

**Wrong password OR wrong key = wrong topology.**
All 1,024 root entries change. The disk looks like random noise.
There is nothing to "decrypt" — the structure doesn't exist
without the correct seed.

**No separate encryption layer.**
The topology IS the encryption. Without the seed, there are
no files, no directories, no structure — just noise.

**Editable HWID = portable security.**
You control the binding. Lock to hardware for maximum security,
use a custom phrase for portability, or paste an old key to migrate.

---

## 1,024 Orthogonal Lenses

Each of the 1,024 lenses is a distinct transform function.
All are derived from the master seed but must be statistically
independent — correlation between lenses = exploitable weakness.

```cpp
struct LensKey {
    uint64_t hi;
    uint64_t lo;
};

void generate_lens_keys(SeedState master, LensKey lens_keys[1024]) {
    for (int i = 0; i < 1024; i++) {
        uint64_t mix_hi = master.hi ^ (uint64_t)i;
        uint64_t mix_lo = master.lo ^ ((uint64_t)i << 32);

        for (int r = 0; r < 64; r++) {
            mix_hi = ((mix_hi << 7) | (mix_hi >> 57))
                     ^ (mix_lo * 0x9E3779B97F4A7C15ULL);
            mix_lo = ((mix_lo << 11) | (mix_lo >> 53))
                     ^ (mix_hi * 0x517CC1B727220A95ULL);
            mix_hi += (uint64_t)i;
        }

        lens_keys[i] = {mix_hi, mix_lo};
    }
}
```

**Validation:** chi-squared test across all 1,024 outputs
to confirm no pairwise correlation.

---

## Self-Routing Value Format (128-bit)

Each value is 128 bits = 16 bytes = fits in one XMM register.

```
┌────────────────────────────────────────────────────────────┐
│ 127 ... 118 │ 117 116 │ 115 ... 0                        │
│ ROUTE (10)  │ CRC (2) │ PAYLOAD (116 bits)               │
└────────────────────────────────────────────────────────────┘

ROUTE   = Top 10 bits. Selects next root table entry (0-1023).
          This IS the branch decision. No CPU evaluation needed.

CRC     = 2-bit mini-checksum over payload.
          DMA verifies before chaining. Bad CRC = halt.

PAYLOAD = 116 bits = 14.5 bytes of usable data per hop.
```

### Reserved Routes
```cpp
constexpr uint16_t HALT_ROUTE  = 0x3FF; // 1023 = end of chain
constexpr uint16_t ERROR_ROUTE = 0x3FE; // 1022 = error handler
constexpr uint16_t FREE_ROUTE  = 0x3FD; // 1021 = unallocated
```

---

## Memory Layout: 8-Level Nesting

### Structure

```
Level 0: Root Table          1 block           16 KB
Level 1: Lens Blocks         1,024 blocks      16 MB
Level 2: Sub-blocks          1,048,576 blocks  16 GB (virtual)
Level 3-7: Deeper nesting    Lazily expanded
```

Each block = 1,024 entries × 16 bytes = 16,384 bytes (16 KB)

### Addressing: 8 Hops

```
Hop 1: root[ROUTE]           → Level 1 block pointer
Hop 2: block[ROUTE]          → Level 2 block pointer
Hop 3: sub-block[ROUTE]      → Level 3 block pointer
Hop 4: ...                   → Level 4
Hop 5: ...                   → Level 5
Hop 6: ...                   → Level 6
Hop 7: ...                   → Level 7
Hop 8: terminal value        → PAYLOAD is final data
```

### Addressable Space

8 levels × 10 route bits per level = 80 bits of address space.
That's 2^80 = ~1.2 × 10^24 possible terminal locations.

Obviously not all populated. The power is in selective expansion.

### Eager vs Lazy Expansion Strategy

**Boot (eager): Expand levels 0-3**
- Level 0: 1 root table = 16 KB (instant)
- Level 1: 1,024 blocks = 16 MB (~milliseconds)
- Level 2: 1,048,576 blocks = 16 GB (limited by physical RAM)
- Level 3: Only partially — fill what RAM allows

Actual boot expansion bounded by physical RAM.
On T7400 with (estimated) 16-32 GB DDR2:
  Levels 0-2 fully expanded = ~16 GB
  Level 3+ = lazy, materialized on first access

**Runtime (lazy): Levels 4-7**
- Expanded on demand when DMA chain reaches an empty pointer
- CPU detects null pointer in chain → expands that branch
- First-access latency, but subsequent access is instant

**Boot time estimate:**
At 3 GHz, generating ~1M blocks of 1,024 entries each:
~1 billion bitwise operations = ~1-3 seconds.
Acceptable tradeoff for near-instant runtime.

---

## The CPU Loop (Core 0 — Address Engine)

The entire program running on Core 0. Lives in L1 cache.

```cpp
struct State128 {
    uint64_t hi;
    uint64_t lo;
};

constexpr uint64_t PHI_HI = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t PHI_LO = 0x517CC1B727220A95ULL;
constexpr uint16_t LENS_MASK = 0x3FF;

void address_engine(SeedState seed, volatile uint64_t* dma_cmd_reg) {
    State128 state = {seed.hi, seed.lo};

    while (true) {
        // One 128-bit bitwise operation: rotate + XOR both halves
        state.hi = ((state.hi << 13) | (state.hi >> 51))
                   ^ (state.lo * PHI_HI);
        state.lo = ((state.lo << 17) | (state.lo >> 47))
                   ^ (state.hi * PHI_LO);

        // Extract route from top 10 bits of hi
        uint16_t route = (uint16_t)(state.hi >> 54) & LENS_MASK;

        // Write to DMA command register. CPU is done.
        *dma_cmd_reg = route;
    }
}
```

**Properties:**
- ~8 instructions per iteration
- Fits entirely in L1 instruction cache
- State fits in two general-purpose registers (or one XMM)
- CPU never reads from main memory
- CPU never sees payload data

---

## Frame Rotation (Core 1 — Frame Controller)

Core 1 runs the 10-frame cycle, controlling what Core 0's
addresses are used for and monitoring system pressure.

```
Frame  1: INTERFACE  - Route addresses to output buffers
Frame  2: ROUTE      - Route addresses for DMA chain setup
Frame  3: MEMORY     - Route addresses for page management
Frame  4: INTERFACE  - Output sync
Frame  5: ROUTE      - Route recalculation
Frame  6: MEMORY     - Reclamation sweep
Frame  7: INTERFACE  - Output sync
Frame  8: ROUTE      - Pressure-adapted routing
Frame  9: MEMORY     - Defragmentation / lazy expansion
Frame 10: PULSE      - Reset state, clear stale chains
```

### Pressure-Adaptive Frame (Frame 8)

```cpp
// Core 1 reads hardware state and biases Core 0's seed
void pressure_frame(volatile State128* shared_state) {
    // Read actual hardware sensors
    uint32_t thermal = read_msr(IA32_THERM_STATUS);
    uint32_t queue   = read_dma_queue_depth();

    // Combine into pressure value
    uint64_t pressure = ((uint64_t)thermal << 32) | queue;

    // XOR into Core 0's state to bias route selection
    // This steers DMA chains away from hot/congested regions
    __atomic_fetch_xor(&shared_state->lo, pressure, __ATOMIC_RELAXED);
}
```

### Reclamation Frame (Frame 6)

```cpp
// Core 1 triggers garbage collection of orphaned blocks
void reclamation_frame(TopologyState* topo) {
    // Walk reachable set from root
    // Any allocated block not reachable = orphan → free it
    // Runs incrementally — one subtree per frame cycle
    topo->sweep_next_subtree();
}
```

---

## DMA Chain Execution (8-Hop)

Once Core 0 writes a root index, DMA chains autonomously
through up to 8 levels:

```
Step 1:  CPU writes route index 742 to DMA command register
Step 2:  DMA reads root[742] → Level 1 pointer P1
Step 3:  DMA reads P1[ROUTE from value] → Level 2 pointer P2
Step 4:  DMA reads P2[ROUTE] → Level 3 pointer P3
Step 5:  DMA reads P3[ROUTE] → Level 4 pointer P4
Step 6:  DMA reads P4[ROUTE] → Level 5 pointer P5
Step 7:  DMA reads P5[ROUTE] → Level 6 pointer P6
Step 8:  DMA reads P6[ROUTE] → Level 7 pointer P7
Step 9:  DMA reads P7[ROUTE] → Terminal value
Step 10: Extract PAYLOAD (116 bits) → deliver to output buffer

Total: 8 memory reads, zero CPU involvement after Step 1.
```

### Chain Termination

A chain stops when:
- HALT_ROUTE (0x3FF) is encountered at any level
- CRC check fails (corruption detected)
- Null pointer at any level (unexpanded lazy branch)
- Pulse frame fires (Frame 10 clears all active chains)

### Null Pointer = Lazy Expansion Trigger

```cpp
// When DMA hits a null pointer, it interrupts Core 1
void handle_lazy_expansion(uint8_t level, uint32_t parent_index,
                           uint16_t route, TopologyState* topo) {
    // Expand this one branch on demand
    uint128_t* new_block = topo->allocate_block();
    expand_single_branch(topo->lens_keys[route], new_block);

    // Patch parent to point to new block
    topo->set_child(level - 1, parent_index, route, new_block);

    // Restart the DMA chain from this point
    restart_dma_chain(level, new_block, route);
}
```

---

## MSB Gating: How Branching Works

The data IS the condition IS the address.

```
Value: 0x_B9A3_..._1234 (128-bit)
       ^^^^
       Route = top 10 bits = 0x2E6 = root entry 742

Value: 0x_0053_..._1234 (128-bit)
       ^^^^
       Route = top 10 bits = 0x001 = root entry 1

Same payload, different MSB = different execution path.
The branch decision is IN the data, not evaluated BY the CPU.
```

At each of 8 levels, 10 bits select the next hop.
Total branching capacity: 1024^8 = 2^80 possible paths.

---

## Storage Model: Hybrid COW + Mutable Pages

### Topology Regions

```
Root Table (1,024 entries):
┌──────────────────────────────────────────────────┐
│ root[0..63]      = System / kernel (COW)         │
│ root[64..511]    = User files (COW)              │
│ root[512..899]   = Working memory (Mutable Pages)│
│ root[900..1020]  = Free pool                     │
│ root[1021]       = FREE sentinel                 │
│ root[1022]       = ERROR handler chain           │
│ root[1023]       = HALT sentinel                 │
└──────────────────────────────────────────────────┘
```

### Copy-on-Write Region (root 0-511): Persistent Data

For files and system data. Never modify in place.

```cpp
void write_file_cow(TopologyState* topo, uint16_t root_index,
                    const uint8_t* data, size_t len) {

    // 1. Allocate new chain
    size_t bytes_per_hop = 14; // 116 payload bits ≈ 14 usable bytes
    size_t hops_needed = (len / bytes_per_hop) + 1;

    // 2. Build chain with route + payload packed per value
    uint128_t* chain = build_chain(topo->lens_keys[root_index],
                                   data, len, hops_needed);

    // 3. Atomic pointer swap at root
    uint128_t* old_chain = topo->swap_root(root_index, chain);

    // 4. Old chain orphaned — reclamation sweep frees it
    //    Until then, old data is still readable (versioning)
}
```

**Properties:**
- Crash-safe: old chain valid until swap completes
- Natural versioning: keep N old chains before reclaiming
- No corruption risk during writes

### Mutable Page Region (root 512-899): Working Memory

For scratch space, caches, runtime state. Fast random writes.

```
128-bit value in mutable region:
┌──────────┬──────────────────────────────────────┐
│ ROUTE(10)│ PAGE_POINTER (118 bits)              │
└──────────┴──────────────────────────────────────┘
                    │
                    ▼
           ┌────────────────┐
           │ Mutable Page   │ ← Standard read/write
           │ (16 KB)        │ ← DMA writes directly
           │                │ ← Route structure untouched
           └────────────────┘
```

Routes stay frozen. Only the target pages change.
One extra DMA hop per access (pointer dereference).

### Storage Capacity (128-bit, 8 levels)

Per-hop payload: 116 bits ≈ 14.5 bytes

**COW region (512 root entries, up to 8 levels deep):**
- Shallow file (2 levels): 512 × 1024 × 14.5B ≈ 7.3 GB
- Deep file (4 levels): effectively unlimited for single files
- Total capacity bounded by physical disk, not addressing

**Mutable region (388 root entries):**
- Each points to a 16KB mutable page
- 388 × 16KB = ~6 MB of fast scratch space
- Can nest deeper for more: 388 × 1024 × 16KB = ~6 GB

### Persistence

```cpp
void flush_topology(const char* image_path, TopologyState* topo) {
    int fd = open(image_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    // Write contiguous image — root table + all expanded blocks
    write(fd, topo->root, ROOT_SIZE);
    for (int level = 0; level < 8; level++) {
        topo->write_expanded_blocks(fd, level);
    }
    // Write mutable pages
    topo->write_mutable_pages(fd);

    fsync(fd);
    close(fd);
}
```

**The disk image without the seed is random noise.**
No header. No magic bytes. No filesystem signature.
No forensic tool can identify it as structured data.

---

## Error Handling

### The Cascade Problem

A single bit flip in a self-routing value corrupts the route,
the CRC, and the payload simultaneously. In an 8-level chain,
corruption at level 2 sends the remaining 6 hops into garbage.

### Mitigations

**1. CRC-2 per value**
2-bit checksum embedded in every 128-bit value.
DMA checks before following route. Bad CRC = halt chain.
Catches ~75% of single-bit errors.

**2. ECC RAM (already on T7400)**
Hardware-level single-bit correction, double-bit detection.
This is your first line of defense. Non-negotiable for this arch.

**3. Sentinel boundaries**
Reserved routes (HALT, ERROR, FREE) catch runaway chains.
Any chain that hits FREE_ROUTE is traversing uninitialized
space — halt and report.

**4. Dual-rail verification (optional, expensive)**
Run two DMA chains from same root, compare at each level.
Divergence = corruption. Cost: 2× DMA bandwidth.

**5. Chain depth limit**
Hardware counter: if DMA exceeds 8 hops without hitting
HALT, force-terminate. Prevents infinite loops from
corruption creating circular routes.

---

## What This Can Express

**Well-suited workloads:**
- Permutation / sorting (data rearrangement)
- Hash computation (bitwise transform chains)
- Encryption / decryption (the topology IS encryption)
- Signal routing / switching
- Deterministic state machines (protocol engines)
- Pattern matching (route to handler via MSB)
- Secure storage (no-structure-without-seed)

**Poorly-suited workloads:**
- Floating point math (no FPU in DMA path)
- Dynamic string processing (variable-length data)
- Arbitrary conditionals beyond 1024-way branch
- Workloads requiring data-dependent computation
  (CPU never sees the data it's routing)

---

## Open Questions

1. **DMA chaining depth:** The Intel 5400 chipset's DMA
   controller has a finite scatter-gather list size.
   Can it chain 8 reads autonomously, or does the CPU
   need to re-kick partway through? Needs datasheet review.

2. **Lazy expansion latency:** When DMA hits a null pointer
   at level 5, how fast can Core 1 expand that branch
   and restart the chain? Target: < 1 frame (< 10ms).

3. **Mutable page size:** 16KB matches the block size.
   Would smaller pages (4KB, matching x86 page size)
   be more efficient for the hardware MMU?

4. **Pressure sensor access:** Reading thermal MSRs
   requires Ring 0. Boot sequence must configure
   MSR access before the frame controller starts.

5. **Seed derivation hardening:** Current FNV + stretching
   is a placeholder. Production should use Argon2id
   with memory-hard parameters. Estimated 1-2 sec
   derivation time at boot is acceptable per Nick.

6. **Multi-machine mesh:** When T7400 and Fold 6 connect
   via Tailscale, do they share a seed? Separate seeds
   with a key-exchange layer? Or does the root table
   have a "remote" region that maps to the other device?

---

## Next Steps

1. Research Intel 5400 DMA scatter-gather capabilities
2. Prototype 128-bit root table + self-routing values (userspace C++)
3. Benchmark 128-bit bitwise loop to confirm L1 residency on Xeon
4. Test orthogonality of 1,024 lens keys (chi-squared)
5. Prototype boot prompt: password + editable HWID
6. Build COW write path with atomic root pointer swap
7. Build reclamation sweep (incremental, one subtree per frame)
8. Entropy test: verify disk image is indistinguishable from random
9. Boot into 64-bit long mode on T7400 (prerequisite for deployment)
