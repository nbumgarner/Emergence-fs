#ifndef EMERGENCE_TOPOLOGY_HPP
#define EMERGENCE_TOPOLOGY_HPP

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <memory>
#include <algorithm>

namespace Emergence {

// ============================================================
// Constants
// ============================================================

constexpr int      LENS_COUNT        = 1024;
constexpr uint16_t LENS_MASK         = 0x3FF;
constexpr uint16_t HALT_ROUTE        = 0x3FF;
constexpr uint16_t ERROR_ROUTE       = 0x3FE;
constexpr uint16_t FREE_ROUTE        = 0x3FD;
constexpr uint64_t PHI_HI            = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t PHI_LO            = 0x517CC1B727220A95ULL;
constexpr size_t   ENTRIES_PER_BLOCK = 1024;
constexpr size_t   PAYLOAD_BYTES_PER_HOP = 13;
constexpr size_t   BLOCK_SIZE_BYTES  = ENTRIES_PER_BLOCK * 16; // 16 KB
constexpr size_t   BYTES_PER_BLOCK   = ENTRIES_PER_BLOCK * PAYLOAD_BYTES_PER_HOP; // ~13 KB

constexpr uint32_t KDF_ROUNDS        = 250000;
constexpr size_t   KDF_MEM_BLOCKS    = 1024;
constexpr uint32_t KDF_MEM_PASSES    = 4;

// Maximum L2 blocks per L1 slot (= entries per block)
constexpr size_t   MAX_L2_PER_SLOT   = ENTRIES_PER_BLOCK;

// Per-slot capacity: 1024 L2 blocks × ~13KB = ~13 MB
constexpr size_t   BYTES_PER_SLOT    = MAX_L2_PER_SLOT * BYTES_PER_BLOCK;

// ============================================================
// 128-bit value
// ============================================================

struct Value128 {
    uint64_t hi;
    uint64_t lo;

    Value128() : hi(0), lo(0) {}
    Value128(uint64_t h, uint64_t l) : hi(h), lo(l) {}

    uint16_t route() const {
        return (uint16_t)(hi >> 54) & LENS_MASK;
    }

    uint8_t compute_crc() const {
        uint64_t payload_hi = hi & 0x000FFFFFFFFFFFFFULL;
        uint64_t fold = payload_hi ^ lo;
        fold ^= (fold >> 32); fold ^= (fold >> 16);
        fold ^= (fold >> 8);  fold ^= (fold >> 4);
        fold ^= (fold >> 2);
        return (uint8_t)(fold & 0x03);
    }

    void pack_route(uint16_t r) {
        hi &= 0x000FFFFFFFFFFFFFULL;
        hi |= ((uint64_t)(r & LENS_MASK) << 54);
        uint8_t c = compute_crc();
        hi |= ((uint64_t)(c & 0x03) << 52);
    }

    size_t get_payload(uint8_t* out, size_t max_bytes) const {
        size_t copied = 0;
        for (size_t i = 0; i < 8 && copied < max_bytes; i++, copied++)
            out[copied] = (uint8_t)(lo >> (i * 8));
        for (size_t i = 0; i < 5 && copied < max_bytes; i++, copied++)
            out[copied] = (uint8_t)(hi >> (i * 8));
        return copied;
    }

    void set_payload(const uint8_t* data, size_t len) {
        lo = 0;
        uint64_t top_bits = hi & 0xFFF0000000000000ULL;
        hi = 0;
        size_t pos = 0;
        for (size_t i = 0; i < 8 && pos < len; i++, pos++)
            lo |= ((uint64_t)data[pos] << (i * 8));
        for (size_t i = 0; i < 5 && pos < len; i++, pos++)
            hi |= ((uint64_t)data[pos] << (i * 8));
        hi |= top_bits;
    }

    void write_to(uint8_t* buf) const {
        memcpy(buf, &lo, 8);
        memcpy(buf + 8, &hi, 8);
    }

    void read_from(const uint8_t* buf) {
        memcpy(&lo, buf, 8);
        memcpy(&hi, buf + 8, 8);
    }
};

// ============================================================
// Seed
// ============================================================

struct Seed {
    uint64_t hi;
    uint64_t lo;
};

// ============================================================
// Memory-hard Key Derivation (Argon2id)
// ============================================================

struct KeyDerivation {
    static Seed derive(const char* password, const char* hwkey) {
        std::string combined = std::string(password) + "|" + hwkey;
        uint8_t seed_bytes[32];
        uint8_t salt[crypto_pwhash_SALTBYTES];
        
        // Generate deterministic salt from hardware key
        crypto_generichash(salt, sizeof(salt), (const uint8_t*)hwkey, strlen(hwkey), NULL, 0);

        if (crypto_pwhash(seed_bytes, 32, combined.c_str(), combined.size(), salt,
                          crypto_pwhash_OPSLIMIT_INTERACTIVE, 
                          crypto_pwhash_MEMLIMIT_INTERACTIVE,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            throw std::runtime_error("Argon2id derivation failed");
        }

        Seed s;
        memcpy(&s.hi, seed_bytes, 8);
        memcpy(&s.lo, seed_bytes + 8, 8);
        
        // Securely clear temporary buffer
        sodium_memzero(seed_bytes, sizeof(seed_bytes));
        
        return s;
    }
};

// ============================================================
// Lens
// ============================================================

struct LensKey { uint64_t hi, lo; };

struct LensGenerator {
    static void generate(Seed master, LensKey keys[LENS_COUNT]) {
        uint8_t prk[32] = {0};
        memcpy(prk, &master.hi, 8);
        memcpy(prk + 8, &master.lo, 8);
        
        for (int i = 0; i < LENS_COUNT; i++) {
            uint8_t info[8] = {0};
            memcpy(info, &i, 4);
            // Domain separation
            info[4] = 'L'; info[5] = 'E'; info[6] = 'N'; info[7] = 'S';
            
            uint8_t out[16];
            crypto_generichash(out, 16, info, 8, prk, 32);
            
            memcpy(&keys[i].hi, out, 8);
            memcpy(&keys[i].lo, out + 8, 8);
        }
        sodium_memzero(prk, sizeof(prk));
    }
};

// ============================================================
// Block: 1024 entries × 16 bytes = 16 KB
// ============================================================

struct Block {
    Value128 entries[ENTRIES_PER_BLOCK];

    Block() {
        for (size_t i = 0; i < ENTRIES_PER_BLOCK; i++) {
            entries[i] = Value128();
            entries[i].pack_route(FREE_ROUTE);
        }
    }

    void serialize(uint8_t* buf) const {
        for (size_t i = 0; i < ENTRIES_PER_BLOCK; i++)
            entries[i].write_to(buf + i * 16);
    }

    void deserialize(const uint8_t* buf) {
        for (size_t i = 0; i < ENTRIES_PER_BLOCK; i++)
            entries[i].read_from(buf + i * 16);
    }
};

// ============================================================
// L2 address: identifies an L2 data block
// ============================================================

struct L2Addr {
    uint16_t l1_slot;   // Which L1 segment table
    uint16_t l2_index;  // Entry within that L1 block

    bool operator==(const L2Addr& o) const {
        return l1_slot == o.l1_slot && l2_index == o.l2_index;
    }
};

struct L2AddrHash {
    size_t operator()(const L2Addr& a) const {
        return std::hash<uint32_t>()(((uint32_t)a.l1_slot << 16) | a.l2_index);
    }
};

// ============================================================
// Topology: 3-level structure
//
// Level 0: Root block (1 block, 1024 entries)
//          - Reserved for filesystem metadata
//
// Level 1: Segment tables (1024 blocks, eagerly allocated)
//          - Each L1 block is a segment table
//          - Each entry can reference an L2 data block
//          - L1 entry route = index of next used entry (chain)
//          - L1 entry payload byte 0-1 = L2 block count marker
//
// Level 2: Data blocks (lazily allocated)
//          - Addressed by (l1_slot, l2_index)
//          - Each holds ~13 KB of file data
//          - Allocated on demand when data is written
//
// Capacity per slot: 1024 L2 blocks × 13 KB = ~13 MB
// Total capacity: 1020 slots × 13 MB = ~13 GB
// ============================================================

class Topology {
private:
    Seed seed_;
    LensKey lens_keys_[LENS_COUNT];
    Block root_;
    std::vector<std::unique_ptr<Block>> level1_;  // Segment tables
    std::unordered_map<L2Addr, std::unique_ptr<Block>, L2AddrHash> level2_; // Data blocks
    bool dirty_;

    // Generate deterministic initial state for an L2 block
    void init_l2_block(Block* block, uint16_t l1_slot, uint16_t l2_index) {
        // Derive from lens key + l2 index for deterministic noise
        LensKey& lk = lens_keys_[l1_slot];
        uint64_t sh = lk.hi ^ ((uint64_t)l2_index * PHI_LO);
        uint64_t sl = lk.lo ^ ((uint64_t)l2_index * PHI_HI);

        for (size_t j = 0; j < ENTRIES_PER_BLOCK; j++) {
            sh = ((sh << 13) | (sh >> 51)) ^ (sl * PHI_HI);
            sl = ((sl << 17) | (sl >> 47)) ^ (sh * PHI_LO);
            Value128 v; v.hi = sh; v.lo = sl;
            v.pack_route(FREE_ROUTE);
            block->entries[j] = v;
        }
    }

    // Get or create an L2 data block
    Block* get_or_create_l2(uint16_t l1_slot, uint16_t l2_index) {
        L2Addr addr = {l1_slot, l2_index};
        auto it = level2_.find(addr);
        if (it != level2_.end())
            return it->second.get();

        // Lazy allocation
        auto block = std::make_unique<Block>();
        init_l2_block(block.get(), l1_slot, l2_index);
        Block* ptr = block.get();
        level2_[addr] = std::move(block);
        dirty_ = true;
        return ptr;
    }

    const Block* get_l2(uint16_t l1_slot, uint16_t l2_index) const {
        L2Addr addr = {l1_slot, l2_index};
        auto it = level2_.find(addr);
        if (it != level2_.end())
            return it->second.get();
        return nullptr;
    }

public:
    Topology() : dirty_(false) { level1_.resize(LENS_COUNT); }

    void initialize(Seed s) {
        seed_ = s;
        LensGenerator::generate(seed_, lens_keys_);
        root_ = Block();
        level2_.clear();

        for (int i = 0; i < LENS_COUNT; i++) {
            level1_[i] = std::make_unique<Block>();
            // Initialize L1 as segment tables (all entries FREE)
            LensKey& lk = lens_keys_[i];
            uint64_t sh = lk.hi, sl = lk.lo;
            for (size_t j = 0; j < ENTRIES_PER_BLOCK; j++) {
                sh = ((sh << 13) | (sh >> 51)) ^ (sl * PHI_HI);
                sl = ((sl << 17) | (sl >> 47)) ^ (sh * PHI_LO);
                Value128 v; v.hi = sh; v.lo = sl;
                v.pack_route(FREE_ROUTE);
                level1_[i]->entries[j] = v;
            }
        }
        dirty_ = true;
    }

    // --------------------------------------------------------
    // Slot-based data operations
    //
    // A "slot" is an L1 index. Data written to a slot is
    // automatically distributed across L2 data blocks.
    // The caller doesn't need to know about L2.
    // --------------------------------------------------------

    // Write data to a slot. Allocates L2 blocks as needed.
    // Returns bytes written.
    size_t write_slot(uint16_t l1_slot, const uint8_t* data, size_t len) {
        if (l1_slot >= LENS_COUNT) return 0;

        size_t written = 0;
        uint16_t l2_idx = 0;

        while (written < len && l2_idx < MAX_L2_PER_SLOT) {
            Block* l2 = get_or_create_l2(l1_slot, l2_idx);

            // Write up to BYTES_PER_BLOCK into this L2 block
            size_t to_write = std::min(BYTES_PER_BLOCK, len - written);
            size_t w = write_block_data(l2, data + written, to_write);
            written += w;
            l2_idx++;
        }

        // Update L1 segment table: mark how many L2 blocks are used
        // Store count in first entry's payload
        if (level1_[l1_slot]) {
            uint8_t count_buf[2];
            count_buf[0] = (uint8_t)(l2_idx & 0xFF);
            count_buf[1] = (uint8_t)((l2_idx >> 8) & 0xFF);
            level1_[l1_slot]->entries[0].set_payload(count_buf, 2);
            level1_[l1_slot]->entries[0].pack_route(l2_idx > 0 ? 0 : FREE_ROUTE);
        }

        dirty_ = true;
        return written;
    }

    // Read data from a slot.
    size_t read_slot(uint16_t l1_slot, uint8_t* out, size_t max_len) const {
        if (l1_slot >= LENS_COUNT) return 0;

        // Get L2 block count from L1 segment table
        uint16_t l2_count = get_l2_count(l1_slot);
        if (l2_count == 0) return 0;

        size_t total = 0;
        for (uint16_t l2_idx = 0; l2_idx < l2_count && total < max_len; l2_idx++) {
            const Block* l2 = get_l2(l1_slot, l2_idx);
            if (!l2) break;

            size_t r = read_block_data(l2, out + total, max_len - total);
            total += r;
            if (r < BYTES_PER_BLOCK) break; // End of data
        }
        return total;
    }

    // Clear a slot: free all its L2 blocks
    void clear_slot(uint16_t l1_slot) {
        if (l1_slot >= LENS_COUNT) return;

        uint16_t l2_count = get_l2_count(l1_slot);
        for (uint16_t i = 0; i < l2_count; i++) {
            L2Addr addr = {l1_slot, i};
            level2_.erase(addr);
        }

        // Reset L1 segment entry
        if (level1_[l1_slot]) {
            level1_[l1_slot]->entries[0].set_payload(nullptr, 0);
            level1_[l1_slot]->entries[0].pack_route(FREE_ROUTE);
        }
        dirty_ = true;
    }

    // Get number of L2 blocks used by a slot
    uint16_t get_l2_count(uint16_t l1_slot) const {
        if (l1_slot >= LENS_COUNT || !level1_[l1_slot]) return 0;
        const Value128& seg = level1_[l1_slot]->entries[0];
        if (seg.route() == FREE_ROUTE) return 0;

        uint8_t buf[2] = {0, 0};
        seg.get_payload(buf, 2);
        return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    }

    // Total L2 blocks currently allocated
    size_t total_l2_blocks() const { return level2_.size(); }

    // --------------------------------------------------------
    // Single-block data read/write (used internally and for
    // metadata in block 0 via legacy interface)
    // --------------------------------------------------------

    // Write data into a block's entries as chained payloads
    // Route 0 = CONTINUE (next sequential entry)
    // HALT_ROUTE = end of data
    // FREE_ROUTE = unused entry
    static size_t write_block_data(Block* block, const uint8_t* data, size_t len) {
        size_t written = 0, entry = 0;

        while (written < len && entry < ENTRIES_PER_BLOCK) {
            size_t chunk = std::min(PAYLOAD_BYTES_PER_HOP, len - written);
            Value128& v = block->entries[entry];
            v.set_payload(data + written, chunk);
            if (written + chunk < len && entry + 1 < ENTRIES_PER_BLOCK)
                v.pack_route(0); // CONTINUE: more data follows
            else
                v.pack_route(HALT_ROUTE);
            written += chunk;
            entry++;
        }
        while (entry < ENTRIES_PER_BLOCK) {
            block->entries[entry].pack_route(FREE_ROUTE);
            entry++;
        }
        return written;
    }

    // Read chained data from a block
    static size_t read_block_data(const Block* block, uint8_t* out, size_t max_len) {
        size_t total = 0, entry = 0;

        while (total < max_len && entry < ENTRIES_PER_BLOCK) {
            const Value128& v = block->entries[entry];
            uint16_t route = v.route();

            if (route == FREE_ROUTE) break; // Unwritten entry

            uint8_t payload[PAYLOAD_BYTES_PER_HOP];
            size_t got = v.get_payload(payload, PAYLOAD_BYTES_PER_HOP);
            size_t cp = std::min(got, max_len - total);
            memcpy(out + total, payload, cp);
            total += cp;

            if (route == HALT_ROUTE) break; // Last entry with data
            entry++; // CONTINUE: next sequential entry
        }
        return total;
    }

    // Legacy single-slot convenience (for metadata block)
    size_t write_chain(uint16_t slot, const uint8_t* data, size_t len) {
        return write_slot(slot, data, len);
    }
    size_t read_chain(uint16_t slot, uint8_t* out, size_t max_len) const {
        return read_slot(slot, out, max_len);
    }

    // --------------------------------------------------------
    // Serialization
    //
    // Image format v5:
    //   [8 bytes]  Verify tag
    //   [8 bytes]  Version (5)
    //   [16 KB]    Root block
    //   [16 MB]    L1 segment tables (1024 × 16 KB)
    //   [8 bytes]  L2 block count
    //   For each L2 block:
    //     [2 bytes] l1_slot
    //     [2 bytes] l2_index
    //     [4 bytes] reserved (alignment)
    //     [16 KB]   block data
    // --------------------------------------------------------

    bool save_image(const char* path) const {
        FILE* fp = fopen(path, "wb");
        if (!fp) return false;

        uint64_t tag = seed_.hi ^ seed_.lo ^ 0xA5A5A5A5A5A5A5A5ULL;
        uint64_t ver = 5;
        fwrite(&tag, 8, 1, fp);
        fwrite(&ver, 8, 1, fp);

        uint8_t buf[BLOCK_SIZE_BYTES];

        // Root block
        root_.serialize(buf);
        obfuscate(buf, BLOCK_SIZE_BYTES, seed_, 0);
        fwrite(buf, BLOCK_SIZE_BYTES, 1, fp);

        // L1 segment tables
        for (int i = 0; i < LENS_COUNT; i++) {
            if (level1_[i]) level1_[i]->serialize(buf);
            else memset(buf, 0, BLOCK_SIZE_BYTES);
            obfuscate(buf, BLOCK_SIZE_BYTES, seed_, i + 1);
            fwrite(buf, BLOCK_SIZE_BYTES, 1, fp);
        }

        // L2 block count
        uint64_t l2_count = level2_.size();
        fwrite(&l2_count, 8, 1, fp);

        // L2 blocks
        for (auto& kv : level2_) {
            uint16_t l1s = kv.first.l1_slot;
            uint16_t l2i = kv.first.l2_index;
            uint32_t reserved = 0;
            fwrite(&l1s, 2, 1, fp);
            fwrite(&l2i, 2, 1, fp);
            fwrite(&reserved, 4, 1, fp);

            kv.second->serialize(buf);
            // Obfuscate with unique index derived from L2 address
            uint64_t obi = (uint64_t)LENS_COUNT + 1 +
                           ((uint64_t)l1s * MAX_L2_PER_SLOT) + l2i;
            obfuscate(buf, BLOCK_SIZE_BYTES, seed_, obi);
            fwrite(buf, BLOCK_SIZE_BYTES, 1, fp);
        }

        fclose(fp);
        return true;
    }

    bool load_image(const char* path, Seed s) {
        FILE* fp = fopen(path, "rb");
        if (!fp) return false;

        seed_ = s;
        LensGenerator::generate(seed_, lens_keys_);

        uint64_t tag, ver;
        if (fread(&tag, 8, 1, fp) != 1 || fread(&ver, 8, 1, fp) != 1) {
            fclose(fp); return false;
        }
        if (tag != (seed_.hi ^ seed_.lo ^ 0xA5A5A5A5A5A5A5A5ULL)) {
            fclose(fp); return false;
        }

        uint8_t buf[BLOCK_SIZE_BYTES];

        // Root block
        if (fread(buf, BLOCK_SIZE_BYTES, 1, fp) != 1) { fclose(fp); return false; }
        obfuscate(buf, BLOCK_SIZE_BYTES, seed_, 0);
        root_.deserialize(buf);

        // L1 segment tables
        level1_.resize(LENS_COUNT);
        for (int i = 0; i < LENS_COUNT; i++) {
            if (fread(buf, BLOCK_SIZE_BYTES, 1, fp) != 1) { fclose(fp); return false; }
            obfuscate(buf, BLOCK_SIZE_BYTES, seed_, i + 1);
            level1_[i] = std::make_unique<Block>();
            level1_[i]->deserialize(buf);
        }

        // L2 blocks
        level2_.clear();
        uint64_t l2_count = 0;
        if (fread(&l2_count, 8, 1, fp) != 1) {
            // No L2 section — possibly fresh or old format. That's OK.
            fclose(fp);
            dirty_ = false;
            return true;
        }

        for (uint64_t n = 0; n < l2_count; n++) {
            uint16_t l1s, l2i;
            uint32_t reserved;
            if (fread(&l1s, 2, 1, fp) != 1 ||
                fread(&l2i, 2, 1, fp) != 1 ||
                fread(&reserved, 4, 1, fp) != 1 ||
                fread(buf, BLOCK_SIZE_BYTES, 1, fp) != 1) {
                fclose(fp); return false;
            }

            uint64_t obi = (uint64_t)LENS_COUNT + 1 +
                           ((uint64_t)l1s * MAX_L2_PER_SLOT) + l2i;
            obfuscate(buf, BLOCK_SIZE_BYTES, seed_, obi);

            L2Addr addr = {l1s, l2i};
            auto block = std::make_unique<Block>();
            block->deserialize(buf);
            level2_[addr] = std::move(block);
        }

        fclose(fp);
        dirty_ = false;
        return true;
    }

    bool is_dirty() const { return dirty_; }
    const Seed& seed() const { return seed_; }

private:
    static void obfuscate(uint8_t* data, size_t len, Seed s, uint64_t bi) {
        uint8_t key[32] = {0};
        memcpy(key, &s.hi, 8);
        memcpy(key + 8, &s.lo, 8);
        
        uint8_t nonce[12] = {0};
        // Use block index as nonce
        memcpy(nonce, &bi, 8);

        crypto_stream_chacha20_ietf_xor(data, data, len, nonce, key);
        sodium_memzero(key, sizeof(key));
    }
};

} // namespace Emergence
#endif
