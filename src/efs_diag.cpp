/*
 * EmergenceFS Diagnostic Tool
 * Tests topology write → save → load → read round-trip
 *
 * Build:
 *   g++ -std=c++17 -O2 -o efs_diag efs_diag.cpp
 *
 * Usage:
 *   ./efs_diag
 */

#include "topology.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <iostream>

using namespace Emergence;

// Fill buffer with deterministic pattern based on offset
void fill_pattern(uint8_t* buf, size_t len, size_t offset) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)((offset + i) * 251 + 17);
    }
}

bool verify_pattern(const uint8_t* buf, size_t len, size_t offset) {
    for (size_t i = 0; i < len; i++) {
        uint8_t expected = (uint8_t)((offset + i) * 251 + 17);
        if (buf[i] != expected) {
            std::cerr << "  MISMATCH at byte " << (offset + i)
                      << ": expected " << (int)expected
                      << " got " << (int)buf[i] << std::endl;
            return false;
        }
    }
    return true;
}

bool test_single_block() {
    std::cout << "Test 1: Single L2 block write/read..." << std::flush;

    Topology topo;
    Seed seed = {0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL};
    topo.initialize(seed);

    // Write one block of data
    uint8_t data[BYTES_PER_BLOCK];
    fill_pattern(data, BYTES_PER_BLOCK, 0);

    size_t w = topo.write_slot(1, data, BYTES_PER_BLOCK);
    if (w != BYTES_PER_BLOCK) {
        std::cerr << " FAIL (wrote " << w << ")" << std::endl;
        return false;
    }

    // Read back
    uint8_t readback[BYTES_PER_BLOCK];
    memset(readback, 0, BYTES_PER_BLOCK);
    size_t r = topo.read_slot(1, readback, BYTES_PER_BLOCK);
    if (r != BYTES_PER_BLOCK) {
        std::cerr << " FAIL (read " << r << ")" << std::endl;
        return false;
    }

    if (memcmp(data, readback, BYTES_PER_BLOCK) != 0) {
        std::cerr << " FAIL (data mismatch before save)" << std::endl;
        verify_pattern(readback, BYTES_PER_BLOCK, 0);
        return false;
    }

    // Save and reload
    topo.save_image("/tmp/efs_diag_test1.img");
    Topology topo2;
    if (!topo2.load_image("/tmp/efs_diag_test1.img", seed)) {
        std::cerr << " FAIL (load failed)" << std::endl;
        return false;
    }

    memset(readback, 0, BYTES_PER_BLOCK);
    r = topo2.read_slot(1, readback, BYTES_PER_BLOCK);
    if (r != BYTES_PER_BLOCK) {
        std::cerr << " FAIL (read after reload: " << r << ")" << std::endl;
        return false;
    }

    if (memcmp(data, readback, BYTES_PER_BLOCK) != 0) {
        std::cerr << " FAIL (data mismatch after reload)" << std::endl;
        verify_pattern(readback, BYTES_PER_BLOCK, 0);
        return false;
    }

    std::cout << " PASS" << std::endl;
    return true;
}

bool test_full_slot() {
    std::cout << "Test 2: Full slot (" << BYTES_PER_SLOT << " bytes)..." << std::flush;

    Topology topo;
    Seed seed = {0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL};
    topo.initialize(seed);

    std::vector<uint8_t> data(BYTES_PER_SLOT);
    fill_pattern(data.data(), BYTES_PER_SLOT, 0);

    size_t w = topo.write_slot(1, data.data(), BYTES_PER_SLOT);
    if (w != BYTES_PER_SLOT) {
        std::cerr << " FAIL (wrote " << w << " of " << BYTES_PER_SLOT << ")" << std::endl;
        return false;
    }

    // Read back before save
    std::vector<uint8_t> readback(BYTES_PER_SLOT, 0);
    size_t r = topo.read_slot(1, readback.data(), BYTES_PER_SLOT);
    if (r != BYTES_PER_SLOT) {
        std::cerr << " FAIL (read before save: " << r << ")" << std::endl;
        return false;
    }

    if (memcmp(data.data(), readback.data(), BYTES_PER_SLOT) != 0) {
        std::cerr << " FAIL (mismatch before save)" << std::endl;
        // Find first mismatch
        for (size_t i = 0; i < BYTES_PER_SLOT; i++) {
            if (data[i] != readback[i]) {
                std::cerr << "  First mismatch at byte " << i
                          << " (L2 block " << (i / BYTES_PER_BLOCK)
                          << ", offset " << (i % BYTES_PER_BLOCK) << ")"
                          << std::endl;
                break;
            }
        }
        return false;
    }

    // Save and reload
    topo.save_image("/tmp/efs_diag_test2.img");
    Topology topo2;
    if (!topo2.load_image("/tmp/efs_diag_test2.img", seed)) {
        std::cerr << " FAIL (load failed)" << std::endl;
        return false;
    }

    std::fill(readback.begin(), readback.end(), 0);
    r = topo2.read_slot(1, readback.data(), BYTES_PER_SLOT);
    if (r != BYTES_PER_SLOT) {
        std::cerr << " FAIL (read after reload: " << r << ")" << std::endl;
        std::cerr << "  L2 count from loaded topo: " << topo2.get_l2_count(1) << std::endl;
        return false;
    }

    if (memcmp(data.data(), readback.data(), BYTES_PER_SLOT) != 0) {
        std::cerr << " FAIL (mismatch after reload)" << std::endl;
        size_t mismatches = 0;
        size_t first_mismatch = BYTES_PER_SLOT;
        for (size_t i = 0; i < BYTES_PER_SLOT; i++) {
            if (data[i] != readback[i]) {
                if (first_mismatch == BYTES_PER_SLOT) first_mismatch = i;
                mismatches++;
            }
        }
        std::cerr << "  Total mismatched bytes: " << mismatches
                  << " / " << BYTES_PER_SLOT << std::endl;
        std::cerr << "  First mismatch at byte " << first_mismatch
                  << " (L2 block " << (first_mismatch / BYTES_PER_BLOCK)
                  << ", offset " << (first_mismatch % BYTES_PER_BLOCK) << ")"
                  << std::endl;
        return false;
    }

    std::cout << " PASS" << std::endl;
    return true;
}

bool test_multi_slot() {
    std::cout << "Test 3: Multi-slot (3 slots, ~39 MB)..." << std::flush;

    Topology topo;
    Seed seed = {0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL};
    topo.initialize(seed);

    size_t total_size = BYTES_PER_SLOT * 3;
    std::vector<uint8_t> data(total_size);
    fill_pattern(data.data(), total_size, 0);

    // Write to 3 separate slots
    uint16_t slots[] = {1, 2, 3};
    size_t written = 0;
    for (int i = 0; i < 3; i++) {
        size_t to_write = std::min(BYTES_PER_SLOT, total_size - written);
        size_t w = topo.write_slot(slots[i], data.data() + written, to_write);
        if (w != to_write) {
            std::cerr << " FAIL (slot " << i << " wrote " << w << ")" << std::endl;
            return false;
        }
        written += w;
    }

    // Save and reload
    topo.save_image("/tmp/efs_diag_test3.img");
    Topology topo2;
    if (!topo2.load_image("/tmp/efs_diag_test3.img", seed)) {
        std::cerr << " FAIL (load failed)" << std::endl;
        return false;
    }

    // Read back from each slot
    std::vector<uint8_t> readback(total_size, 0);
    size_t total_read = 0;
    for (int i = 0; i < 3; i++) {
        size_t to_read = std::min(BYTES_PER_SLOT, total_size - total_read);
        size_t r = topo2.read_slot(slots[i], readback.data() + total_read, to_read);
        if (r != to_read) {
            std::cerr << " FAIL (slot " << i << " read " << r
                      << ", expected " << to_read << ")" << std::endl;
            std::cerr << "  L2 count: " << topo2.get_l2_count(slots[i]) << std::endl;
            return false;
        }
        total_read += r;
    }

    if (memcmp(data.data(), readback.data(), total_size) != 0) {
        std::cerr << " FAIL (data mismatch)" << std::endl;
        size_t mismatches = 0;
        size_t first = total_size;
        for (size_t i = 0; i < total_size; i++) {
            if (data[i] != readback[i]) {
                if (first == total_size) first = i;
                mismatches++;
            }
        }
        std::cerr << "  Mismatched bytes: " << mismatches << std::endl;
        std::cerr << "  First at byte " << first
                  << " (slot " << (first / BYTES_PER_SLOT)
                  << ", L2 block " << ((first % BYTES_PER_SLOT) / BYTES_PER_BLOCK)
                  << ")" << std::endl;
        return false;
    }

    std::cout << " PASS" << std::endl;
    return true;
}

bool test_partial_slot() {
    std::cout << "Test 4: Partial slot (70 MB across 6 slots)..." << std::flush;

    Topology topo;
    Seed seed = {0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL};
    topo.initialize(seed);

    size_t total_size = 70 * 1024 * 1024; // 70 MB
    std::vector<uint8_t> data(total_size);
    fill_pattern(data.data(), total_size, 0);

    // Calculate slots needed
    size_t num_slots = (total_size + BYTES_PER_SLOT - 1) / BYTES_PER_SLOT;
    std::cout << " (" << num_slots << " slots)..." << std::flush;

    // Write
    size_t written = 0;
    for (size_t s = 0; s < num_slots; s++) {
        size_t to_write = std::min(BYTES_PER_SLOT, total_size - written);
        size_t w = topo.write_slot((uint16_t)(s + 1), data.data() + written, to_write);
        if (w != to_write) {
            std::cerr << " FAIL (slot " << s << " wrote " << w
                      << " expected " << to_write << ")" << std::endl;
            return false;
        }
        written += w;
    }

    // Verify before save
    std::vector<uint8_t> readback(total_size, 0);
    size_t total_read = 0;
    for (size_t s = 0; s < num_slots; s++) {
        size_t to_read = std::min(BYTES_PER_SLOT, total_size - total_read);
        size_t r = topo.read_slot((uint16_t)(s + 1), readback.data() + total_read, to_read);
        total_read += r;
    }

    if (total_read != total_size || memcmp(data.data(), readback.data(), total_size) != 0) {
        std::cerr << " FAIL (mismatch BEFORE save, read " << total_read << ")" << std::endl;
        return false;
    }

    // Save
    std::cout << " save..." << std::flush;
    topo.save_image("/tmp/efs_diag_test4.img");

    // Reload
    Topology topo2;
    if (!topo2.load_image("/tmp/efs_diag_test4.img", seed)) {
        std::cerr << " FAIL (load failed)" << std::endl;
        return false;
    }

    // Read back
    std::fill(readback.begin(), readback.end(), 0);
    total_read = 0;
    for (size_t s = 0; s < num_slots; s++) {
        size_t to_read = std::min(BYTES_PER_SLOT, total_size - total_read);
        size_t r = topo2.read_slot((uint16_t)(s + 1), readback.data() + total_read, to_read);
        if (r != to_read) {
            std::cerr << " FAIL (slot " << s << " read " << r
                      << " expected " << to_read
                      << ", L2 count=" << topo2.get_l2_count((uint16_t)(s + 1))
                      << ")" << std::endl;
            return false;
        }
        total_read += r;
    }

    if (memcmp(data.data(), readback.data(), total_size) != 0) {
        std::cerr << " FAIL (mismatch AFTER reload)" << std::endl;
        size_t mismatches = 0;
        size_t first = total_size;
        for (size_t i = 0; i < total_size; i++) {
            if (data[i] != readback[i]) {
                if (first == total_size) first = i;
                mismatches++;
            }
        }
        std::cerr << "  Mismatched: " << mismatches << " / " << total_size << std::endl;
        std::cerr << "  First at byte " << first
                  << " (slot " << (first / BYTES_PER_SLOT)
                  << ", L2 block " << ((first % BYTES_PER_SLOT) / BYTES_PER_BLOCK)
                  << ", block offset " << (first % BYTES_PER_BLOCK)
                  << ")" << std::endl;

        // Show some context
        std::cerr << "  Expected bytes at mismatch: ";
        for (size_t i = first; i < first + 16 && i < total_size; i++)
            fprintf(stderr, "%02x ", data[i]);
        std::cerr << std::endl;
        std::cerr << "  Got bytes at mismatch:      ";
        for (size_t i = first; i < first + 16 && i < total_size; i++)
            fprintf(stderr, "%02x ", readback[i]);
        std::cerr << std::endl;

        return false;
    }

    std::cout << " PASS" << std::endl;
    return true;
}

int main() {
    std::cout << "=== EmergenceFS Topology Diagnostic ===" << std::endl;
    std::cout << "BYTES_PER_BLOCK: " << BYTES_PER_BLOCK << std::endl;
    std::cout << "BYTES_PER_SLOT:  " << BYTES_PER_SLOT << std::endl;
    std::cout << std::endl;

    int passed = 0, failed = 0;

    if (test_single_block()) passed++; else failed++;
    if (test_full_slot()) passed++; else failed++;
    if (test_multi_slot()) passed++; else failed++;
    if (test_partial_slot()) passed++; else failed++;

    std::cout << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;

    // Cleanup
    remove("/tmp/efs_diag_test1.img");
    remove("/tmp/efs_diag_test2.img");
    remove("/tmp/efs_diag_test3.img");
    remove("/tmp/efs_diag_test4.img");

    return failed > 0 ? 1 : 0;
}
