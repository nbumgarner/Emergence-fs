#ifndef EMERGENCE_STATE_ENGINE_HPP
#define EMERGENCE_STATE_ENGINE_HPP

#include "topology.hpp"
#include <functional>
#include <cstring>
#include <stdexcept>

namespace Emergence {

constexpr uint16_t SE_FREE  = 0x3FD;
constexpr uint16_t SE_ERROR = 0x3FE;
constexpr uint16_t SE_HALT  = 0x3FF;

struct ExecutionResult {
    uint16_t prev_state;
    uint16_t input;
    uint16_t next_state;
    Value128 value;
    bool     valid;
    
    void output(uint8_t* dst, size_t max_len) const {
        value.get_payload(dst, max_len);
    }
};

struct ProjectionResult {
    uint16_t path[8];
    int      depth;
    Value128 terminal;
    bool     halted;
};

class StateEngine {
public:
    explicit StateEngine(Topology& topo) : topo_(topo), current_state_(0) {}
    
    void build_from_seed() {
        // Reset state to root
        current_state_ = 0;
    }
    
    void reset(int state = 0) { current_state_ = state; }
    
    ExecutionResult step(uint16_t input) {
        // Topological transition: State x Input -> New State
        uint16_t slot = (current_state_ ^ input) & LENS_MASK;
        uint8_t payload[16];
        size_t bytes = topo_.read_slot(slot, payload, 16);
        
        ExecutionResult res;
        res.prev_state = current_state_;
        res.input = input;
        
        if (bytes > 0) {
            res.valid = true;
            res.value.read_from(payload);
        } else {
            // FALLBACK: If the topology is empty, use deterministic Lens noise
            // This ensures the keystream is never zero and remains secure.
            res.valid = false;
            // Get the Lens Key for this slot and mix with input for noise
            const Seed& s = topo_.seed();
            uint64_t h = s.hi ^ ((uint64_t)slot * 0x9E3779B97F4A7C15ULL);
            uint64_t l = s.lo ^ ((uint64_t)input * 0x517CC1B727220A95ULL);
            res.value.hi = h;
            res.value.lo = l;
        }
        
        res.next_state = res.value.route();
        current_state_ = res.next_state;
        return res;
    }
    
    size_t generate_keystream(uint8_t* out, size_t len) {
        size_t generated = 0;
        while (generated < len) {
            ExecutionResult res = step(generated & 0xFFFF);
            uint8_t buf[16];
            res.output(buf, 16);
            size_t to_copy = std::min((size_t)16, len - generated);
            memcpy(out + generated, buf, to_copy);
            generated += to_copy;
        }
        return generated;
    }
    
private:
    Topology& topo_;
    uint16_t current_state_;
};

class ProjectedEngine {
public:
    explicit ProjectedEngine(Topology& topo) : topo_(topo) {}
    
    // Non-linear projection: Transforms a block of data through the topology
    void project(uint8_t* data, size_t len, uint64_t salt) {
        for (size_t i = 0; i < len; i += 16) {
            uint16_t slot = (uint16_t)((i ^ salt) & LENS_MASK);
            uint8_t payload[16];
            if (topo_.read_slot(slot, payload, 16) > 0) {
                for (size_t j = 0; j < 16 && (i + j) < len; j++) {
                    data[i + j] ^= payload[j];
                }
            }
        }
    }
    
private:
    Topology& topo_;
};

} // namespace Emergence
#endif
