#ifndef EMERGENCE_STATE_ENGINE_HPP
#define EMERGENCE_STATE_ENGINE_HPP

#include "topology.hpp"
#include <functional>
#include <cstring>
#include <stdexcept>
#include <unordered_map>

namespace Emergence {

class AddressEngine {
public:
    struct State { uint64_t hi, lo; };
    explicit AddressEngine(Seed seed) { state_ = {seed.hi, seed.lo}; }
    void step() {
        state_.hi = ((state_.hi << 13) | (state_.hi >> 51)) ^ (state_.lo * PHI_HI);
        state_.lo = ((state_.lo << 17) | (state_.lo >> 47)) ^ (state_.hi * PHI_LO);
    }
    uint16_t get_route() const { return (uint16_t)(state_.hi >> 54) & LENS_MASK; }
    void bias(uint64_t entropy) { state_.lo ^= entropy; }
    State get_state() const { return state_; }
private:
    State state_;
};

class StateEngine {
public:
    explicit StateEngine(Topology& topo) : topo_(topo) {}

    Value128 execute_chain(Seed start_seed) {
        // FAST PATH: Check structural cache
        uint64_t key = start_seed.hi ^ start_seed.lo;
        auto it = structural_cache_.find(key);
        if (it != structural_cache_.end()) return it->second;

        AddressEngine ae(start_seed); uint16_t path[8];
        for (int i = 0; i < 8; i++) { ae.step(); path[i] = ae.get_route(); }
        Value128 terminal;
        if (topo_.traverse_8_hops(path, terminal)) {
            structural_cache_[key] = terminal;
            return terminal;
        }
        return Value128(0, 0);
    }

    void program_state(Seed start_seed, const Value128& terminal) {
        AddressEngine ae(start_seed); uint16_t path[8];
        for (int i = 0; i < 8; i++) { ae.step(); path[i] = ae.get_route(); }
        topo_.materialize_8_hops(path, terminal);
        
        uint64_t key = start_seed.hi ^ start_seed.lo;
        structural_cache_[key] = terminal;
    }

private:
    Topology& topo_;
    // Simulates the EM-1 L0 "Synaptic Cache"
    std::unordered_map<uint64_t, Value128> structural_cache_;
};

class SiliconMirror {
public:
    explicit SiliconMirror(Topology& topo) : topo_(topo) {}
    void project(uint8_t* data, size_t len, Seed projection_seed) {
        AddressEngine ae(projection_seed);
        for (size_t i = 0; i < len; i += 16) {
            ae.step(); uint16_t path[8];
            for(int j=0; j<8; j++) {
                uint64_t mix = ae.get_state().hi ^ (uint64_t)j;
                path[j] = (uint16_t)(mix >> (j * 7)) & LENS_MASK;
            }
            Value128 v;
            if (topo_.traverse_8_hops(path, v)) {
                uint8_t payload[16]; v.get_payload(payload, 16);
                for (size_t k = 0; k < 16 && (i + k) < len; k++) data[i + k] ^= payload[k];
            }
        }
    }
private:
    Topology& topo_;
};

} // namespace Emergence
#endif
