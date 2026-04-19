#ifndef EMERGENCE_TOPOLOGICAL_ASSEMBLER_HPP
#define EMERGENCE_TOPOLOGICAL_ASSEMBLER_HPP

#include "state_engine.hpp"
#include <map>
#include <string>
#include <vector>

namespace Emergence {

/**
 * TopologicalAssembler: Maps logic transitions into the 8-level substrate.
 * Transforms (CurrentState, InputSignal) -> (NextState, OutputAction).
 */
class TopologicalAssembler {
public:
    struct Transition {
        uint64_t current_state;
        uint16_t signal;
        uint64_t next_state;
        uint64_t action_hi;
        uint64_t action_lo;
    };

    explicit TopologicalAssembler(SubstrateTopology& topo) 
        : topo_(topo), state_engine_(topo) {}

    // Map a single transition into the substrate
    void map_transition(const Transition& t) {
        // Derive the starting seed for this state/signal pair
        Seed start_seed;
        start_seed.hi = t.current_state ^ 0x5555555555555555ULL;
        start_seed.lo = (uint64_t)t.signal ^ 0xAAAAAAAAAAAAAAAAULL;

        // The terminal value encodes the next state and the output action
        // We use the hi part for next state and metadata, lo for action
        Value128 terminal;
        terminal.hi = t.next_state;
        terminal.lo = t.action_lo; // Simplified for demo
        
        // Pack next state into route if needed for auto-chaining
        // But in a Mealy machine, the next seed is derived externally.
        
        state_engine_.program_state(start_seed, terminal);
    }

    // Assemble a high-level state machine description
    void assemble(const std::vector<Transition>& transitions) {
        for (const auto& t : transitions) {
            map_transition(t);
        }
    }

    // Helper to resolve a transition via the substrate
    bool resolve(uint64_t state, uint16_t signal, uint64_t& next_state, uint64_t& action) {
        Seed s;
        s.hi = state ^ 0x5555555555555555ULL;
        s.lo = (uint64_t)signal ^ 0xAAAAAAAAAAAAAAAAULL;

        Value128 result = state_engine_.execute_chain(s);
        if (result.hi == 0 && result.lo == 0) return false; // Dimension folded

        next_state = result.hi;
        action = result.lo;
        return true;
    }

private:
    SubstrateTopology& topo_;
    StateEngine state_engine_;
};

/**
 * MemoryLense: Uses the substrate as a high-efficiency virtual memory space.
 * Maps 64-bit virtual addresses into the 8-level physical substrate.
 */
class MemoryLense {
public:
    explicit MemoryLense(SubstrateTopology& topo) : topo_(topo), state_engine_(topo) {}

    void write_u64(uint64_t vaddr, uint64_t value) {
        Seed s = vaddr_to_seed(vaddr);
        Value128 v;
        v.lo = value;
        state_engine_.program_state(s, v);
    }

    uint64_t read_u64(uint64_t vaddr) {
        Seed s = vaddr_to_seed(vaddr);
        Value128 result = state_engine_.execute_chain(s);
        return result.lo;
    }

private:
    Seed vaddr_to_seed(uint64_t vaddr) {
        Seed s;
        s.hi = vaddr;
        s.lo = vaddr ^ 0xFFFFFFFFFFFFFFFFULL;
        return s;
    }

    SubstrateTopology& topo_;
    StateEngine state_engine_;
};

} // namespace Emergence
#endif
