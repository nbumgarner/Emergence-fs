#!/bin/bash
# ==============================================================================
# EM-1 REAL-WORLD AUDIT: HARDWARE & ENTROPY VALIDATION (V2)
# ==============================================================================
set -e

WORKSPACE_ROOT="/home/ubuntu"
ENTROPY_FILE="$WORKSPACE_ROOT/entropy_1gb.bin"
OUTPUT_FILE="$WORKSPACE_ROOT/audit_out.enc"
SEAL_BIN="$WORKSPACE_ROOT/emergence-fs/efs_seal"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}Executing Real-World Hardware Benchmark (No Sparse Files)${NC}"

# 1. Prepare 1GB of High-Entropy Data
if [ ! -f "$ENTROPY_FILE" ]; then
    echo -e "${YELLOW}Generating 1GB Entropy Source...${NC}"
    dd if=/dev/urandom of="$ENTROPY_FILE" bs=1M count=1024 status=progress
fi

# 2. Re-build with the Fixed Engine
echo -e "${YELLOW}Re-building Production Engine...${NC}"
cd "$WORKSPACE_ROOT/emergence-fs"
g++ -std=c++17 -O3 -march=native -o efs_seal efs_seal.cpp -lsodium
cd "$WORKSPACE_ROOT"

# 3. 15GB Throughput Test (15 Iterations of 1GB)
echo -e "${YELLOW}Initiating 15GB Sequential Hardware Projection...${NC}"
export EFS_PASSWORD="lauriewired_audit_2026"
export EFS_HWKEY="REAL-HARDWARE-TEST"

TOTAL_START=$(date +%s.%N)

for i in {1..15}
do
    echo -n "Iteration $i/15... "
    "$SEAL_BIN" seal "$ENTROPY_FILE" "$OUTPUT_FILE" > /dev/null 2>&1
    echo "Done."
done

TOTAL_END=$(date +%s.%N)
DURATION=$(echo "$TOTAL_END - $TOTAL_START" | bc)
THROUGHPUT=$(echo "15360 / $DURATION" | bc -l)

echo -e "\n${GREEN}TRUTHFUL AUDIT COMPLETE${NC}"
echo -e "Total Data: 15 GB"
echo -e "Total Time: $(printf "%.2f" $DURATION)s"
echo -e "True Hardware Throughput: $(printf "%.2f" $THROUGHPUT) MB/s"

# Final Verification: Unseal the last iteration and compare
echo -e "${YELLOW}Verifying Bit-Integrity...${NC}"
"$SEAL_BIN" unseal "$OUTPUT_FILE" audit_verify.bin > /dev/null 2>&1
if cmp -s "$ENTROPY_FILE" audit_verify.bin; then
    echo -e "${GREEN}INTEGRITY VERIFIED: No bit-flipping detected.${NC}"
else
    echo -e "${RED}INTEGRITY FAILURE: Data corruption detected.${NC}"
fi

# Cleanup
rm "$ENTROPY_FILE" "$OUTPUT_FILE" audit_verify.bin
