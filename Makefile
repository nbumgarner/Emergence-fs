CXX = g++
CXXFLAGS = -std=c++17 -O3 -march=native -Iinclude
LDFLAGS = -lsodium
FUSE_FLAGS = $(shell pkg-config --cflags fuse3)
FUSE_LIBS = $(shell pkg-config --libs fuse3)

TOOLS = efs_seal efs_vault
CORE = emergence_fs
DIAG = efs_diag

.PHONY: all clean tools core diag

all: core tools diag

core: src/emergence_fs.cpp include/topology.hpp include/filemap.hpp
	$(CXX) $(CXXFLAGS) $(FUSE_FLAGS) -o $(CORE) src/emergence_fs.cpp $(FUSE_LIBS) $(LDFLAGS)

tools: tools/efs_seal.cpp tools/efs_vault.cpp include/topology.hpp include/state_engine.hpp
	$(CXX) $(CXXFLAGS) -o efs_seal tools/efs_seal.cpp $(LDFLAGS)
	$(CXX) $(CXXFLAGS) -o efs_vault tools/efs_vault.cpp $(LDFLAGS)

diag: src/efs_diag.cpp include/topology.hpp
	$(CXX) $(CXXFLAGS) -o $(DIAG) src/efs_diag.cpp

clean:
	rm -f $(CORE) $(TOOLS) $(DIAG)
	rm -f *.o
