#ifndef EMERGENCE_TOPOLOGICAL_IO_HPP
#define EMERGENCE_TOPOLOGICAL_IO_HPP

#include "topology.hpp"
#include "state_engine.hpp"
#include <map>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <iostream>

namespace Emergence {

/**
 * TopologicalIO: Substrate-Level I/O Virtualization.
 * Maps physical devices/sockets to 80-bit Routes in the substrate.
 */
class TopologicalIO {
public:
    struct Device {
        int fd;
        uint16_t route_path[8];
        bool active;
    };

    explicit TopologicalIO(SubstrateTopology& topo) : topo_(topo) {}

    // Bind a Unix File Descriptor (NIC/NVMe simulation) to a specific route
    void bind_device(int fd, const uint16_t path[8]) {
        Device dev;
        dev.fd = fd;
        memcpy(dev.route_path, path, sizeof(dev.route_path));
        dev.active = true;
        devices_.push_back(dev);
        
        // Set non-blocking for DMA simulation
        fcntl(fd, F_SETFL, O_NONBLOCK);
        
        std::cout << "[EM-1] IO-BIND: FD " << fd << " -> Substrate Route [";
        for(int i=0; i<8; i++) std::cout << path[i] << (i<7 ? ":" : "");
        std::cout << "]" << std::endl;
    }

    // "Pulse" the I/O layer: Move data between FDs and the Substrate
    // This simulates the hardware DMA engine writing directly to coordinates.
    void sync() {
        for (auto& dev : devices_) {
            if (!dev.active) continue;

            uint8_t buffer[16]; // 128-bit DMA chunk
            ssize_t n = read(dev.fd, buffer, 16);
            
            if (n > 0) {
                // DATA ARRIVED: Move it directly into the substrate coordinate
                Value128 v;
                v.set_payload(buffer, n);
                topo_.materialize_8_hops(dev.route_path, v);
                
                // SIGNAL PRESSURE: Notify that this coordinate is "Hot"
                last_active_route_ = dev.route_path[0]; // Simplified pressure signal
            }
        }
    }

    uint16_t get_io_pressure() const { return last_active_route_; }

private:
    SubstrateTopology& topo_;
    std::vector<Device> devices_;
    uint16_t last_active_route_ = 0;
};

/**
 * VirtualNIC: Simulates a high-speed network interface integrated with the substrate.
 */
class VirtualNIC {
public:
    VirtualNIC() {
        // Create a socket pair to simulate hardware <-> substrate link
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds_) < 0) {
            perror("socketpair");
        }
    }

    int get_substrate_fd() { return fds_[0]; }
    int get_hardware_fd() { return fds_[1]; }

    // Simulate an incoming packet from the "wire"
    void inject_packet(const std::string& data) {
        write(fds_[1], data.c_str(), std::min(data.length(), (size_t)16));
    }

private:
    int fds_[2];
};

} // namespace Emergence
#endif
