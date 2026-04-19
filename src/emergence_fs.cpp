/*
 * EmergenceFS v0.5 — Self-Routing Topology Filesystem
 *
 * 3-level nesting: Root → L1 segment tables → L2 data blocks
 * ~13 MB per file, ~13 GB total capacity
 *
 * Build:
 *   sudo apt install libfuse3-dev pkg-config
 *   make
 *
 * Usage:
 *   mkdir -p /tmp/emergence
 *   ./emergence_fs /tmp/emergence
 *
 * Unmount:
 *   fusermount -u /tmp/emergence
 */

#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>

#include "topology.hpp"
#include "filemap.hpp"

// ============================================================
// Global state
// ============================================================

static Emergence::Topology   g_topology;
static Emergence::FileMap*   g_filemap = nullptr;
static std::string           g_image_path;

// ============================================================
// FUSE callbacks
// ============================================================

static int efs_getattr(const char* path, struct stat* st,
                       struct fuse_file_info* /*fi*/) {
    memset(st, 0, sizeof(struct stat));
    std::string p(path);

    if (g_filemap->is_directory(p)) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        st->st_uid = getuid();
        st->st_gid = getgid();
        const Emergence::FileMeta* meta = g_filemap->get_meta(p);
        if (meta) {
            st->st_atime = meta->modified;
            st->st_mtime = meta->modified;
            st->st_ctime = meta->created;
        }
        return 0;
    }

    const Emergence::FileMeta* meta = g_filemap->get_meta(p);
    if (!meta) return -ENOENT;

    st->st_mode = S_IFREG | 0644;
    st->st_nlink = 1;
    st->st_size = (off_t)meta->size;
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = meta->modified;
    st->st_mtime = meta->modified;
    st->st_ctime = meta->created;
    return 0;
}

static int efs_readdir(const char* path, void* buf,
                       fuse_fill_dir_t filler,
                       off_t /*offset*/, struct fuse_file_info* /*fi*/,
                       enum fuse_readdir_flags /*flags*/) {
    std::string p(path);
    if (!g_filemap->is_directory(p)) return -ENOTDIR;

    filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);

    auto children = g_filemap->list_directory(p);
    for (auto& name : children)
        filler(buf, name.c_str(), nullptr, 0, (fuse_fill_dir_flags)0);

    return 0;
}

static int efs_open(const char* path, struct fuse_file_info* /*fi*/) {
    std::string p(path);
    if (!g_filemap->exists(p)) return -ENOENT;
    if (g_filemap->is_directory(p)) return -EISDIR;
    return 0;
}

static int efs_read(const char* path, char* buf, size_t size,
                    off_t offset, struct fuse_file_info* /*fi*/) {
    ssize_t r = g_filemap->read_file(path, (uint8_t*)buf, size, (size_t)offset);
    if (r < 0) return -ENOENT;
    return (int)r;
}

static int efs_write(const char* path, const char* buf,
                     size_t size, off_t offset,
                     struct fuse_file_info* /*fi*/) {
    ssize_t w = g_filemap->write_file(path, (const uint8_t*)buf,
                                       size, (size_t)offset);
    if (w < 0) return -EIO;
    return (int)w;
}

static int efs_create(const char* path, mode_t /*mode*/,
                      struct fuse_file_info* /*fi*/) {
    std::string p(path);
    if (g_filemap->exists(p)) return 0;
    if (!g_filemap->create_file(p)) return -ENOSPC;
    return 0;
}

static int efs_unlink(const char* path) {
    if (!g_filemap->delete_file(path)) return -ENOENT;
    return 0;
}

static int efs_mkdir(const char* path, mode_t /*mode*/) {
    if (!g_filemap->mkdir(path)) return -EEXIST;
    return 0;
}

static int efs_rmdir(const char* path) {
    if (!g_filemap->rmdir(path)) return -ENOTEMPTY;
    return 0;
}

static int efs_rename(const char* from, const char* to,
                      unsigned int /*flags*/) {
    if (g_filemap->exists(to) && !g_filemap->is_directory(to))
        g_filemap->delete_file(to);
    if (!g_filemap->rename_entry(from, to)) return -ENOENT;
    return 0;
}

static int efs_truncate(const char* path, off_t size,
                        struct fuse_file_info* /*fi*/) {
    if (!g_filemap->truncate_file(path, (size_t)size))
        return -ENOENT;
    return 0;
}

static int efs_utimens(const char* /*path*/,
                       const struct timespec /*tv*/[2],
                       struct fuse_file_info* /*fi*/) {
    return 0;
}

static void efs_destroy(void* /*private_data*/) {
    if (g_filemap) {
        std::cerr << "[EmergenceFS] Flushing data to topology..." << std::flush;
        g_filemap->sync();
        std::cerr << " done." << std::endl;
    }

    if (!g_image_path.empty()) {
        std::cerr << "[EmergenceFS] Saving topology..." << std::flush;
        if (g_topology.save_image(g_image_path.c_str())) {
            std::cerr << " done. (L2 blocks: "
                      << g_topology.total_l2_blocks() << ")" << std::endl;
        } else {
            std::cerr << " FAILED!" << std::endl;
        }
    }

    delete g_filemap;
    g_filemap = nullptr;
}

static int efs_statfs(const char* /*path*/, struct statvfs* stbuf) {
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->f_bsize = Emergence::BYTES_PER_BLOCK;
    stbuf->f_frsize = Emergence::BYTES_PER_BLOCK;
    // Total blocks = slots × L2 blocks per slot
    stbuf->f_blocks = (Emergence::SLOT_END - Emergence::SLOT_START + 1)
                      * Emergence::MAX_L2_PER_SLOT;
    stbuf->f_bfree = g_filemap ? g_filemap->slots_available()
                                 * Emergence::MAX_L2_PER_SLOT : 0;
    stbuf->f_bavail = stbuf->f_bfree;
    stbuf->f_namemax = 255;
    return 0;
}

// ============================================================
// FUSE operations
// ============================================================

static struct fuse_operations efs_oper;

static void init_fuse_ops() {
    memset(&efs_oper, 0, sizeof(efs_oper));
    efs_oper.getattr  = efs_getattr;
    efs_oper.mkdir    = efs_mkdir;
    efs_oper.unlink   = efs_unlink;
    efs_oper.rmdir    = efs_rmdir;
    efs_oper.rename   = efs_rename;
    efs_oper.truncate = efs_truncate;
    efs_oper.open     = efs_open;
    efs_oper.read     = efs_read;
    efs_oper.write    = efs_write;
    efs_oper.statfs   = efs_statfs;
    efs_oper.readdir  = efs_readdir;
    efs_oper.destroy  = efs_destroy;
    efs_oper.create   = efs_create;
    efs_oper.utimens  = efs_utimens;
}

// ============================================================
// Boot prompt
// ============================================================

static std::string read_password(const char* prompt) {
    std::cerr << prompt;
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    std::string pw;
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    std::cerr << std::endl;
    return pw;
}

static std::string auto_detect_hwid() {
    std::vector<std::string> macs;
    std::set<std::string> seen;

    struct ifaddrs* ifas = nullptr;
    if (getifaddrs(&ifas) == 0) {
        for (struct ifaddrs* ifa = ifas; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            std::string name(ifa->ifa_name);
            if (seen.count(name)) continue;
            seen.insert(name);

            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) continue;
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                unsigned char* m = (unsigned char*)ifr.ifr_hwaddr.sa_data;
                if (m[0] || m[1] || m[2] || m[3] || m[4] || m[5]) {
                    char mac[32];
                    snprintf(mac, sizeof(mac), "%02X%02X-%02X%02X-%02X%02X",
                             m[0], m[1], m[2], m[3], m[4], m[5]);
                    macs.push_back(std::string(mac));
                }
            }
            close(fd);
        }
        freeifaddrs(ifas);
    }

    if (!macs.empty()) {
        std::sort(macs.begin(), macs.end());
        return macs[0];
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0)
        return std::string(hostname);
    return "DEFAULT-HWID";
}

// ============================================================
// Main
// ============================================================

int main(int argc, char* argv[]) {
    const char* home = getenv("HOME");
    g_image_path = home ? std::string(home) + "/.emergence.img"
                        : ".emergence.img";

    const char* custom = getenv("EMERGENCE_IMAGE");
    if (custom) g_image_path = custom;

    std::cerr << std::endl;
    std::cerr << "========================================" << std::endl;
    std::cerr << "  EmergenceFS v0.5.2" << std::endl;
    std::cerr << "  3-Level Self-Routing Topology" << std::endl;
    std::cerr << "  ~13 GB/file, ~13 GB total" << std::endl;
    std::cerr << "========================================" << std::endl;
    std::cerr << std::endl;

    std::string password = read_password("Password: ");
    if (password.empty()) {
        std::cerr << "Error: Password cannot be empty." << std::endl;
        return 1;
    }

    std::string auto_hwid = auto_detect_hwid();
    std::cerr << std::endl;
    std::cerr << "Hardware Key" << std::endl;
    std::cerr << "  Auto-detected: " << auto_hwid << std::endl;
    std::cerr << "  [ENTER to accept, or type custom key]" << std::endl;
    std::cerr << std::endl << "Hardware Key: ";

    std::string hwkey;
    std::getline(std::cin, hwkey);
    if (hwkey.empty()) hwkey = auto_hwid;

    std::cerr << std::endl;
    std::cerr << "  >>> Using Hardware Key: " << hwkey << " <<<" << std::endl;

    std::cerr << std::endl << "Deriving seed..." << std::flush;
    Emergence::Seed seed = Emergence::KeyDerivation::derive(
        password.c_str(), hwkey.c_str());
    std::cerr << " done." << std::endl;

    bool loaded = false;
    FILE* test = fopen(g_image_path.c_str(), "rb");
    if (test) {
        fclose(test);
        std::cerr << "Loading image..." << std::flush;
        loaded = g_topology.load_image(g_image_path.c_str(), seed);
        if (loaded) {
            std::cerr << " done. (L2 blocks: "
                      << g_topology.total_l2_blocks() << ")" << std::endl;
        } else {
            std::cerr << std::endl;
            std::cerr << "ERROR: Wrong password or hardware key." << std::endl;
            return 1;
        }
    }

    if (!loaded) {
        std::cerr << "Creating fresh topology..." << std::flush;
        g_topology.initialize(seed);
        std::cerr << " done." << std::endl;
    }

    g_filemap = new Emergence::FileMap(g_topology);
    g_filemap->initialize();

    std::cerr << "Slots available: " << g_filemap->slots_available()
              << " / " << (Emergence::SLOT_END - Emergence::SLOT_START + 1)
              << " (~" << (g_filemap->slots_available() * Emergence::BYTES_PER_SLOT / 1024 / 1024)
              << " MB capacity)" << std::endl;
    std::cerr << "Image: " << g_image_path << std::endl;
    std::cerr << std::endl << "Mounting..." << std::endl;
    std::cerr << "  fusermount -u <mountpoint> to unmount" << std::endl;
    std::cerr << std::endl;

    init_fuse_ops();
    return fuse_main(argc, argv, &efs_oper, nullptr);
}
