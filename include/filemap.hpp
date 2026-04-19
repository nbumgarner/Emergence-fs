#ifndef EMERGENCE_FILEMAP_HPP
#define EMERGENCE_FILEMAP_HPP

#include "topology.hpp"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <ctime>
#include <mutex>
#include <algorithm>
#include <sstream>

namespace Emergence {

// ============================================================
// Slot allocation
//
// Slot 0       = Filesystem metadata
// Slots 1-1020 = Available for files and directories
// ============================================================

constexpr uint16_t META_SLOT       = 0;
constexpr uint16_t SLOT_START      = 1;
constexpr uint16_t SLOT_END        = 1020;

// ============================================================
// FileMeta: files can span multiple slots
// ============================================================

struct FileMeta {
    std::string              full_path;
    std::vector<uint16_t>    slots;     // One or more L1 slots
    size_t                   size;
    time_t                   created;
    time_t                   modified;
    bool                     is_directory;
};

// ============================================================
// Slot Allocator
// ============================================================

class SlotAllocator {
private:
    std::unordered_set<uint16_t> used_;

public:
    void mark_used(uint16_t s) { used_.insert(s); }
    void mark_free(uint16_t s) { used_.erase(s); }
    bool is_used(uint16_t s) const { return used_.count(s) > 0; }

    uint16_t allocate() {
        for (uint16_t i = SLOT_START; i <= SLOT_END; i++) {
            if (!is_used(i)) {
                mark_used(i);
                return i;
            }
        }
        return HALT_ROUTE;
    }

    // Allocate multiple slots at once
    std::vector<uint16_t> allocate_n(size_t n) {
        std::vector<uint16_t> result;
        for (uint16_t i = SLOT_START; i <= SLOT_END && result.size() < n; i++) {
            if (!is_used(i)) {
                result.push_back(i);
            }
        }
        if (result.size() < n) {
            return {}; // Not enough space
        }
        for (uint16_t s : result) mark_used(s);
        return result;
    }

    void free_all(const std::vector<uint16_t>& slots) {
        for (uint16_t s : slots) mark_free(s);
    }

    size_t slots_free() const {
        size_t total = SLOT_END - SLOT_START + 1;
        return total - used_.size();
    }
};

// ============================================================
// FileMap: multi-slot files, subdirectories
// ============================================================

class FileMap {
private:
    Topology& topo_;
    std::unordered_map<std::string, FileMeta> entries_;
    std::unordered_map<std::string, std::vector<uint8_t>> data_cache_;
    SlotAllocator allocator_;
    std::mutex mu_;

    // How many slots needed for a given file size
    static size_t slots_needed(size_t bytes) {
        if (bytes == 0) return 1;
        return (bytes + BYTES_PER_SLOT - 1) / BYTES_PER_SLOT;
    }

public:
    explicit FileMap(Topology& topo) : topo_(topo) {}

    void initialize() {
        std::lock_guard<std::mutex> lock(mu_);
        entries_.clear();
        data_cache_.clear();

        FileMeta root_dir;
        root_dir.full_path = "/";
        root_dir.size = 0;
        root_dir.created = time(nullptr);
        root_dir.modified = root_dir.created;
        root_dir.is_directory = true;
        entries_["/"] = root_dir;

        allocator_.mark_used(META_SLOT);

        // Metadata can span multiple L2 blocks within slot 0
        std::vector<uint8_t> meta_buf(BYTES_PER_SLOT);
        size_t meta_len = topo_.read_slot(META_SLOT, meta_buf.data(), meta_buf.size());
        if (meta_len > 0) {
            deserialize_all(meta_buf.data(), meta_len);
        }
    }

    // --------------------------------------------------------
    // Path utilities
    // --------------------------------------------------------

    static std::string parent_path(const std::string& path) {
        if (path == "/") return "/";
        size_t last = path.rfind('/');
        if (last == 0) return "/";
        if (last == std::string::npos) return "/";
        return path.substr(0, last);
    }

    static std::string basename(const std::string& path) {
        size_t last = path.rfind('/');
        if (last == std::string::npos) return path;
        return path.substr(last + 1);
    }

    static std::string normalize(const std::string& path) {
        if (path.empty() || path == "/") return "/";
        std::string result;
        bool last_slash = false;
        for (char c : path) {
            if (c == '/') {
                if (!last_slash) result += c;
                last_slash = true;
            } else {
                result += c;
                last_slash = false;
            }
        }
        if (result.size() > 1 && result.back() == '/')
            result.pop_back();
        if (result.empty() || result[0] != '/')
            result = "/" + result;
        return result;
    }

    // --------------------------------------------------------
    // Lookups
    // --------------------------------------------------------

    bool exists(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        return entries_.count(normalize(path)) > 0;
    }

    bool is_directory(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = entries_.find(normalize(path));
        return it != entries_.end() && it->second.is_directory;
    }

    const FileMeta* get_meta(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = entries_.find(normalize(path));
        if (it == entries_.end()) return nullptr;
        return &it->second;
    }

    std::vector<std::string> list_directory(const std::string& dir_path) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm = normalize(dir_path);
        std::vector<std::string> result;
        for (auto& kv : entries_) {
            if (kv.first == norm) continue;
            if (parent_path(kv.first) == norm)
                result.push_back(basename(kv.first));
        }
        return result;
    }

    // --------------------------------------------------------
    // Directory operations
    // --------------------------------------------------------

    bool mkdir(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm = normalize(path);
        if (entries_.count(norm)) return false;

        std::string parent = parent_path(norm);
        auto pit = entries_.find(parent);
        if (pit == entries_.end() || !pit->second.is_directory) return false;

        FileMeta meta;
        meta.full_path = norm;
        meta.size = 0;
        meta.created = time(nullptr);
        meta.modified = meta.created;
        meta.is_directory = true;

        entries_[norm] = meta;
        flush_metadata();
        return true;
    }

    bool rmdir(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm = normalize(path);
        if (norm == "/") return false;

        auto it = entries_.find(norm);
        if (it == entries_.end() || !it->second.is_directory) return false;

        for (auto& kv : entries_) {
            if (kv.first != norm && parent_path(kv.first) == norm)
                return false;
        }

        entries_.erase(it);
        flush_metadata();
        return true;
    }

    // --------------------------------------------------------
    // File operations
    // --------------------------------------------------------

    bool create_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm = normalize(path);
        if (entries_.count(norm)) return false;

        std::string parent = parent_path(norm);
        auto pit = entries_.find(parent);
        if (pit == entries_.end() || !pit->second.is_directory) return false;

        // Allocate one slot initially; more added on write
        uint16_t slot = allocator_.allocate();
        if (slot == HALT_ROUTE) return false;

        FileMeta meta;
        meta.full_path = norm;
        meta.slots = {slot};
        meta.size = 0;
        meta.created = time(nullptr);
        meta.modified = meta.created;
        meta.is_directory = false;

        entries_[norm] = meta;
        data_cache_[norm] = std::vector<uint8_t>();

        flush_metadata();
        return true;
    }

    bool delete_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm = normalize(path);

        auto it = entries_.find(norm);
        if (it == entries_.end() || it->second.is_directory) return false;

        for (uint16_t s : it->second.slots)
            topo_.clear_slot(s);
        allocator_.free_all(it->second.slots);
        data_cache_.erase(norm);
        entries_.erase(it);

        flush_metadata();
        return true;
    }

    ssize_t read_file(const std::string& path, uint8_t* buf,
                      size_t size, size_t offset) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm = normalize(path);

        auto it = entries_.find(norm);
        if (it == entries_.end() || it->second.is_directory) return -1;

        ensure_cached(norm, it->second);

        auto& data = data_cache_[norm];
        if (offset >= data.size()) return 0;
        size_t avail = data.size() - offset;
        size_t to_copy = std::min(size, avail);
        memcpy(buf, data.data() + offset, to_copy);
        return (ssize_t)to_copy;
    }

    ssize_t write_file(const std::string& path, const uint8_t* buf,
                       size_t size, size_t offset) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm = normalize(path);

        auto it = entries_.find(norm);
        if (it == entries_.end() || it->second.is_directory) return -1;

        ensure_cached(norm, it->second);
        auto& data = data_cache_[norm];

        if (offset + size > data.size())
            data.resize(offset + size);

        memcpy(data.data() + offset, buf, size);

        it->second.size = data.size();
        it->second.modified = time(nullptr);

        // Ensure enough slots allocated (but don't flush to topology yet)
        if (!ensure_slots(it->second, data.size())) return -1;

        // Don't write to topology on every call — that's insane for
        // large files. Data lives in cache until sync() or unmount.

        return (ssize_t)size;
    }

    bool truncate_file(const std::string& path, size_t new_size) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm = normalize(path);

        auto it = entries_.find(norm);
        if (it == entries_.end() || it->second.is_directory) return false;

        auto cache_it = data_cache_.find(norm);
        if (cache_it != data_cache_.end()) {
            cache_it->second.resize(new_size);
        }

        it->second.size = new_size;
        it->second.modified = time(nullptr);

        // Release excess slots
        size_t need = slots_needed(new_size);
        while (it->second.slots.size() > need && need > 0) {
            uint16_t released = it->second.slots.back();
            topo_.clear_slot(released);
            allocator_.mark_free(released);
            it->second.slots.pop_back();
        }

        if (new_size == 0 && !it->second.slots.empty()) {
            topo_.clear_slot(it->second.slots[0]);
        } else if (cache_it != data_cache_.end() && new_size > 0) {
            write_to_slots(it->second.slots,
                           cache_it->second.data(), cache_it->second.size());
        }

        flush_metadata();
        return true;
    }

    bool rename_entry(const std::string& from, const std::string& to) {
        std::lock_guard<std::mutex> lock(mu_);
        std::string norm_from = normalize(from);
        std::string norm_to = normalize(to);

        auto it = entries_.find(norm_from);
        if (it == entries_.end()) return false;
        if (entries_.count(norm_to)) return false;

        std::string parent = parent_path(norm_to);
        if (!entries_.count(parent)) return false;

        FileMeta meta = it->second;
        meta.full_path = norm_to;

        auto ci = data_cache_.find(norm_from);
        if (ci != data_cache_.end()) {
            data_cache_[norm_to] = std::move(ci->second);
            data_cache_.erase(ci);
        }

        entries_.erase(it);
        entries_[norm_to] = meta;

        if (meta.is_directory) {
            std::vector<std::pair<std::string, std::string>> renames;
            for (auto& kv : entries_) {
                if (kv.first.size() > norm_from.size() &&
                    kv.first.substr(0, norm_from.size()) == norm_from &&
                    kv.first[norm_from.size()] == '/') {
                    renames.push_back({kv.first,
                        norm_to + kv.first.substr(norm_from.size())});
                }
            }
            for (auto& rp : renames) {
                FileMeta cm = entries_[rp.first];
                cm.full_path = rp.second;
                entries_.erase(rp.first);
                entries_[rp.second] = cm;
                auto di = data_cache_.find(rp.first);
                if (di != data_cache_.end()) {
                    data_cache_[rp.second] = std::move(di->second);
                    data_cache_.erase(di);
                }
            }
        }

        flush_metadata();
        return true;
    }

    void sync() {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& kv : entries_) {
            if (kv.second.is_directory) continue;
            if (kv.second.slots.empty()) continue;
            auto ci = data_cache_.find(kv.first);
            if (ci != data_cache_.end() && !ci->second.empty()) {
                write_to_slots(kv.second.slots,
                               ci->second.data(), ci->second.size());
            }
        }
        flush_metadata();
    }

    size_t slots_available() const { return allocator_.slots_free(); }

private:
    // --------------------------------------------------------
    // Multi-slot read/write helpers
    // --------------------------------------------------------

    void write_to_slots(const std::vector<uint16_t>& slots,
                        const uint8_t* data, size_t len) {
        size_t written = 0;
        for (size_t i = 0; i < slots.size() && written < len; i++) {
            size_t to_write = std::min(BYTES_PER_SLOT, len - written);
            topo_.write_slot(slots[i], data + written, to_write);
            written += to_write;
        }
    }

    size_t read_from_slots(const std::vector<uint16_t>& slots,
                           uint8_t* out, size_t max_len) const {
        size_t total = 0;
        for (size_t i = 0; i < slots.size() && total < max_len; i++) {
            size_t to_read = std::min(BYTES_PER_SLOT, max_len - total);
            size_t r = topo_.read_slot(slots[i], out + total, to_read);
            total += r;
            if (r < BYTES_PER_SLOT) break;
        }
        return total;
    }

    // Ensure a file has enough slots for its size
    bool ensure_slots(FileMeta& meta, size_t target_size) {
        size_t need = slots_needed(target_size);
        if (meta.slots.size() >= need) return true;

        size_t extra = need - meta.slots.size();
        auto new_slots = allocator_.allocate_n(extra);
        if (new_slots.empty()) return false; // ENOSPC

        for (uint16_t s : new_slots)
            meta.slots.push_back(s);
        return true;
    }

    // --------------------------------------------------------
    // Large file I/O: bypass cache, read/write directly
    // --------------------------------------------------------

    ssize_t read_large_file(const FileMeta& meta, uint8_t* buf,
                            size_t size, size_t offset) const {
        if (offset >= meta.size) return 0;
        size_t avail = meta.size - offset;
        size_t to_read = std::min(size, avail);

        // Find which slot the offset falls in
        size_t slot_idx = offset / BYTES_PER_SLOT;
        size_t slot_offset = offset % BYTES_PER_SLOT;
        size_t total_read = 0;

        // Heap-allocate slot buffer (BYTES_PER_SLOT is ~13 MB)
        std::vector<uint8_t> slot_buf(BYTES_PER_SLOT);

        while (total_read < to_read && slot_idx < meta.slots.size()) {
            size_t chunk = std::min(BYTES_PER_SLOT - slot_offset, to_read - total_read);

            size_t slot_data = topo_.read_slot(meta.slots[slot_idx],
                                                slot_buf.data(), slot_offset + chunk);

            if (slot_data <= slot_offset) break;
            size_t got = std::min(chunk, slot_data - slot_offset);
            memcpy(buf + total_read, slot_buf.data() + slot_offset, got);
            total_read += got;

            slot_idx++;
            slot_offset = 0;
        }

        return (ssize_t)total_read;
    }

    ssize_t write_large_file(FileMeta& meta, const std::string& norm,
                             const uint8_t* buf, size_t size, size_t offset) {
        // Update file size
        size_t new_end = offset + size;
        if (new_end > meta.size) meta.size = new_end;
        meta.modified = time(nullptr);

        // Ensure enough slots
        if (!ensure_slots(meta, meta.size)) return -1;

        // Find which slot the offset falls in
        size_t slot_idx = offset / BYTES_PER_SLOT;
        size_t slot_offset = offset % BYTES_PER_SLOT;
        size_t total_written = 0;

        while (total_written < size && slot_idx < meta.slots.size()) {
            size_t chunk = std::min(BYTES_PER_SLOT - slot_offset, size - total_written);

            if (slot_offset == 0 && chunk == BYTES_PER_SLOT) {
                // Full slot write — no need to read first
                topo_.write_slot(meta.slots[slot_idx], buf + total_written, chunk);
            } else {
                // Partial slot write — read-modify-write
                std::vector<uint8_t> slot_buf(BYTES_PER_SLOT, 0);
                topo_.read_slot(meta.slots[slot_idx], slot_buf.data(), BYTES_PER_SLOT);
                memcpy(slot_buf.data() + slot_offset, buf + total_written, chunk);

                size_t write_len = slot_offset + chunk;
                topo_.write_slot(meta.slots[slot_idx], slot_buf.data(), write_len);
            }

            total_written += chunk;
            slot_idx++;
            slot_offset = 0;
        }

        // Evict from cache if present (stale now)
        data_cache_.erase(norm);

        flush_metadata();
        return (ssize_t)total_written;
    }

    // --------------------------------------------------------
    // Cache
    // --------------------------------------------------------

    void ensure_cached(const std::string& norm, const FileMeta& meta) {
        if (data_cache_.count(norm)) return;
        if (meta.size > 0 && !meta.slots.empty()) {
            std::vector<uint8_t> data(meta.size);
            size_t r = read_from_slots(meta.slots, data.data(), meta.size);
            data.resize(r);
            data_cache_[norm] = std::move(data);
        } else {
            data_cache_[norm] = std::vector<uint8_t>();
        }
    }

    // --------------------------------------------------------
    // Metadata serialization
    //
    // Format:
    //   D|F \t path \t slot1,slot2,... \t size \t created \t modified \n
    // --------------------------------------------------------

    void flush_metadata() {
        std::string ser;
        for (auto& kv : entries_) {
            if (kv.first == "/") continue;
            const FileMeta& m = kv.second;
            ser += (m.is_directory ? "D" : "F");
            ser += "\t" + m.full_path + "\t";

            for (size_t i = 0; i < m.slots.size(); i++) {
                if (i > 0) ser += ",";
                ser += std::to_string(m.slots[i]);
            }

            ser += "\t" + std::to_string(m.size);
            ser += "\t" + std::to_string(m.created);
            ser += "\t" + std::to_string(m.modified);
            ser += "\n";
        }
        topo_.write_slot(META_SLOT, (const uint8_t*)ser.c_str(), ser.size());
    }

    void deserialize_all(const uint8_t* data, size_t len) {
        std::string raw((const char*)data, len);
        std::istringstream stream(raw);
        std::string line;

        while (std::getline(stream, line)) {
            if (line.empty()) continue;

            std::vector<std::string> fields;
            std::istringstream ls(line);
            std::string field;
            while (std::getline(ls, field, '\t'))
                fields.push_back(field);

            if (fields.size() < 6) continue;

            FileMeta meta;
            meta.is_directory = (fields[0] == "D");
            meta.full_path = fields[1];

            // Parse comma-separated slots
            if (!fields[2].empty()) {
                std::istringstream ss(fields[2]);
                std::string tok;
                while (std::getline(ss, tok, ',')) {
                    if (!tok.empty()) {
                        uint16_t s = (uint16_t)std::stoi(tok);
                        meta.slots.push_back(s);
                        allocator_.mark_used(s);
                    }
                }
            }

            meta.size = (size_t)std::stoull(fields[3]);
            meta.created = (time_t)std::stoll(fields[4]);
            meta.modified = (time_t)std::stoll(fields[5]);

            entries_[meta.full_path] = meta;

            // Don't eagerly cache — let ensure_cached load on first access
            // This keeps startup fast even with large files
        }
    }
};

} // namespace Emergence
#endif
