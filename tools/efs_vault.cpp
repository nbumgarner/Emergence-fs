/*
 * efs_vault — Topology-Native Secrets Engine
 * Copyright (c) 2024-2026 Emergence Systems. All rights reserved.
 *
 * A hardware-bound credential vault where the topology IS the security.
 * No database. No server. No decrypt step. Wrong credentials = the
 * secrets structurally do not exist.
 *
 * See LICENSE for terms.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>
#include <csignal>
#include <sys/stat.h>

#include "topology.hpp"
#include "state_engine.hpp"

using namespace Emergence;

// ─── Product Info ───────────────────────────────────────────────────────────

#define EFS_VAULT_VERSION   "1.0.0"
#define EFS_VAULT_PRODUCT   "EFS Vault"
#define EFS_VAULT_COMPANY   "Emergence Systems"
#define EFS_VAULT_YEAR      "2026"

// ─── Constants ──────────────────────────────────────────────────────────────

constexpr uint16_t VAULT_META_SLOT   = 0;
constexpr uint16_t VAULT_DATA_START  = 1;
constexpr uint16_t VAULT_DATA_END    = 1000;
constexpr uint16_t VAULT_MAX_SECRETS = VAULT_DATA_END - VAULT_DATA_START + 1;

// ─── Exit codes (machine-parseable) ─────────────────────────────────────────

constexpr int EXIT_OK          = 0;
constexpr int EXIT_USAGE       = 1;
constexpr int EXIT_AUTH_FAIL   = 2;
constexpr int EXIT_NOT_FOUND   = 3;
constexpr int EXIT_FULL        = 4;
constexpr int EXIT_IO_ERROR    = 5;

// ─── Output mode ────────────────────────────────────────────────────────────

enum class OutputMode { TEXT, JSON, QUIET };
static OutputMode g_output = OutputMode::TEXT;
static bool g_stdin_secret = false;  // read secret from stdin instead of argv

static void status(const std::string& msg) {
    if (g_output == OutputMode::QUIET) return;
    if (g_output == OutputMode::JSON) return;
    std::cerr << msg;
}

// ─── Vault Entry ────────────────────────────────────────────────────────────

struct VaultEntry {
    std::string name;
    std::string secret;
    time_t      created;
    time_t      modified;
    uint32_t    version;
};

// ─── Vault ──────────────────────────────────────────────────────────────────

class Vault {
private:
    Topology    topo_;
    Seed        seed_;
    std::string image_path_;
    std::vector<VaultEntry> entries_;
    bool        dirty_;
    bool        se_built_;

    uint16_t name_to_slot(const std::string& name) const {
        // Topology-Native Trie Traversal
        // Use the seed to project the name through the state engine deterministic route
        uint16_t sym = 0;
        for (unsigned char c : name) {
            uint8_t key[32];
            memcpy(key +  0, &seed_.hi, 8); memcpy(key +  8, &seed_.lo, 8);
            memset(key + 16, 0, 16); // padding for 32 byte key
            uint8_t msg[3] = {(uint8_t)(sym & 0xFF), (uint8_t)(sym >> 8), c};
            uint8_t mac[2];
            crypto_generichash(mac, 2, msg, sizeof(msg), key, sizeof(key));
            uint16_t mac16; memcpy(&mac16, mac, 2);
            sym = mac16 & LENS_MASK;
        }
        return (uint16_t)(VAULT_DATA_START + (sym % VAULT_MAX_SECRETS));
    }

    static std::string to_hex(const std::string& s) {
        std::ostringstream oss;
        for (unsigned char c : s)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        return oss.str();
    }

    static std::string from_hex(const std::string& h) {
        std::string result;
        for (size_t i = 0; i + 1 < h.size(); i += 2) {
            unsigned int byte;
            std::sscanf(h.c_str() + i, "%02x", &byte);
            result += (char)(unsigned char)byte;
        }
        return result;
    }

    void flush_metadata() {
        std::string ser;
        for (auto& e : entries_) {
            ser += e.name + "\t";
            ser += to_hex(e.secret) + "\t";
            ser += std::to_string(e.created) + "\t";
            ser += std::to_string(e.modified) + "\t";
            ser += std::to_string(e.version) + "\n";
        }
        topo_.write_slot(VAULT_META_SLOT,
                         reinterpret_cast<const uint8_t*>(ser.c_str()),
                         ser.size());
        dirty_ = true;
    }

    void load_metadata() {
        entries_.clear();
        std::vector<uint8_t> buf(BYTES_PER_SLOT);
        size_t len = topo_.read_slot(VAULT_META_SLOT, buf.data(), buf.size());
        if (len == 0) return;

        std::string raw(reinterpret_cast<char*>(buf.data()), len);
        std::istringstream stream(raw);
        std::string line;

        while (std::getline(stream, line)) {
            if (line.empty()) continue;
            std::vector<std::string> fields;
            std::istringstream ls(line);
            std::string field;
            while (std::getline(ls, field, '\t')) fields.push_back(field);
            if (fields.size() < 5) continue;

            VaultEntry e;
            e.name     = fields[0];
            e.secret   = from_hex(fields[1]);
            e.created  = (time_t)std::stoll(fields[2]);
            e.modified = (time_t)std::stoll(fields[3]);
            e.version  = (uint32_t)std::stoul(fields[4]);
            entries_.push_back(e);
        }
    }

    VaultEntry* find_entry(const std::string& name) {
        for (auto& e : entries_)
            if (e.name == name) return &e;
        return nullptr;
    }

    // Lazily build the state engine (expensive: 1M transitions)
    StateEngine make_se() {
        StateEngine se(topo_);
        se.build_from_seed();
        return se;
    }

public:
    Vault() : dirty_(false), se_built_(false) {}

    bool open(const std::string& image_path, const char* password, const char* hwkey) {
        image_path_ = image_path;
        seed_ = KeyDerivation::derive(password, hwkey);

        FILE* fp = fopen(image_path.c_str(), "rb");
        if (fp) {
            fclose(fp);
            if (!topo_.load_image(image_path.c_str(), seed_))
                return false;
            load_metadata();
        } else {
            topo_.initialize(seed_);
        }
        return true;
    }

    bool save() {
        if (!dirty_ && entries_.empty()) return true;
        flush_metadata();
        return topo_.save_image(image_path_.c_str());
    }

    size_t count() const { return entries_.size(); }

    // ── Store ───────────────────────────────────────────────────────────────

    int store(const std::string& name, const std::string& secret) {
        VaultEntry* existing = find_entry(name);
        if (existing) {
            existing->secret   = secret;
            existing->modified = time(nullptr);
            existing->version++;
        } else {
            if (entries_.size() >= VAULT_MAX_SECRETS) return EXIT_FULL;
            VaultEntry e;
            e.name     = name;
            e.secret   = secret;
            e.created  = time(nullptr);
            e.modified = e.created;
            e.version  = 1;
            entries_.push_back(e);
        }

        uint16_t slot = name_to_slot(name);
        topo_.write_slot(slot,
                         reinterpret_cast<const uint8_t*>(secret.c_str()),
                         secret.size());
        flush_metadata();
        dirty_ = true;
        return EXIT_OK;
    }

    // ── Get ─────────────────────────────────────────────────────────���───────

    bool get(const std::string& name, std::string& out) {
        VaultEntry* e = find_entry(name);
        if (!e) return false;
        out = e->secret;
        return true;
    }

    // ── Get with metadata ───────────────────────────────────────────────────

    bool get_meta(const std::string& name, VaultEntry& out) {
        VaultEntry* e = find_entry(name);
        if (!e) return false;
        out = *e;
        return true;
    }

    // ── Delete ──────────────────────────────────────────────────────────────

    bool remove(const std::string& name) {
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (it->name == name) {
                uint16_t slot = name_to_slot(name);
                topo_.clear_slot(slot);
                entries_.erase(it);
                flush_metadata();
                dirty_ = true;
                return true;
            }
        }
        return false;
    }

    // ── List ────────────────────────────────────────────────────────────────

    const std::vector<VaultEntry>& list() const { return entries_; }

    // ── Derive ──────────────────────────────────────────────────────────────

    std::string derive(const std::string& name, const std::string& service,
                       size_t token_len = 32) {
        VaultEntry* e = find_entry(name);
        if (!e) return "";

        StateEngine se = make_se();
        se.reset(0);
        for (unsigned char c : e->secret)
            se.step((uint16_t)c);
        for (unsigned char c : service)
            se.step((uint16_t)c);

        std::vector<uint8_t> token_bytes(token_len);
        se.generate_keystream(token_bytes.data(), token_len);

        static const char b64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string token;
        for (size_t i = 0; i < token_len; i++)
            token += b64[token_bytes[i] % 64];
        return token;
    }

    // ── Derive raw bytes (for integration, hex output) ──────────────────────

    std::string derive_hex(const std::string& name, const std::string& service,
                           size_t byte_len = 32) {
        VaultEntry* e = find_entry(name);
        if (!e) return "";

        StateEngine se = make_se();
        se.reset(0);
        for (unsigned char c : e->secret)
            se.step((uint16_t)c);
        for (unsigned char c : service)
            se.step((uint16_t)c);

        std::vector<uint8_t> raw(byte_len);
        se.generate_keystream(raw.data(), byte_len);
        return to_hex(std::string(raw.begin(), raw.end()));
    }

    // ── TOTP ────────────────────────────────────────────────────────────────

    std::string totp(const std::string& name, int digits = 6) {
        VaultEntry* e = find_entry(name);
        if (!e) return "";

        uint64_t time_step = (uint64_t)time(nullptr) / 30;

        StateEngine se = make_se();
        se.reset(0);
        for (unsigned char c : e->secret)
            se.step((uint16_t)c);
        for (int i = 0; i < 8; i++)
            se.step((uint16_t)((time_step >> (i * 8)) & 0xFF));

        uint8_t buf[4];
        se.generate_keystream(buf, 4);
        uint32_t code = ((uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                         ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24));

        uint32_t mod = 1;
        for (int i = 0; i < digits; i++) mod *= 10;
        code = code % mod;

        char out[12];
        snprintf(out, sizeof(out), "%0*u", digits, code);
        return std::string(out);
    }

    // ── Info ────────────────────────────────────────────────────────────────

    std::string image_path() const { return image_path_; }
    size_t capacity() const { return VAULT_MAX_SECRETS; }
};

// ─── Signal handling for clean shutdown ─────────────────────────────────────

static Vault* g_vault_ptr = nullptr;

static void signal_handler(int sig) {
    if (g_vault_ptr) {
        g_vault_ptr->save();
    }
    _exit(128 + sig);
}

// ─── CLI Helpers ────────────────────────────────────────────────────────────

static std::string read_password(const char* prompt) {
    // Check EFS_PASSWORD env first (for scripting/CI)
    const char* env_pw = getenv("EFS_PASSWORD");
    if (env_pw) return std::string(env_pw);

    // If not a TTY, read from stdin without prompt
    if (!isatty(STDIN_FILENO)) {
        std::string pw;
        std::getline(std::cin, pw);
        return pw;
    }

    std::cerr << prompt;
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    std::string pw;
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    std::cerr << "\n";
    return pw;
}

static std::string auto_hwid() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0)
        return std::string(hostname);
    return "DEFAULT-HWID";
}

static std::string get_hwkey() {
    const char* env_hw = getenv("EFS_HWKEY");
    if (env_hw && strlen(env_hw) > 0) return std::string(env_hw);
    std::ifstream f("/etc/machine-id");
    std::string id;
    if (f >> id) return id;
    return "emergence-fallback-hwkey";
}

// ── JSON helpers ────────────────────────────────────────────────────────────

static std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8]; snprintf(buf, sizeof(buf), "\\u%04x", (int)(unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static void json_kv(const std::string& key, const std::string& val, bool last = false) {
    std::cout << "  \"" << key << "\": \"" << json_escape(val) << "\"" << (last ? "\n" : ",\n");
}

static void json_kv_int(const std::string& key, int64_t val, bool last = false) {
    std::cout << "  \"" << key << "\": " << val << (last ? "\n" : ",\n");
}

// ─── Usage ──────────────────────────────────────────────────────────────────

static void print_version() {
    std::cout << EFS_VAULT_PRODUCT << " v" << EFS_VAULT_VERSION << "\n"
              << EFS_VAULT_COMPANY << " — Topology-Native Secrets Engine\n"
              << "Post-quantum (Argon2id + 256-bit seed) · Hardware-bound · Zero-server\n";
}

static void usage(const char* argv0) {
    print_version();
    std::cerr << "\nUsage: " << argv0 << " [options] <command> [args]\n"
              << "\nCommands:\n"
              << "  store   <name> <secret>     Store or update a secret\n"
              << "  get     <name>              Retrieve a secret (stdout)\n"
              << "  derive  <name> <service>    Derive per-service token\n"
              << "  list                        List stored secret names\n"
              << "  info    <name>              Show secret metadata\n"
              << "  export                      Dump all secrets (TSV to stdout)\n"
              << "  rotate  <name> <new_secret> Rotate a secret (increments version)\n"
              << "  delete  <name>              Delete a secret\n"
              << "  totp    <name>              Generate time-based code\n"
              << "  status                      Vault status and capacity\n"
              << "\nOptions:\n"
              << "  --json                      JSON output mode\n"
              << "  --quiet, -q                 Suppress status messages\n"
              << "  --stdin                     Read secret value from stdin (store/rotate)\n"
              << "  --version, -v               Show version\n"
              << "  --help, -h                  Show this help\n"
              << "\nEnvironment:\n"
              << "  VAULT_IMAGE     Path to vault image (default: ~/.emergence_vault.img)\n"
              << "  EFS_PASSWORD    Vault password (avoids interactive prompt)\n"
              << "  EFS_HWKEY       Hardware key (avoids interactive prompt)\n"
              << "\nExamples:\n"
              << "  # Store a secret\n"
              << "  " << argv0 << " store aws-prod \"AKIA...:wJalr...\"\n"
              << "\n"
              << "  # Retrieve into env var\n"
              << "  export DB_URL=$(" << argv0 << " -q get db-prod)\n"
              << "\n"
              << "  # Derive per-service token\n"
              << "  " << argv0 << " derive aws-master api-gateway\n"
              << "\n"
              << "  # Non-interactive (CI/CD)\n"
              << "  EFS_PASSWORD=secret EFS_HWKEY=mykey " << argv0 << " -q get db-prod\n"
              << "\n"
              << "  # Pipe secret from file\n"
              << "  " << argv0 << " --stdin store tls-cert < server.pem\n";
}

// ─── Main ───────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    // Parse global options
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--json")                    g_output = OutputMode::JSON;
        else if (a == "--quiet" || a == "-q") g_output = OutputMode::QUIET;
        else if (a == "--stdin")              g_stdin_secret = true;
        else if (a == "--version" || a == "-v") { print_version(); return 0; }
        else if (a == "--help" || a == "-h")  { usage(argv[0]); return 0; }
        else args.push_back(a);
    }

    if (args.empty()) { usage(argv[0]); return EXIT_USAGE; }

    std::string op = args[0];

    // Determine vault image path
    const char* home = getenv("HOME");
    std::string image_path = home ? std::string(home) + "/.emergence_vault.img"
                                  : ".emergence_vault.img";
    const char* custom = getenv("VAULT_IMAGE");
    if (custom) image_path = custom;

    // Banner (unless quiet/json)
    if (g_output == OutputMode::TEXT) {
        std::cerr << "╭───────────────────────────────────────────────╮\n";
        std::cerr << "│  " << EFS_VAULT_PRODUCT << " v" << EFS_VAULT_VERSION
                  << " — " << EFS_VAULT_COMPANY << "  │\n";
        std::cerr << "│  Topology-native secrets engine               │\n";
        std::cerr << "╰───────────────────────────────────────────────╯\n";
    }

    // Authenticate
    std::string password = read_password("Password: ");
    if (password.empty()) {
        status("Error: password cannot be empty.\n");
        return EXIT_AUTH_FAIL;
    }

    std::string hwkey = get_hwkey();

    status("Opening vault...");

    Vault vault;
    if (!vault.open(image_path, password.c_str(), hwkey.c_str())) {
        status("\nError: wrong password or hardware key.\n");
        return EXIT_AUTH_FAIL;
    }
    status(" ok.\n");

    // Install signal handler for clean saves
    g_vault_ptr = &vault;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    int rc = EXIT_OK;

    // ── Dispatch ────────────────────────────────────────────────────────────

    if (op == "store" || op == "rotate") {
        std::string name, secret;
        if (args.size() < 2) {
            std::cerr << "Usage: store <name> <secret>\n"; return EXIT_USAGE;
        }
        name = args[1];

        if (g_stdin_secret) {
            // Read secret from stdin (for binary/multiline secrets)
            std::ostringstream oss;
            oss << std::cin.rdbuf();
            secret = oss.str();
            // Strip trailing newline if present
            if (!secret.empty() && secret.back() == '\n') secret.pop_back();
        } else {
            if (args.size() < 3) {
                std::cerr << "Usage: " << op << " <name> <secret> (or use --stdin)\n";
                return EXIT_USAGE;
            }
            secret = args[2];
        }

        rc = vault.store(name, secret);
        if (rc == EXIT_OK) {
            if (g_output == OutputMode::JSON) {
                std::cout << "{\n";
                json_kv("status", "ok");
                json_kv("command", op);
                json_kv("name", name, true);
                std::cout << "}\n";
            } else {
                status(std::string(op == "rotate" ? "Rotated" : "Stored") + ": " + name + "\n");
            }
        } else {
            status("Error: vault full (" + std::to_string(VAULT_MAX_SECRETS) + " max).\n");
        }

    } else if (op == "get") {
        if (args.size() < 2) { std::cerr << "Usage: get <name>\n"; return EXIT_USAGE; }
        std::string secret;
        if (vault.get(args[1], secret)) {
            if (g_output == OutputMode::JSON) {
                std::cout << "{\n";
                json_kv("name", args[1]);
                json_kv("value", secret, true);
                std::cout << "}\n";
            } else {
                std::cout << secret << "\n";
            }
        } else {
            status("Error: '" + args[1] + "' not found.\n");
            rc = EXIT_NOT_FOUND;
        }

    } else if (op == "info") {
        if (args.size() < 2) { std::cerr << "Usage: info <name>\n"; return EXIT_USAGE; }
        VaultEntry e;
        if (vault.get_meta(args[1], e)) {
            if (g_output == OutputMode::JSON) {
                std::cout << "{\n";
                json_kv("name", e.name);
                json_kv_int("version", e.version);
                json_kv_int("size", (int64_t)e.secret.size());
                json_kv_int("created", (int64_t)e.created);
                json_kv_int("modified", (int64_t)e.modified, true);
                std::cout << "}\n";
            } else {
                char created[20], modified[20];
                strftime(created, sizeof(created), "%Y-%m-%d %H:%M:%S", localtime(&e.created));
                strftime(modified, sizeof(modified), "%Y-%m-%d %H:%M:%S", localtime(&e.modified));
                std::cout << "Name:     " << e.name << "\n"
                          << "Version:  v" << e.version << "\n"
                          << "Size:     " << e.secret.size() << " bytes\n"
                          << "Created:  " << created << "\n"
                          << "Modified: " << modified << "\n";
            }
        } else {
            status("Error: '" + args[1] + "' not found.\n");
            rc = EXIT_NOT_FOUND;
        }

    } else if (op == "derive") {
        if (args.size() < 3) { std::cerr << "Usage: derive <name> <service>\n"; return EXIT_USAGE; }
        status("Building state machine...");
        std::string token = vault.derive(args[1], args[2]);
        if (!token.empty()) {
            status(" ok.\n");
            if (g_output == OutputMode::JSON) {
                std::cout << "{\n";
                json_kv("name", args[1]);
                json_kv("service", args[2]);
                json_kv("token", token);
                json_kv_int("length", (int64_t)token.size(), true);
                std::cout << "}\n";
            } else {
                std::cout << token << "\n";
            }
        } else {
            status("\nError: '" + args[1] + "' not found.\n");
            rc = EXIT_NOT_FOUND;
        }

    } else if (op == "list") {
        auto& entries = vault.list();
        if (g_output == OutputMode::JSON) {
            std::cout << "[\n";
            for (size_t i = 0; i < entries.size(); i++) {
                auto& e = entries[i];
                std::cout << "  {\"name\": \"" << json_escape(e.name)
                          << "\", \"version\": " << e.version
                          << ", \"size\": " << e.secret.size()
                          << ", \"created\": " << e.created
                          << ", \"modified\": " << e.modified
                          << "}" << (i + 1 < entries.size() ? "," : "") << "\n";
            }
            std::cout << "]\n";
        } else {
            if (entries.empty()) {
                status("(vault is empty)\n");
            } else {
                std::cout << std::left
                          << std::setw(28) << "NAME"
                          << std::setw(10) << "VERSION"
                          << std::setw(8) << "SIZE"
                          << std::setw(22) << "CREATED"
                          << "MODIFIED" << "\n";
                std::cout << std::string(90, '-') << "\n";
                for (auto& e : entries) {
                    char created[20], modified[20];
                    strftime(created, sizeof(created), "%Y-%m-%d %H:%M:%S", localtime(&e.created));
                    strftime(modified, sizeof(modified), "%Y-%m-%d %H:%M:%S", localtime(&e.modified));
                    std::cout << std::left
                              << std::setw(28) << e.name
                              << std::setw(10) << ("v" + std::to_string(e.version))
                              << std::setw(8) << (std::to_string(e.secret.size()) + "B")
                              << std::setw(22) << created
                              << modified << "\n";
                }
            }
        }

    } else if (op == "export") {
        auto& entries = vault.list();
        if (g_output == OutputMode::JSON) {
            std::cout << "[\n";
            for (size_t i = 0; i < entries.size(); i++) {
                auto& e = entries[i];
                std::cout << "  {\"name\": \"" << json_escape(e.name)
                          << "\", \"value\": \"" << json_escape(e.secret) << "\"}"
                          << (i + 1 < entries.size() ? "," : "") << "\n";
            }
            std::cout << "]\n";
        } else {
            for (auto& e : entries)
                std::cout << e.name << "\t" << e.secret << "\n";
        }
        status("Exported " + std::to_string(entries.size()) + " secret(s).\n");

    } else if (op == "delete") {
        if (args.size() < 2) { std::cerr << "Usage: delete <name>\n"; return EXIT_USAGE; }
        if (vault.remove(args[1])) {
            if (g_output == OutputMode::JSON) {
                std::cout << "{\"status\": \"deleted\", \"name\": \""
                          << json_escape(args[1]) << "\"}\n";
            } else {
                status("Deleted: " + args[1] + "\n");
            }
        } else {
            status("Error: '" + args[1] + "' not found.\n");
            rc = EXIT_NOT_FOUND;
        }

    } else if (op == "totp") {
        if (args.size() < 2) { std::cerr << "Usage: totp <name>\n"; return EXIT_USAGE; }
        status("Building state machine...");
        std::string code = vault.totp(args[1]);
        if (!code.empty()) {
            status(" ok.\n");
            int remaining = 30 - (int)(time(nullptr) % 30);
            if (g_output == OutputMode::JSON) {
                std::cout << "{\n";
                json_kv("name", args[1]);
                json_kv("code", code);
                json_kv_int("expires_in", remaining, true);
                std::cout << "}\n";
            } else {
                std::cout << code << "\n";
                status("Valid for ~" + std::to_string(remaining) + "s\n");
            }
        } else {
            status("\nError: '" + args[1] + "' not found.\n");
            rc = EXIT_NOT_FOUND;
        }

    } else if (op == "status") {
        if (g_output == OutputMode::JSON) {
            std::cout << "{\n";
            json_kv("product", std::string(EFS_VAULT_PRODUCT) + " v" + EFS_VAULT_VERSION);
            json_kv("image", vault.image_path());
            json_kv_int("secrets", (int64_t)vault.count());
            json_kv_int("capacity", (int64_t)vault.capacity());
            json_kv_int("available", (int64_t)(vault.capacity() - vault.count()), true);
            std::cout << "}\n";
        } else {
            struct stat st;
            std::string img_size = "new";
            if (stat(vault.image_path().c_str(), &st) == 0)
                img_size = std::to_string(st.st_size / 1024 / 1024) + " MB";

            std::cout << "Product:   " << EFS_VAULT_PRODUCT << " v" << EFS_VAULT_VERSION << "\n"
                      << "Image:     " << vault.image_path() << " (" << img_size << ")\n"
                      << "Secrets:   " << vault.count() << " / " << vault.capacity() << "\n"
                      << "Available: " << (vault.capacity() - vault.count()) << " slots\n"
                      << "Security:  Argon2id (64 MB, 3 iterations) → 256-bit seed\n"
                      << "PQ level:  128-bit (Grover bound)\n";
        }

    } else {
        std::cerr << "Unknown command: " << op << "\n";
        std::cerr << "Run with --help for usage.\n";
        return EXIT_USAGE;
    }

    // Save on mutation
    if (op == "store" || op == "rotate" || op == "delete") {
        status("Saving...");
        if (vault.save()) {
            status(" ok.\n");
        } else {
            status(" FAILED.\n");
            rc = EXIT_IO_ERROR;
        }
    }

    return rc;
}
