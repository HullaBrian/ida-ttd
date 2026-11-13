// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: the emulator a replay, a fork or a recording
// runs in, and what decides how it is set up (registry hives, the fork
// settings, the log relay, the network gate).
// See sogen_state.h.

#include "backend-sogen/sogen_state.h"

#include <windows_emulator.hpp>
#include <ttd_session.hpp>
#include <ttd_ui.hpp>
#include <unicorn_x86_64_emulator.hpp>
#include <platform/ui_backend.hpp>
#include <platform/console_backend.hpp>
#include <network/dns_lookup.hpp>
#include <network/socket_factory.hpp>
#include <network/socket_wrapper.hpp>

#include <chrono>

namespace idattd::sogen
{
    // ------------------------------------------------------------ forks

    // The folder this DLL was loaded from; the default registry folder is
    // "registry" beside it.
    std::filesystem::path module_dir()
    {
        HMODULE self = nullptr;
        wchar_t buf[MAX_PATH] = {};
        if ( GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                              | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(&module_dir), &self)
          && GetModuleFileNameW(self, buf, MAX_PATH) != 0 )
            return std::filesystem::path(buf).parent_path();
        return std::filesystem::current_path();
    }

    std::string manifest_value(const ttd::trace &t, std::string_view key)
    {
        for ( const auto &[k, v] : t.manifest() )
            if ( k == key )
                return v;
        return std::string();
    }

    // For messages: the ABI's text is UTF-8, and path::string() throws on a
    // character missing from the ANSI code page.
    std::string path_utf8(const std::filesystem::path &p)
    {
        const std::u8string s = p.u8string();
        return std::string(s.begin(), s.end());
    }

    // ------------------------------------------------------------ registry hives

    // The hives Sogen loads, in the order it fingerprints them.
    constexpr const char *kHives[] = { "SYSTEM", "SECURITY", "SAM", "SOFTWARE", "HARDWARE", "NTUSER.DAT" };

    // ttd::registry_fingerprint (the manifest's "registry" value for a folder
    // of hives), cached until a hive changes size or time: the hives are well
    // over 100 MB, and the core checks a folder before every replay.
    std::string hive_fingerprint(const std::filesystem::path &dir)
    {
        std::wstring key = dir.native();
        for ( const char *hive : kHives )
        {
            std::error_code ec;
            const auto size = std::filesystem::file_size(dir / hive, ec);
            const auto when = std::filesystem::last_write_time(dir / hive, ec);
            key += L'|' + std::to_wstring(ec ? 0 : size) + L':'
                 + std::to_wstring(ec ? 0 : when.time_since_epoch().count());
        }
        static std::mutex mtx;
        static std::map<std::wstring, std::string> cache;
        {
            std::lock_guard<std::mutex> lock(mtx);
            if ( auto it = cache.find(key); it != cache.end() )
                return it->second;
        }
        std::string fp = ttd::registry_fingerprint(dir);
        std::lock_guard<std::mutex> lock(mtx);
        return cache.emplace(key, std::move(fp)).first->second;
    }

    // The manifest's "system_dlls" value for the System32 a replay would load
    // from: the emulation root's filesys\c\windows\system32, or this machine's
    // own for a recording made against the host. Assumes the guest's Windows
    // is C:\Windows (environment_differences reads the real system root from
    // the hives, which may be absent here when the recording carries them),
    // so a difference is only a warning.
    std::string system_dll_fingerprint(const std::string &root)
    {
        std::filesystem::path sys;
        if ( root.empty() )
        {
            wchar_t buf[MAX_PATH] = {};
            const UINT n = GetSystemWindowsDirectoryW(buf, MAX_PATH);
            if ( n == 0 || n >= MAX_PATH )
                return std::string();
            sys = std::filesystem::path(buf) / L"System32";
        }
        else
        {
            // The root comes from the recording: never reach out to a share
            // it names, only to say whether the DLLs match.
            if ( !idattd::is_local_drive_path(root.c_str()) )
                return std::string();
            sys = utf8_path(root.c_str()) / L"filesys" / L"c" / L"windows" / L"system32";
        }
        return ttd::system_dll_fingerprint(sys);
    }

    // Whether 'dir' holds the hives a recording that names 'recorded' was
    // made with (check_registry's codes), and why not, in words.
    int check_hives(const std::string &recorded, const std::filesystem::path &dir, std::string *why)
    {
        if ( !std::filesystem::is_regular_file(dir / "SYSTEM") )
        {
            *why = "no registry hives (SYSTEM, SOFTWARE, ...) in " + path_utf8(dir)
                 + ": Sogen's emulator reads the program's registry from them, whether it "
                   "records a program or replays one";
            return ITTD_E_NO_REGISTRY;
        }
        if ( recorded.empty() )
            return ITTD_REGISTRY_UNVERIFIED;
        const std::string found = hive_fingerprint(dir);
        if ( found == recorded )
            return ITTD_OK;
        *why = "the registry hives in " + path_utf8(dir) + " are not the ones this recording was made "
               "with (it names hives " + recorded + "; these are " + found + "). A replay with them "
               "diverges wherever the program reads a key that differs. The right ones are the very "
               "files Sogen was given when it recorded";
        return ITTD_E_REGISTRY_MISMATCH;
    }

    // The setting at 'offset' (offsetof the field), if the caller's struct is
    // new enough to carry it. An offset, not &s->field, which is undefined
    // for a null 's'.
    template <typename T>
    const T *setting(const ittd_fork_settings *s, size_t offset)
    {
        if ( s == nullptr || offset + sizeof(T) > s->size )
            return nullptr;
        return reinterpret_cast<const T *>(reinterpret_cast<const char *>(s) + offset);
    }

    const char *const *setting_registry_dir(const ittd_fork_settings *s)
    {
        return setting<const char *>(s, offsetof(ittd_fork_settings, registry_dir));
    }

    const char *const *setting_emulation_root(const ittd_fork_settings *s)
    {
        return setting<const char *>(s, offsetof(ittd_fork_settings, emulation_root));
    }

    const uint32_t *setting_flags(const ittd_fork_settings *s)
    {
        return setting<uint32_t>(s, offsetof(ittd_fork_settings, flags));
    }

    // The ABI 3 settings, each with what an older caller (a smaller struct)
    // gets.
    uint32_t setting_network(const ittd_fork_settings *s)
    {
        const uint32_t *v = setting<uint32_t>(s, offsetof(ittd_fork_settings, network));
        return v != nullptr && *v == ITTD_NET_LIVE ? ITTD_NET_LIVE : ITTD_NET_OFFLINE;
    }

    bool setting_elevated(const ittd_fork_settings *s)
    {
        const uint32_t *v = setting<uint32_t>(s, offsetof(ittd_fork_settings, elevated));
        return v != nullptr && *v != 0;
    }

    // What a recording keeps, as Sogen's access kinds. The kernel's writes
    // into the program (host_write) are always kept: a replay of the result
    // puts them back where a syscall's live result differs from the recorded
    // one, so a recording without them could not be forked reliably.
    uint64_t setting_access_kinds(const ittd_fork_settings *s)
    {
        const uint32_t *v = setting<uint32_t>(s, offsetof(ittd_fork_settings, access_mask));
        const uint32_t mask = v != nullptr ? *v : 0;
        if ( mask == 0 )
            return ttd::all_access_kinds;
        uint64_t kinds = static_cast<uint64_t>(ttd::access_kind::host_write);
        if ( (mask & ITTD_ACCESS_READ) != 0 )
            kinds |= static_cast<uint64_t>(ttd::access_kind::read);
        if ( (mask & ITTD_ACCESS_WRITE) != 0 )
            kinds |= static_cast<uint64_t>(ttd::access_kind::write);
        if ( (mask & ITTD_ACCESS_EXEC) != 0 )
            kinds |= static_cast<uint64_t>(ttd::access_kind::execute);
        return kinds;
    }

    // 0 keeps ttd::record_settings' own default.
    uint64_t setting_checkpoint_interval(const ittd_fork_settings *s, uint64_t fallback)
    {
        const uint64_t *v = setting<uint64_t>(s, offsetof(ittd_fork_settings, checkpoint_interval));
        return v != nullptr && *v != 0 ? *v : fallback;
    }

    // The folder of registry hives a run in emulation root 'root' (none: this
    // machine's files) loads. windows_emulator loads <root>\registry whenever
    // there is a root and ignores registry_directory, so that is the folder
    // to check; without one, the settings' folder, else "registry" beside
    // this DLL.
    std::filesystem::path registry_for(const ittd_fork_settings *settings, const std::filesystem::path &root)
    {
        if ( !root.empty() )
            return root / "registry";
        if ( const char *const *v = setting_registry_dir(settings); v != nullptr && *v != nullptr && **v != '\0' )
            return utf8_path(*v);
        return module_dir() / "registry";
    }

    // Sogen's log and the program's console output, a line at a time, to the
    // caller's callback. The logger hands over text as printed, a line or
    // less or several at once, so whole lines are cut out here; what is left
    // at the end goes out when the emulator (which holds the relay through
    // its logger and callbacks) is destroyed.
    struct log_relay
    {
        void (*fn)(void *, const char *) = nullptr;
        void *ctx = nullptr;
        std::mutex lock;
        std::string pending;

        void add(std::string_view text)
        {
            std::lock_guard<std::mutex> g(lock);
            pending.append(text.data(), text.size());
            size_t start = 0;
            for ( size_t nl; (nl = pending.find('\n', start)) != std::string::npos; start = nl + 1 )
            {
                std::string line = pending.substr(start, nl - start);
                if ( !line.empty() && line.back() == '\r' )
                    line.pop_back();
                fn(ctx, line.c_str());
            }
            pending.erase(0, start);
        }

        ~log_relay()
        {
            if ( !pending.empty() )
                fn(ctx, pending.c_str());
        }
    };

    std::shared_ptr<log_relay> make_log_relay(const ittd_fork_settings *s)
    {
        using log_fn = void (*)(void *, const char *);
        const log_fn *fn = setting<log_fn>(s, offsetof(ittd_fork_settings, log));
        if ( fn == nullptr || *fn == nullptr )
            return nullptr;
        auto relay = std::make_shared<log_relay>();
        relay->fn = *fn;
        if ( void *const *ctx = setting<void *>(s, offsetof(ittd_fork_settings, log_ctx)); ctx != nullptr )
            relay->ctx = *ctx;
        return relay;
    }

    struct gated_dns_lookup : ::sogen::network::dns_lookup
    {
        std::shared_ptr<net_gate> gate;
        std::unique_ptr<::sogen::network::dns_lookup> offline =
            ::sogen::network::create_dns_lookup(::sogen::network::network_mode::offline);
        std::unique_ptr<::sogen::network::dns_lookup> live =
            ::sogen::network::create_dns_lookup(::sogen::network::network_mode::live);

        explicit gated_dns_lookup(std::shared_ptr<net_gate> g) : gate(std::move(g)) {}

        std::vector<::sogen::network::address> resolve_host(std::string_view hostname,
                                                         std::optional<int> family) override
        {
            return (gate->live ? live : offline)->resolve_host(hostname, family);
        }
    };

    struct gated_socket_factory : ::sogen::network::socket_factory
    {
        std::shared_ptr<net_gate> gate;
        std::unique_ptr<::sogen::network::socket_factory> offline =
            ::sogen::network::create_socket_factory(::sogen::network::network_mode::offline);
        std::unique_ptr<::sogen::network::socket_factory> live =
            ::sogen::network::create_socket_factory(::sogen::network::network_mode::live);

        explicit gated_socket_factory(std::shared_ptr<net_gate> g) : gate(std::move(g)) {}

        std::unique_ptr<::sogen::network::i_socket> create_socket(int af, int type, int protocol) override
        {
            return (gate->live ? live : offline)->create_socket(af, type, protocol);
        }

        int poll_sockets(std::span<::sogen::network::poll_entry> entries) override
        {
            return poll(entries, std::nullopt);
        }

        // A pending request on a host socket waits here for the host (up to
        // 10 s of real time, during which guest time stands still), so the
        // guest's own timeouts do not run out first. Only the real sockets
        // wait, and not at all when a loopback socket is already ready.
        int wait_for_sockets(std::span<::sogen::network::poll_entry> entries, std::chrono::milliseconds wait) override
        {
            return poll(entries, wait);
        }

        std::vector<::sogen::network::address> get_local_addresses(int family) override
        {
            return (gate->live ? live : offline)->get_local_addresses(family);
        }

      private:
        int poll(std::span<::sogen::network::poll_entry> entries, std::optional<std::chrono::milliseconds> wait)
        {
            // The real factory's sockets are socket_wrappers (and it throws on
            // any other); the loopback factory skips what is not its own.
            std::vector<::sogen::network::poll_entry> real, loop;
            std::vector<size_t> real_at, loop_at;
            for ( size_t i = 0; i < entries.size(); i++ )
            {
                const bool is_real = dynamic_cast<::sogen::network::socket_wrapper *>(entries[i].s) != nullptr;
                (is_real ? real : loop).push_back(entries[i]);
                (is_real ? real_at : loop_at).push_back(i);
            }
            int ready = 0;
            if ( !loop.empty() )
                ready += std::max(0, offline->poll_sockets(loop));
            if ( !real.empty() )
                ready += std::max(0, wait.has_value() && ready == 0 ? live->wait_for_sockets(real, *wait)
                                                                    : live->poll_sockets(real));
            for ( size_t i = 0; i < loop.size(); i++ )
                entries[loop_at[i]] = loop[i];
            for ( size_t i = 0; i < real.size(); i++ )
                entries[real_at[i]] = real[i];
            return ready;
        }
    };

    // What every emulator here has: Unicorn, the relative clock, a headless
    // UI whose window input can be recorded and replayed, no console input
    // from this process (inside IDA there is none to give), the log as the
    // settings ask, the CPUID overrides, and the checks TTD needs. 'gate',
    // when given, has the network follow it (gated_socket_factory). 'app',
    // when given, is the program to run from its start, and is moved from.
    std::unique_ptr<::sogen::windows_emulator> make_emulator(::sogen::application_settings *app,
                                                           ::sogen::emulator_settings es,
                                                           const ittd_fork_settings *settings,
                                                           const std::shared_ptr<net_gate> &gate)
    {
        // One vCPU and instruction precision, so the instruction hook may keep
        // the kernel lock from one instruction to the next instead of taking
        // it for each (Sogen's analyzer does the same). Nothing here waits,
        // inside a hook, for another thread that takes it: progress and log
        // callbacks only queue.
        es.keep_kernel_lock_between_instructions = true;
        ::sogen::emulator_interfaces ifs{};
        ifs.ui = std::make_unique<ttd::recordable_ui_backend>(std::make_unique<::sogen::null_ui_backend>());
        ifs.console = std::make_unique<::sogen::null_console_backend>();
        if ( gate != nullptr )
        {
            ifs.dns_lookup     = std::make_unique<gated_dns_lookup>(gate);
            ifs.socket_factory = std::make_unique<gated_socket_factory>(gate);
        }
        ::sogen::emulator_callbacks cbs{};
        const std::shared_ptr<log_relay> relay = make_log_relay(settings);
        if ( relay != nullptr )
        {
            cbs.on_stdout = [relay](std::string_view data) { relay->add(data); };
            // Most generic accesses are every file and key the program opens;
            // these two say the emulator has no answer for something, which is
            // where a program that fails quietly usually stopped.
            cbs.on_generic_access = [relay](std::string_view type, std::u16string_view name)
            {
                if ( type != "Rejecting message to unknown port" && type != "Opening unsupported device" )
                    return;
                std::string line(type);
                line += ": ";
                line += ::sogen::u16_to_u8(name);
                line += "\n";
                relay->add(line);
            };
        }
        auto emu = app != nullptr
                 ? std::make_unique<::sogen::windows_emulator>(::sogen::unicorn::create_x86_64_emulator(), std::move(*app),
                                                             es, std::move(cbs), std::move(ifs))
                 : std::make_unique<::sogen::windows_emulator>(::sogen::unicorn::create_x86_64_emulator(), es,
                                                             std::move(cbs), std::move(ifs));
        // Nothing reads emulator_settings::disable_logging any more; the
        // logger's own switch keeps its output off this process's stdout.
        emu->log.disable_output(true);
        if ( relay != nullptr )
            emu->log.set_sink([relay](::sogen::color, std::string_view message) { relay->add(message); });
        ttd::install_cpuid_overrides(*emu);
        ttd::require_deterministic(*emu);
        return emu;
    }

    // An emulator set up to replay 't' the way Sogen records: Unicorn, the
    // relative clock, the CPUID overrides, and a headless UI that takes the
    // recorded window input. 'strict' is set from the settings. With 'gate'
    // given and the settings asking for the network, the network follows the
    // gate (fork_open opens it at the fork's position); otherwise it stays
    // offline, as a replay of the recording itself must.
    std::unique_ptr<::sogen::windows_emulator> replay_emulator(const ttd::trace &t, const ittd_fork_settings *settings,
                                                             bool *strict, std::shared_ptr<net_gate> *gate)
    {
        const std::string recorded_root = manifest_value(t, "emulation_root");
        std::filesystem::path root = utf8_path(recorded_root.c_str());
        *strict = false;
        if ( const char *const *v = setting_emulation_root(settings); v != nullptr && *v != nullptr )
        {
            root = utf8_path(*v);
        }
        else if ( !recorded_root.empty() && !idattd::is_local_drive_path(recorded_root.c_str()) )
        {
            // The root comes from the recording, which anyone may have made:
            // a UNC path would have Windows connect to that host (and offer
            // the user's credentials) as soon as the replay looked there.
            throw coded_error(ITTD_E_FAILED, "this recording names the emulation root \"" + recorded_root
                                             + "\", which is not a folder on a local drive. Give the emulation "
                                               "root explicitly to replay it");
        }
        const std::filesystem::path registry = registry_for(settings, root);
        bool allow_host = false, any_registry = false;
        if ( const uint32_t *v = setting_flags(settings); v != nullptr )
        {
            *strict      = (*v & ITTD_FORK_STRICT) != 0;
            allow_host   = (*v & ITTD_FORK_ALLOW_HOST) != 0;
            any_registry = (*v & ITTD_FORK_ANY_REGISTRY) != 0;
        }
        // Against the host, the program's file operations reach this machine
        // for real, so only on request. (The network stays offline unless
        // the settings open it, and then only past a fork's position.)
        if ( root.empty() && !allow_host )
            throw coded_error(ITTD_E_HOST_REPLAY, "this recording was made against the host, not an emulation root: "
                                     "replaying it runs the program's file operations (creating, changing, "
                                     "deleting files) on this machine again. Allow that explicitly to go ahead");
        std::string why;
        const int hives = check_hives(manifest_value(t, "registry"), registry, &why);
        // A recording that carries what it read of its hives replays without
        // hive files (Sogen serves the registry from it in seek, run_to and
        // replay_to_end). The recording's own hive files are still loaded
        // when present, so a fork can read further than the recording did;
        // other hives would answer differently and are left out.
        const bool carried = t.has_registry_hives();
        const bool load = !carried || hives == ITTD_OK;
        // Without carried hives, wrong ones are refused (unless asked for)
        // before the replay spends minutes reaching the divergence.
        if ( !carried && (hives == ITTD_E_NO_REGISTRY || (hives == ITTD_E_REGISTRY_MISMATCH && !any_registry)) )
            throw coded_error(hives, why);

        ::sogen::emulator_settings es{};
        es.disable_logging    = true;
        es.use_relative_time  = true;
        es.emulation_root     = root;
        es.registry_directory = registry;
        es.load_registry      = load;
        // The emulator's own mode stays offline even for a fork that goes
        // live (it decides, once, what the network device shows); the gate
        // switches what sockets and name lookups reach.
        es.network            = ::sogen::network::network_mode::offline;
        std::shared_ptr<net_gate> g;
        if ( gate != nullptr && setting_network(settings) == ITTD_NET_LIVE )
        {
            g = std::make_shared<net_gate>();
            *gate = g;
        }
        return make_emulator(nullptr, es, settings, g);
    }
}
