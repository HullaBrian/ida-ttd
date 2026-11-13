// SPDX-License-Identifier: GPL-2.0-only
//
// ida-ttd's Sogen backend: forks (a recording replayed to a position,
// changed and run on), writing a recording, and recording a program.
// See sogen_state.h.

#include "backend-sogen/sogen_state.h"

#include <windows_emulator.hpp>
#include <ttd_session.hpp>
#include <ttd_network.hpp>

#include <chrono>

namespace idattd::sogen
{
    // Seek a fresh emulator to the position: a checkpoint restore and up to a
    // checkpoint interval of replay, verified against the recording.
    int fork_open(ittd_backend *hb, ittd_position at_pos, const ittd_fork_settings *settings,
                  const ittd_progress *progress, ittd_fork **out)
    {
        backend_t *b = B(hb);
        if ( b == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        *out = nullptr;
        return guarded(b->error, [&]()
        {
            auto f = std::make_unique<fork_t>();
            f->owner = b;
            f->trace = open_trace(b->path);
            f->trace->set_checkpoint_cache_size(kCheckpointsPerReader);
            if ( !resolve(*f->trace, at_pos, &f->position) )
            {
                b->error.set("that position is not in the recording");
                return ITTD_E_NO_POSITION;
            }
            bool strict = false;
            f->access_kinds        = setting_access_kinds(settings);
            f->checkpoint_interval = setting_checkpoint_interval(settings, 0);
            f->emu = replay_emulator(*f->trace, settings, &strict, &f->net);
            ttd::seek(*f->emu, *f->trace, f->position, strict, control(progress));
            // A recording that logged what the network answered (every one
            // made since Sogen's network tap, 2026-11-11) is replayed from it, and the log stops the
            // emulator at the first question it has no answer for. A fork's
            // run differs from the recording, so from here on the network
            // answers again: the offline one, or the real one when the
            // settings asked for it. Sockets open at the fork position were
            // the recording's and answer as a connection the host reset.
            if ( std::optional<ttd::network_tap> tap = ttd::find_network_tap(*f->emu); tap.has_value() )
                tap->go_live();
            if ( f->net != nullptr )
                f->net->live = true;
            *out = reinterpret_cast<ittd_fork *>(f.release());
            return ITTD_OK;
        });
    }

    int fork_regs(ittd_fork *hf, ittd_regs *out)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || out == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            auto &cpu = f->emu->x64_emu();
            *out = ittd_regs{};
            for ( int i = 0; i < ITTD_REG_GP_COUNT; i++ )
                out->gp[i] = cpu.reg<uint64_t>(kGp[i]);
            out->rflags  = cpu.reg<uint64_t>(x86_register::rflags);
            // The bases belong to the segment group, which also has the
            // selectors: filling the bases but reporting only GP left them
            // looking like registers nobody read.
            out->fs_base = cpu.reg<uint64_t>(x86_register::fs_base);
            out->gs_base = cpu.reg<uint64_t>(x86_register::gs_base);
            for ( int i = 0; i < ITTD_SEG_COUNT; i++ )
                out->seg[i] = (uint16_t)cpu.reg<uint64_t>(kSeg[i]);
            out->have = ITTD_REGS_GP | ITTD_REGS_SEG;
            return ITTD_OK;
        });
    }

    int fork_set_regs(ittd_fork *hf, const ittd_regs *regs)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || regs == nullptr )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            if ( f->recorded )
                throw std::runtime_error("this fork has already run");
            auto &cpu = f->emu->x64_emu();
            if ( (regs->have & ITTD_REGS_GP) != 0 )
            {
                for ( int i = 0; i < ITTD_REG_GP_COUNT; i++ )
                    cpu.reg<uint64_t>(kGp[i], regs->gp[i]);
                cpu.reg<uint64_t>(x86_register::rflags, regs->rflags);
            }
            if ( (regs->have & ITTD_REGS_SEG) != 0 )
            {
                cpu.reg<uint64_t>(x86_register::fs_base, regs->fs_base);
                cpu.reg<uint64_t>(x86_register::gs_base, regs->gs_base);
            }
            return ITTD_OK;
        });
    }

    int fork_write_memory(ittd_fork *hf, uint64_t ea, const void *buf, size_t size)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || (buf == nullptr && size != 0) )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            if ( f->recorded )
                throw std::runtime_error("this fork has already run");
            if ( !f->emu->memory.try_write_memory(ea, buf, size) )
                throw std::runtime_error("that memory is not mapped writable in the fork");
            return ITTD_OK;
        });
    }

    // ------------------------------------------------------------ output files

    // A recording being replayed is read through std::ifstream, which shares
    // read and write but not delete: a new recording written over it would
    // change it under its reader (in this IDA or another). An exclusive open
    // fails on such a file, so it is refused before anything runs.
    void refuse_open_output(const std::filesystem::path &p)
    {
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if ( h != INVALID_HANDLE_VALUE )
        {
            CloseHandle(h);
            return;
        }
        if ( GetLastError() == ERROR_SHARING_VIOLATION || GetLastError() == ERROR_LOCK_VIOLATION )
            throw coded_error(ITTD_E_BAD_ARG, path_utf8(p) + " is open, probably as a recording being replayed "
                                              "(in this IDA or another): record into another file, or close it first");
    }

    // A recording goes into a file beside its target and is moved into place
    // once complete, so one that fails leaves the old file as it was, and
    // the target is never half-written. Replacing needs delete access, which
    // a reader that opened the target meanwhile denies: the complete
    // recording then stays under its .partial name, and the error says so.
    std::filesystem::path partial_path(const std::filesystem::path &p)
    {
        return std::filesystem::path(p.native() + L".partial");
    }

    // Deletes the .partial file of a recording that did not complete; one
    // that did is kept (kept = true) even when it cannot be moved into place.
    struct partial_guard
    {
        std::filesystem::path path;
        bool kept = false;
        ~partial_guard()
        {
            if ( !kept )
            {
                std::error_code ec;
                std::filesystem::remove(path, ec);
            }
        }
    };

    void move_into_place(const std::filesystem::path &partial, const std::filesystem::path &p)
    {
        if ( MoveFileExW(partial.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) )
            return;
        const DWORD err = GetLastError();
        throw coded_error(ITTD_E_FAILED, "the recording is complete in " + path_utf8(partial) + ", but "
                                         + path_utf8(p) + " could not be replaced (Windows error "
                                         + std::to_string(err) + "): it was opened while the recording ran");
    }

    // Record 'emu' as 'rs' asks into 'target': into its .partial file, kept
    // once complete and then moved into place.
    void record_to(::sogen::windows_emulator &emu, ttd::record_settings &rs, const std::filesystem::path &target,
                   const std::function<bool()> &interrupted)
    {
        rs.path = partial_path(target);
        partial_guard guard{ rs.path };
        ttd::record(emu, rs, interrupted);
        guard.kept = true;
        move_into_place(rs.path, target);
    }

    int fork_record(ittd_fork *hf, const char *path, uint64_t max_instructions, const char *note,
                    const ittd_progress *progress, uint64_t *out_instructions)
    {
        fork_t *f = F(hf);
        if ( f == nullptr || path == nullptr || *path == '\0' )
            return ITTD_E_BAD_ARG;
        return guarded(f->owner->error, [&]()
        {
            if ( f->recorded )
                throw std::runtime_error("this fork has already run");
            const std::filesystem::path target = utf8_path(path);
            refuse_open_output(target);
            f->recorded = true;
            ttd::record_settings rs{};
            rs.max_instructions = max_instructions;
            rs.access_mask      = f->access_kinds;
            if ( f->checkpoint_interval != 0 )
                rs.checkpoint_interval = f->checkpoint_interval;
            const std::u8string parent = f->owner->path.u8string();
            rs.manifest = {
                { "tool", "ida-ttd" },
                { "parent", std::string(parent.begin(), parent.end()) },
                { "parent_id", f->trace->id() },
                { "fork_position", std::to_string(f->position) },
            };
            if ( note != nullptr && *note != '\0' )
                rs.manifest.emplace_back("fork_changes", note);
            if ( f->net != nullptr )
                rs.manifest.emplace_back("network", "live after the fork position");
            bool stopped = false;
            std::function<bool()> interrupted;
            if ( progress != nullptr && progress->cancelled != nullptr )
                interrupted = [progress, &stopped]()
                {
                    stopped = stopped || progress->cancelled(progress->ud) != 0;
                    return stopped;
                };
            uint64_t before = f->emu->get_executed_instructions();
            record_to(*f->emu, rs, target, interrupted);
            if ( out_instructions != nullptr )
                *out_instructions = f->emu->get_executed_instructions() - before;
            // A cancelled recording is still a complete, readable trace of
            // what ran before the stop.
            return ITTD_OK;
        });
    }

    void fork_close(ittd_fork *hf)
    {
        delete F(hf);
    }

    // ------------------------------------------------------------ recording

    // UTF-8 to the UTF-16 Sogen keeps command lines in.
    std::u16string utf16(const char *s)
    {
        const std::wstring w = utf8_path(s).wstring();
        return std::u16string(w.begin(), w.end());
    }

    std::wstring lower(std::wstring s)
    {
        for ( wchar_t &c : s )
            c = (wchar_t)towlower(c);
        return s;
    }

    // The guest path ("c:\dir\x.exe") of a host path inside an emulation
    // root's file system (<root>\filesys\c\dir\x.exe), or nothing when it is
    // not in there. Windows paths compare without case.
    std::optional<std::filesystem::path> guest_path(const std::filesystem::path &root,
                                                    const std::filesystem::path &host)
    {
        std::wstring base = (root / L"filesys").lexically_normal().native();
        if ( !base.empty() && base.back() != L'\\' )
            base += L'\\';
        const std::wstring h = host.lexically_normal().native();
        if ( h.size() <= base.size() || lower(h).compare(0, base.size(), lower(base)) != 0 )
            return std::nullopt;
        const std::wstring rest = h.substr(base.size());
        const size_t slash = rest.find(L'\\');
        const std::wstring drive = rest.substr(0, slash);
        if ( drive.size() != 1 )
            return std::nullopt;
        return std::filesystem::path(drive + L":\\" + (slash == std::wstring::npos ? L"" : rest.substr(slash + 1)));
    }

    // Where a guest path lives in an emulation root: c:\dir\x -> <root>\filesys\c\dir\x.
    std::filesystem::path in_root(const std::filesystem::path &root, const std::filesystem::path &guest)
    {
        const std::wstring g = guest.native();
        if ( g.size() < 2 || g[1] != L':' )
            return {};
        std::wstring rest = g.substr(2);
        while ( !rest.empty() && (rest.front() == L'\\' || rest.front() == L'/') )
            rest.erase(rest.begin());
        return root / L"filesys" / std::wstring(1, (wchar_t)towlower(g[0])) / rest;
    }

    // A program or folder for a run in an emulation root, as the guest sees
    // it: a host path inside the root's file system becomes its guest path; a
    // path the root has (a guest path typed as such) is taken as it is; a
    // file elsewhere on this machine is refused, since the program sees only
    // the root.
    std::filesystem::path guest_for(const std::filesystem::path &root, const std::filesystem::path &given,
                                    const char *what)
    {
        if ( std::optional<std::filesystem::path> g = guest_path(root, given) )
            return *g;
        std::error_code ec;
        if ( std::filesystem::exists(in_root(root, given), ec) )
            return given;
        const std::string fs_dir = path_utf8(root / L"filesys");
        if ( std::filesystem::exists(given, ec) )
            throw coded_error(ITTD_E_BAD_ARG, std::string("the ") + what + " " + path_utf8(given)
                              + " is outside the emulation root, and a program running in it sees only "
                              + fs_dir + " (its C: drive is " + fs_dir + "\\c). Copy it in there and choose that copy");
        throw coded_error(ITTD_E_BAD_ARG, std::string("there is no ") + what + " " + path_utf8(given)
                          + " in the emulation root (" + fs_dir + ")");
    }

    // An emulation root is the folder holding filesys\ (the guest's drives)
    // and registry\ (its hives). Picking either of those instead of the root
    // is the likely mistake, so the message names the parent then.
    void check_emulation_root(const std::filesystem::path &root)
    {
        std::error_code ec;
        if ( std::filesystem::is_directory(root / L"filesys", ec) )
            return;
        std::string msg = path_utf8(root) + " is not an emulation root: an emulation root is the folder that "
                          "holds filesys\\ (the program's drives) and registry\\ (its hives)";
        const std::filesystem::path parent = root.parent_path();
        if ( std::filesystem::is_directory(parent / L"filesys", ec) )
            msg += ". Did you mean " + path_utf8(parent) + "?";
        throw coded_error(ITTD_E_BAD_ARG, msg);
    }

    // The program run from its start the way analyzer --ttd-record runs it
    // (one vCPU, Unicorn, the relative clock), against an emulation root or
    // this machine's files, recorded until it exits or the limit.
    int record_program(const ittd_record_request *req, const ittd_fork_settings *settings,
                       const ittd_progress *progress, uint64_t *out_instructions)
    {
        if ( req == nullptr || req->size < sizeof(ittd_record_request)
          || req->application == nullptr || *req->application == '\0'
          || req->out_path == nullptr || *req->out_path == '\0' )
            return ITTD_E_BAD_ARG;
        return guarded(g_module_error, [&]()
        {
            std::filesystem::path root;
            if ( const char *const *v = setting_emulation_root(settings); v != nullptr && *v != nullptr && **v != '\0' )
                root = utf8_path(*v);
            if ( !root.empty() )
                check_emulation_root(root);
            const std::filesystem::path registry = registry_for(settings, root);
            const uint32_t *flags = setting_flags(settings);
            if ( root.empty() && (flags == nullptr || (*flags & ITTD_FORK_ALLOW_HOST) == 0) )
                throw coded_error(ITTD_E_HOST_REPLAY, "without an emulation root the program runs against this "
                                                      "machine's files, and whatever it creates, changes or deletes "
                                                      "happens for real. Allow that explicitly to go ahead");
            // The recording carries what it reads of the hives, so they are
            // only needed here, to run it.
            std::string why;
            if ( check_hives("", registry, &why) == ITTD_E_NO_REGISTRY )
                throw coded_error(ITTD_E_NO_REGISTRY, "no registry hives (SYSTEM, SOFTWARE, ...) in "
                                                      + path_utf8(registry) + ": Sogen runs the program "
                                                        "against a copy of the registry, which it needs");

            // In an emulation root the program and its folder are guest paths.
            std::filesystem::path program = utf8_path(req->application);
            std::filesystem::path cwd;
            if ( req->working_dir != nullptr && *req->working_dir != '\0' )
                cwd = utf8_path(req->working_dir);
            if ( !root.empty() )
            {
                program = guest_for(root, program, "program");
                if ( !cwd.empty() )
                    cwd = guest_for(root, cwd, "working directory");
            }
            ::sogen::application_settings app{};
            app.application = ::sogen::windows_path(program);
            if ( !cwd.empty() )
                app.working_directory = ::sogen::windows_path(cwd);
            // The command line as given, after the program's quoted name: the
            // program splits it itself, so it gets exactly what was typed.
            const std::wstring pw = program.wstring();
            std::u16string line = u"\"" + std::u16string(pw.begin(), pw.end()) + u"\"";
            if ( req->arguments != nullptr && *req->arguments != '\0' )
                line += u" " + utf16(req->arguments);
            app.command_line = line;

            ::sogen::emulator_settings es{};
            es.use_relative_time  = true;
            es.emulation_root     = root;
            es.registry_directory = registry;
            es.load_registry      = true;
            es.elevated           = setting_elevated(settings);
            // Where the relative clock's system time starts (1970 at 0). The
            // checkpoints carry it, so a replay needs nothing more.
            if ( req->start_time > 0 )
                es.relative_time_start = std::chrono::system_clock::time_point(std::chrono::seconds(req->start_time));
            // From the start: there is no recorded part to reach first.
            es.network = setting_network(settings) == ITTD_NET_LIVE ? ::sogen::network::network_mode::live
                                                                     : ::sogen::network::network_mode::offline;
            auto emu = make_emulator(&app, es, settings, nullptr);

            ttd::record_settings rs{};
            const std::filesystem::path target = utf8_path(req->out_path);
            refuse_open_output(target);
            rs.access_mask        = setting_access_kinds(settings);
            rs.checkpoint_interval = setting_checkpoint_interval(settings, rs.checkpoint_interval);
            rs.max_instructions    = req->max_instructions;
            rs.manifest = { { "tool", "ida-ttd" } };
            if ( es.network == ::sogen::network::network_mode::live )
                rs.manifest.emplace_back("network", "live");
            if ( req->start_time > 0 )
                rs.manifest.emplace_back("start_time", std::to_string(req->start_time));
            std::function<bool()> interrupted;
            if ( progress != nullptr && progress->cancelled != nullptr )
                interrupted = [progress]() { return progress->cancelled(progress->ud) != 0; };
            record_to(*emu, rs, target, interrupted);
            if ( out_instructions != nullptr )
                *out_instructions = emu->get_executed_instructions();
            return ITTD_OK;
        });
    }
}
