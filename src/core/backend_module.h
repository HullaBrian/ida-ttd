#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // A backend DLL, seen through the C++ interface the core uses.
    //
    // The DLL exports one function and speaks the flat C ABI in
    // abi/ida_ttd_backend.h; this class is the translation between that and
    // ITraceBackend, and nothing more. It never adds behaviour a backend does
    // not have: an entry point the table leaves NULL becomes a query that did
    // not run, a navigation that Failed, or an empty list.
    //
    // The DLL stays loaded for the life of the process. The ABI says the table
    // is static and the core keeps the pointer, and unloading from a static
    // destructor would run under the loader lock.
    class BackendModule : public ITraceBackend
    {
    public:
        // Wraps 'api', which the module at 'path' returned for this core's
        // ABI version.
        BackendModule(const ittd_backend_api *api, const qstring &path);
        ~BackendModule() override;

        const char *id() const override;
        const char *display_name() const override;
        bool        can_open(const char *path) const override;
        const char *file_filter() const override;

        bool open(const char *path, qstring *errbuf) override;
        void close() override;
        bool is_open() const override { return m_handle != nullptr; }
        const TraceInfo    &info() const override { return m_info; }
        const Capabilities &capabilities() const override { return m_caps; }
        bool prepare(ProgressSink *progress) override;
        bool prepared() const override;

        qstring     format_position(Position p) const override;
        bool        parse_position(const char *text, Position *out) const override;
        const char *position_syntax() const override;

        CursorPtr make_cursor() override;
        std::unique_ptr<INavigator> make_navigator(ITraceCursor *cursor) override;

        std::vector<ModuleInfo> modules() const override;
        std::vector<ThreadInfo> threads() const override;
        std::vector<TraceEvent> timeline() const override;

        QueryResult query_accesses(ea_t lo, ea_t hi, uint8_t kinds, PositionRange when,
                                   std::vector<Access> *out, ProgressSink *progress) override;
        QueryResult query_executed(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                   std::vector<ea_t> *out, ProgressSink *progress) override;
        QueryResult query_calls(const std::vector<ea_t> &targets, PositionRange when,
                                std::vector<CallEvent> *out, ProgressSink *progress) override;
        QueryResult query_indirect_targets(const std::vector<std::pair<ea_t, ea_t>> &ranges,
                                           bool jumps,
                                           std::map<ea_t, std::vector<IndirectTarget>> *out,
                                           ProgressSink *progress) override;
        QueryResult query_exceptions(std::vector<ExceptionEvent> *out,
                                     ProgressSink *progress) override;
        QueryResult query_syscalls(std::vector<SyscallEvent> *out,
                                   ProgressSink *progress) override;
        QueryResult query_self_modifying(std::vector<SelfModHit> *out,
                                         ProgressSink *progress) override;
        ForkResult  record_fork(const ForkRequest &req, ProgressSink *progress) override;
        QueryResult query_strings(const ReplaySettings &settings, uint32_t min_length,
                                  std::vector<StringHit> *out, ProgressSink *progress) override;
        QueryResult query_buffers(const ReplaySettings &settings,
                                  std::vector<BufferHit> *out, ProgressSink *progress) override;
        QueryResult query_mapping_changes(std::vector<ittd_mapping_change> *out,
                                          std::vector<qstring> *files,
                                          ProgressSink *progress) override;
        Position position_add(Position p, int64_t delta) const override;
        bool query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                               Position *call_pos, ea_t *entry) override;
        QueryResult query_instructions(PositionRange when, uint32_t tid, size_t max,
                                       std::vector<Access> *out, ProgressSink *progress) override;
        QueryResult registers_at(const std::vector<Position> &positions,
                                 std::vector<ittd_regs> *out,
                                 ProgressSink *progress) override;

        std::vector<Symbol> module_symbols(ea_t base) override;
        std::vector<std::pair<ea_t, ea_t>> module_functions(ea_t base) override;

        // The file the module was loaded from, for messages.
        const qstring &path() const { return m_path; }
        // The backend's own reason for its last failure on the open trace.
        qstring last_error() const override;

    private:
        const ittd_backend_api *m_api = nullptr;
        qstring       m_path;
        ittd_backend *m_handle = nullptr;
        bool          m_prepared = false;
        TraceInfo     m_info;
        Capabilities  m_caps;
    };

    // Load every backend DLL in IDA's plugins/ida-ttd-backends and
    // plugins/ida-ttd/ida-ttd-backends directories -- the user's and the
    // installation's -- and add the ones that answer for
    // this core's ABI version to BackendRegistry. A module that fails to load,
    // or answers for another version, is named in the output window and
    // skipped. Safe to call more than once; later calls do nothing.
    void load_backend_modules();
}
