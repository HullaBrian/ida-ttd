#pragma once

#include "common/pch.h"
#include "core/backend.h"

namespace idattd
{
    // A backend DLL, seen through the C++ interface the core uses.
    //
    // A pure translation between the C ABI (abi/ida_ttd_backend.h) and
    // ITraceBackend that adds no behaviour: an entry the table leaves NULL
    // becomes a query that did not run, a navigation that Failed, or an empty
    // list.
    //
    // The DLL stays loaded for the life of the process: the table is static
    // and the core keeps the pointer, and unloading from a static destructor
    // would run under the loader lock.
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
        // The same module's table: every open() of it is a separate backend.
        std::unique_ptr<ITraceBackend> new_instance() const override
        { return std::make_unique<BackendModule>(m_api, m_path); }

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
        QueryResult query_access_heat(uint32_t page_shift, uint32_t slices,
                                      std::vector<HeatCell> *out, ProgressSink *progress) override;
        Position heat_slice_position(uint32_t slices, uint32_t slice) override;
        QueryResult query_access_heat_window(uint32_t page_shift, uint32_t slices, PositionRange when,
                                             std::vector<HeatCell> *out, ProgressSink *progress) override;
        Position heat_window_slice_position(uint32_t slices, uint32_t slice, PositionRange when) override;
        bool can_window_heat() const override;
        bool query_out_values(const std::vector<OutSlot> &slots,
                              std::vector<std::optional<uint64_t>> *out, ProgressSink *progress) override;
        bool query_register_change(Position at, uint32_t tid, uint32_t reg, uint64_t max_back,
                                   Position *where, bool *found, ProgressSink *progress) override;
        bool query_frame_entry(Position at, uint32_t tid, uint64_t max_back,
                               Position *call_pos, ea_t *entry) override;
        QueryResult query_instructions(PositionRange when, uint32_t tid, size_t max,
                                       std::vector<Access> *out, ProgressSink *progress) override;
        QueryResult registers_at(const std::vector<Position> &positions,
                                 std::vector<ittd_regs> *out,
                                 ProgressSink *progress) override;
        QueryResult read_memory_at(const std::vector<MemAt> &reads, std::vector<uint8_t> *data,
                                   std::vector<uint8_t> *known, ProgressSink *progress) override;

        std::vector<Symbol> module_symbols(ea_t base) override;
        std::vector<std::pair<ea_t, ea_t>> module_functions(ea_t base) override;

        // The file the module was loaded from, for messages.
        const qstring &path() const { return m_path; }
        // The backend's own reason for its last failure on the open trace.
        qstring last_error() const override;
        ReplayBlock last_replay_block() const override { return m_replayBlock; }
        bool replay_env(ReplayEnv *out) override;
        HiveCheck check_registry(const char *dir, qstring *why) override;
        qstring scan_notice() const override;

    private:
        // Keeps what a replay call's status code says the user can fix.
        int note_replay(int rc);

        const ittd_backend_api *m_api = nullptr;
        qstring       m_path;
        ittd_backend *m_handle = nullptr;
        bool          m_prepared = false;
        // The open recording's info set ITTD_CAP_PREPARE and the table has
        // prepare(): only then is prepare() called.
        bool          m_needs_prepare = false;
        TraceInfo     m_info;
        Capabilities  m_caps;
        ReplayBlock   m_replayBlock = ReplayBlock::None;
    };

    // $IDAUSR\ida-ttd, or a folder in it when 'sub' is given: where files the
    // user adds after installing live (the TTD runtime in windbg\, the Sogen
    // backend in backends\, registry hives in registry\). Not in
    // plugins\ida-ttd\, which HCLI replaces on every upgrade, and not under
    // plugins\ at all, since none of it is a plugin.
    qstring user_data_dir(const char *sub = nullptr);

    // Load every backend DLL in $IDAUSR\ida-ttd\backends, then in the user's
    // and the installation's plugins\ida-ttd-backends and
    // plugins\ida-ttd\ida-ttd-backends, and add those that speak this core's
    // ABI version to BackendRegistry. A module that fails to load or speaks
    // another version is named in the output window and skipped. Later calls
    // load nothing more.
    //
    // A backend DLL is loaded once per process and its table is shared by
    // every IDA module that loads it (ida-ttd.dll and ttd-loader.dll), so its
    // log callback is whichever was set last. With 'install_log' (the
    // plugin), every call points every registered module's log at this
    // binary again, so a callback a since-unloaded binary left behind is
    // replaced. The loader passes false and uses attach_backend_log /
    // detach_backend_log around the work it does.
    void load_backend_modules(bool install_log = true);
    // Point every registered module's log at this binary. With
    // 'post_requests' false, lines logged from other threads are only queued,
    // never handed to IDA as a UI request, so nothing of this binary can run
    // after it is unloaded; they are printed by flush_backend_log and by
    // detach_backend_log.
    void attach_backend_log(bool post_requests);
    // Clear every registered module's log callback and print what is queued.
    // Call on the main thread, after the backends' work has finished.
    void detach_backend_log();
    // Print what backends logged from other threads, when called on the main
    // thread (run_query's wait loop calls it).
    void flush_backend_log();
}
