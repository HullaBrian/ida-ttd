#pragma once

#include "common/pch.h"

namespace idattd
{
    // Thread-safe FIFO of debug events. TraceManager fills it during
    // navigation; ev_get_debug_event drains it one event at a time.
    class EventQueue
    {
    public:
        void push(const debug_event_t &ev);
        bool empty();
        // Atomically pop the next event; false (leaving *out untouched) when
        // empty. Avoids the check-then-act race of empty() followed by a pop.
        bool try_pop(debug_event_t *out);
        // Drop every queued event. Called when a session starts or ends:
        // leftover events describe modules and threads of another trace, and
        // IDA would act on them.
        void clear();

        // Builders, one per IDA event kind.
        void add_process_start(pid_t pid, thid_t tid, const std::string &module,
                               ea_t base, ea_t rebase_to, asize_t size);
        void add_process_exit(pid_t pid);
        void add_thread_start(pid_t pid, thid_t tid);
        void add_thread_exit(pid_t pid, thid_t tid);
        void add_lib_load(pid_t pid, thid_t tid, const std::string &module,
                          ea_t base, ea_t rebase_to, asize_t size);
        void add_lib_unload(pid_t pid, thid_t tid, const std::string &module, ea_t base);
        void add_step(pid_t pid, thid_t tid, ea_t ea);
        void add_breakpoint(pid_t pid, thid_t tid, ea_t ea);

    private:
        std::deque<debug_event_t> m_events;
        std::mutex                m_mutex;
    };
}
