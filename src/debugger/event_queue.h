#pragma once

#include "common/pch.h"

namespace idattd
{
    // Thread-safe FIFO of debug events. The TraceManager fills it during
    // navigation; ev_get_debug_event drains it one event at a time.
    class EventQueue
    {
    public:
        void push(const debug_event_t &ev);
        bool empty();
        // Atomically pop the next event. Returns false (leaving *out untouched)
        // when the queue is empty. Prefer this over empty()+pop(): the two-call
        // form is a check-then-act race, and popping an empty queue is UB.
        bool try_pop(debug_event_t *out);
        // Drop every queued event. Called when a trace session starts or ends:
        // events left over from a previous trace describe modules and threads
        // that do not exist in the new one, and IDA would happily act on them.
        void clear();

        // Convenience builders matching the IDA event taxonomy.
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
