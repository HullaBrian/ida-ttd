#pragma once

#include "pch.h"

namespace idattd
{
    // Thread-safe FIFO of debug events. The TraceManager fills it during
    // navigation; ev_get_debug_event drains it one event at a time.
    class EventQueue
    {
    public:
        void push(const debug_event_t &ev);
        bool empty();
        debug_event_t pop();

        // Convenience builders matching the IDA event taxonomy.
        void add_process_start(pid_t pid, thid_t tid, const std::string &module,
                               ea_t base, ea_t rebase_to, asize_t size);
        void add_process_exit(pid_t pid);
        void add_thread_start(pid_t pid, thid_t tid);
        void add_thread_exit(pid_t pid, thid_t tid);
        void add_lib_load(const std::string &module, ea_t base, ea_t rebase_to, asize_t size);
        void add_lib_unload(const std::string &module, ea_t base);
        void add_step(pid_t pid, thid_t tid, ea_t ea);
        void add_breakpoint(pid_t pid, thid_t tid, ea_t ea);

    private:
        std::deque<debug_event_t> m_events;
        std::mutex                m_mutex;
    };
}
