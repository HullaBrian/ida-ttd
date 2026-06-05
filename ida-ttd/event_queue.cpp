#include "event_queue.h"

namespace idattd
{
    //-----------------------------------------------------------------------
    void EventQueue::push(const debug_event_t &ev)
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        m_events.push_back(ev);
    }

    //-----------------------------------------------------------------------
    bool EventQueue::empty()
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        return m_events.empty();
    }

    //-----------------------------------------------------------------------
    debug_event_t EventQueue::pop()
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        debug_event_t ev = m_events.front();
        m_events.pop_front();
        return ev;
    }

    //-----------------------------------------------------------------------
    void EventQueue::add_process_start(pid_t pid, thid_t tid, const std::string &module,
                                       ea_t base, ea_t rebase_to, asize_t size)
    {
        debug_event_t ev;
        ev.pid = pid;
        ev.tid = tid;
        ev.ea  = base;
        ev.handled = true;
        modinfo_t &mi = ev.set_modinfo(PROCESS_STARTED);
        mi.name      = module.c_str();
        mi.base      = base;
        mi.size      = size;
        mi.rebase_to = rebase_to;
        push(ev);
    }

    //-----------------------------------------------------------------------
    void EventQueue::add_process_exit(pid_t pid)
    {
        debug_event_t ev;
        ev.pid = pid;
        ev.ea  = BADADDR;
        ev.handled = true;
        ev.set_exit_code(PROCESS_EXITED, 0);
        push(ev);
    }

    //-----------------------------------------------------------------------
    void EventQueue::add_thread_start(pid_t pid, thid_t tid)
    {
        debug_event_t ev;
        ev.pid = pid;
        ev.tid = tid;
        ev.ea  = BADADDR;
        ev.handled = true;
        ev.set_eid(THREAD_STARTED);
        push(ev);
    }

    //-----------------------------------------------------------------------
    void EventQueue::add_thread_exit(pid_t pid, thid_t tid)
    {
        debug_event_t ev;
        ev.pid = pid;
        ev.tid = tid;
        ev.ea  = BADADDR;
        ev.handled = true;
        ev.set_exit_code(THREAD_EXITED, 0);
        push(ev);
    }

    //-----------------------------------------------------------------------
    void EventQueue::add_lib_load(const std::string &module, ea_t base, ea_t rebase_to, asize_t size)
    {
        debug_event_t ev;
        ev.ea = base;
        ev.handled = true;
        modinfo_t &mi = ev.set_modinfo(LIB_LOADED);
        mi.name      = module.c_str();
        mi.base      = base;
        mi.size      = size;
        mi.rebase_to = rebase_to;
        push(ev);
    }

    //-----------------------------------------------------------------------
    void EventQueue::add_lib_unload(const std::string &module, ea_t base)
    {
        debug_event_t ev;
        ev.ea = base;
        ev.handled = true;
        ev.set_info(LIB_UNLOADED) = module.c_str();
        push(ev);
    }

    //-----------------------------------------------------------------------
    void EventQueue::add_step(pid_t pid, thid_t tid, ea_t ea)
    {
        debug_event_t ev;
        ev.pid = pid;
        ev.tid = tid;
        ev.ea  = ea;
        ev.handled = true;
        ev.set_eid(STEP);
        push(ev);
    }

    //-----------------------------------------------------------------------
    void EventQueue::add_breakpoint(pid_t pid, thid_t tid, ea_t ea)
    {
        debug_event_t ev;
        ev.pid = pid;
        ev.tid = tid;
        ev.ea  = ea;
        ev.handled = true;
        ev.set_bpt();
        push(ev);
    }
}
