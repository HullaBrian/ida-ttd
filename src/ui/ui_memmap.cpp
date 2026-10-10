// The reconstructed memory map: the change timeline listing and its two actions.
#include "ui/ui.h"
#include "ui/names.h"

using namespace TTD;

namespace idattd
{
    //=======================================================================
    // MemoryMapChooser
    //=======================================================================
    static const int   g_mm_widths[] = { 16, 8, 11, 18, 20, 11, 32, 32 };
    static const char *g_mm_header[] = { "Position", "Thread", "Change",
                                         "Base", "Size", "Protection",
                                         "Requested by", "API" };

    // NtFreeVirtualMemory's "protection" argument is really its free type.
    static const uint32_t MEM_RELEASE_BIT  = 0x8000;
    static const uint32_t MEM_DECOMMIT_BIT = 0x4000;

    MemoryMapChooser::MemoryMapChooser(TraceManager *mgr, std::vector<RegionChange> &&rows)
        : chooser_t(0, qnumber(g_mm_widths), g_mm_widths, g_mm_header, nullptr),
          m_mgr(mgr), m_rows(std::move(rows))
    {
        // The string is a member because chooser_base_t keeps the pointer it is
        // given rather than copying it.
        m_title.sprnt("TTD memory map [%d]", (int)m_rows.size());
        title = m_title.c_str();
    }

    size_t idaapi MemoryMapChooser::get_count() const
    {
        return m_rows.size();
    }

    void idaapi MemoryMapChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                          chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_rows.size() )
            return;
        const RegionChange &c = m_rows[n];
        cols->at(0).sprnt("%llX:%llX", (uint64_t)c.pos.Sequence, (uint64_t)c.pos.Steps);
        cols->at(1).sprnt("0x%X", c.tid);

        qstring what = change_name(c.kind);
        // Say when a call targeted another process. It is left out of this
        // process's map, and seeing that it happened at all is the point.
        if ( c.other_process )
            what.append(" (other process)");
        cols->at(2) = what;

        cols->at(3).sprnt("0x%llX", (uint64_t)c.base);
        if ( c.size == 0 )
            cols->at(4) = "whole region";
        else
            cols->at(4).sprnt("0x%llX", c.size);
        // The base and size are what an unrecoverable out-parameter costs: the
        // kernel's exact answer was not in the recording, so the caller's own
        // request was rounded out to page boundaries instead. That is a floor on
        // the real region, never an overstatement.
        if ( !c.exact )
            cols->at(4).append(" (at least)");

        if ( c.kind == RC_FREE )
            cols->at(5) = (c.protect & MEM_RELEASE_BIT) != 0 ? "release"
                        : (c.protect & MEM_DECOMMIT_BIT) != 0 ? "decommit" : "";
        else if ( c.kind == RC_UNMAPVIEW )
            cols->at(5) = "";
        else
            cols->at(5) = protection_text(c.protect);

        // Who wanted the memory, and what they ended up calling. The instruction
        // that actually invoked the syscall sits in between and is nearly always
        // an unnamed internal helper of the DLL the stub lives in, which is why
        // it is not a column: double-click travels there, where the whole stack
        // is live.
        ea_t origin = chain_origin(m_mgr, c);
        cols->at(6) = origin != BADADDR ? describe_address(m_mgr, origin) : qstring();
        cols->at(7) = c.api != BADADDR ? describe_address(m_mgr, c.api) : qstring();
    }

    ea_t idaapi MemoryMapChooser::get_ea(size_t n) const
    {
        if ( n >= m_rows.size() )
            return BADADDR;
        // Follow what the row names: the code that asked for the memory.
        ea_t origin = chain_origin(m_mgr, m_rows[n]);
        return origin != BADADDR ? origin : m_rows[n].pc;
    }

    chooser_t::cbret_t idaapi MemoryMapChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_rows.size() )
        {
            // The call, not the return. Travelling to the return leaves you
            // inside the syscall stub, which is never what the row is about and
            // does not match the function the row names.
            const RegionChange &c = m_rows[n];
            m_mgr->set_next_position(c.call_pos.IsValid() ? c.call_pos : c.pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // Memory map actions
    //=======================================================================
    int idaapi MemoryMapHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("The memory map is only available while replaying a trace.");
            return 1;
        }

        MemoryMap &map = mgr()->memmap_for_update();
        if ( map.empty() )
        {
            // Building it replays the whole recording, so say so before starting
            // rather than after.
            if ( ask_yn(ASKBTN_YES,
                        "Reconstructing the memory map replays the whole recording "
                        "once, watching every call that allocates, protects or frees "
                        "memory.\n\n"
                        "That can take a while on a large trace. It is saved in the "
                        "database afterwards, so this is paid once.\n\n"
                        "Build it now?") != ASKBTN_YES )
            {
                return 1;
            }

            bool cancelled = false;
            if ( !build_memory_map(mgr(), &map, &cancelled) )
                return 1;
            if ( map.empty() )
            {
                info("The recording made no memory allocations, protection changes "
                     "or frees that could be recovered.");
                return 1;
            }
            if ( !cancelled )
                map.save(mgr()->trace_fingerprint());
            else
                msg("[ida-ttd] memory map: the sweep was cancelled, so the partial "
                    "map is used for this session but not saved.\n");

            // The regions in force at the current position are new information
            // for IDA: it has been treating all of user space as one segment.
            invalidate_dbgmem_config();
            refresh_idaview_anyway();
        }

        std::vector<RegionChange> rows;
        rows.reserve(map.size());
        for ( size_t i = 0; i < map.size(); i++ )
            rows.push_back(map.at(i));

        MemoryMapChooser *ch = new MemoryMapChooser(mgr(), std::move(rows));
        ch->choose();
        return 1;
    }

    int idaapi ClearMemoryMapHandler::activate(action_activation_ctx_t *)
    {
        MemoryMap::erase();
        if ( mgr() != nullptr )
        {
            mgr()->memmap_for_update().clear();
            // Back to one flat range over user space, which is what the debugger
            // reported before any of this existed.
            invalidate_dbgmem_config();
        }
        msg("[ida-ttd] memory map cleared; the debugger is back to reporting user "
            "space as a single range.\n");
        refresh_idaview_anyway();
        return 1;
    }
}
