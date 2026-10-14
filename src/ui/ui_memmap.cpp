// The reconstructed memory map: the change timeline, the map at the playhead,
// and re-reading memory from the recording.
#include "ui/ui.h"
#include "ui/names.h"

namespace idattd
{
    //=======================================================================
    // MemoryTimelineChooser
    //=======================================================================
    static const int   g_mm_widths[] = { 16, 8, 11, 18, 20, 11, 32, 32 };
    static const char *g_mm_header[] = { "Position", "Thread", "Change",
                                         "Base", "Size", "Protection",
                                         "Requested by", "API" };

    // NtFreeVirtualMemory's "protection" argument is really its free type.
    static const uint32_t MEM_RELEASE_BIT  = 0x8000;
    static const uint32_t MEM_DECOMMIT_BIT = 0x4000;

    MemoryTimelineChooser::MemoryTimelineChooser(TraceManager *mgr, std::vector<RegionChange> &&rows)
        : chooser_t(0, qnumber(g_mm_widths), g_mm_widths, g_mm_header, nullptr),
          m_mgr(mgr), m_rows(std::move(rows))
    {
        // The string is a member because chooser_base_t keeps the pointer it is
        // given rather than copying it.
        m_title.sprnt("TTD memory timeline [%d]", (int)m_rows.size());
        title = m_title.c_str();
    }

    size_t idaapi MemoryTimelineChooser::get_count() const
    {
        return m_rows.size();
    }

    void idaapi MemoryTimelineChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                          chooser_item_attrs_t * /*attrs*/, size_t n) const
    {
        if ( n >= m_rows.size() )
            return;
        const RegionChange &c = m_rows[n];
        cols->at(0) = format_position(c.pos);
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

    ea_t idaapi MemoryTimelineChooser::get_ea(size_t n) const
    {
        if ( n >= m_rows.size() )
            return BADADDR;
        // Follow what the row names: the code that asked for the memory.
        ea_t origin = chain_origin(m_mgr, m_rows[n]);
        return origin != BADADDR ? origin : m_rows[n].pc;
    }

    chooser_t::cbret_t idaapi MemoryTimelineChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_rows.size() )
        {
            // The call, not the return. Travelling to the return leaves you
            // inside the syscall stub, which is never what the row is about and
            // does not match the function the row names.
            const RegionChange &c = m_rows[n];
            m_mgr->set_next_position(c.call_pos.is_valid() ? c.call_pos : c.pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // Re-read memory from the recording
    //=======================================================================
    int idaapi RereadHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("Re-reading memory is only possible while replaying a trace.");
            return 1;
        }

        // A selection in the disassembly is the common case; fall back to asking
        // so the command is usable from the menu with nothing selected.
        ea_t lo = BADADDR, hi = BADADDR;
        if ( !read_range_selection(nullptr, &lo, &hi) || lo >= hi )
        {
            ea_t here = get_screen_ea();
            if ( here == BADADDR )
            {
                warning("Put the cursor on an address, or select a range, first.");
                return 1;
            }
            // Default to the enclosing function, else a page, kept inside the
            // segment the cursor is in.
            lo = here;
            hi = here + 0x1000;
            segment_info_t si;
            if ( get_segment_info(&si, here) )
            {
                func_entry_info_t fi;
                if ( get_func_entry_info(&fi, here) && fi.end_ea > fi.start_ea )
                {
                    lo = fi.start_ea;
                    hi = fi.end_ea;
                }
                if ( hi > si.end_ea )
                    hi = si.end_ea;
            }

            static const char form[] =
                "TTD re-read memory\n"
                "\n"
                "Discard what IDA has cached for this range, rebuild it from the\n"
                "recording, and disassemble it again.\n"
                "\n"
                "  <~S~tart:$::16::>\n"
                "  <~E~nd:$::16::>\n"
                "\n";
            if ( !ask_form(form, &lo, &hi) )
                return 1;
        }

        if ( lo >= hi )
        {
            warning("The end address must be above the start address.");
            return 1;
        }

        size_t got = mgr()->reread_range(lo, hi);
        msg("[ida-ttd] re-read %a..%a: %d byte(s) recovered from recorded "
            "writes.\n", lo, hi, (int)got);
        refresh_idaview_anyway();
        return 1;
    }

    //=======================================================================
    // Memory map actions
    //=======================================================================
    // Build the change timeline if this database has none yet, asking first:
    // it replays the whole recording. False when there is none afterwards.
    static bool ensure_timeline(TraceManager *mgr, const char *declined_note)
    {
        MemoryMap &map = mgr->memmap_for_update();
        if ( !map.empty() )
            return true;

        // Building it replays the whole recording, so say so before starting
        // rather than after.
        qstring q;
        q.sprnt("Reconstructing the memory map replays the whole recording "
                "once, watching every call that allocates, protects or frees "
                "memory.\n\n"
                "That can take a while on a large trace. It is saved in the "
                "database afterwards, so this is paid once.%s\n\n"
                "Build it now?", declined_note);
        if ( ask_yn(ASKBTN_YES, "%s", q.c_str()) != ASKBTN_YES )
            return false;

        bool cancelled = false;
        if ( !build_memory_map(mgr, &map, &cancelled) )
            return false;
        if ( map.empty() )
        {
            info("The recording made no memory allocations, protection changes "
                 "or frees that could be recovered.");
            return false;
        }
        if ( !cancelled )
            map.save(mgr->trace_fingerprint());
        else
            msg("[ida-ttd] memory map: the sweep was cancelled, so the partial "
                "map is used for this session but not saved.\n");

        // The regions in force at the current position are new information
        // for IDA: it has been treating all of user space as one segment.
        invalidate_dbgmem_config();
        refresh_idaview_anyway();
        return true;
    }

    int idaapi MemoryTimelineHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("The memory timeline is only available while replaying a trace.");
            return 1;
        }
        if ( !ensure_timeline(mgr(), "") )
            return 1;

        const MemoryMap &map = mgr()->memmap();
        std::vector<RegionChange> rows;
        rows.reserve(map.size());
        for ( size_t i = 0; i < map.size(); i++ )
            rows.push_back(map.at(i));

        MemoryTimelineChooser *ch = new MemoryTimelineChooser(mgr(), std::move(rows));
        ch->choose();
        return 1;
    }

    int idaapi MemoryMapHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("The memory map is only available while replaying a trace.");
            return 1;
        }
        // Without the timeline the map still has the modules, stacks and the
        // PEB, just not what the program allocated.
        ensure_timeline(mgr(), "\n\nWithout it, the map shows the modules, "
                               "stacks and the PEB, but nothing the program "
                               "allocated.");
        if ( find_widget(MemoryMapChooser::TITLE) != nullptr )
        {
            MemoryMapChooser::refresh_open();
            activate_widget(find_widget(MemoryMapChooser::TITLE), true);
            return 1;
        }
        MemoryMapChooser *ch = new MemoryMapChooser(mgr());
        ch->choose();
        return 1;
    }

    //=======================================================================
    // MemoryMapChooser: the map at the playhead
    //=======================================================================
    const char *const MemoryMapChooser::TITLE = "TTD memory map";

    static const int   g_am_widths[] = { 16, 16, 10, 12, 8, 36, 16 };
    static const char *g_am_header[] = { "Base", "End", "Size", "Protection",
                                         "Type", "Use", "Allocated at" };

    MemoryMapChooser::MemoryMapChooser(TraceManager *mgr)
        : chooser_t(CH_CAN_EDIT | CH_CAN_REFRESH, qnumber(g_am_widths), g_am_widths,
                    g_am_header, TITLE),
          m_mgr(mgr)
    {
        popup_names[POPUP_EDIT]    = "Travel to where it was allocated";
        popup_names[POPUP_REFRESH] = "Refresh";
    }

    void MemoryMapChooser::rebuild() const
    {
        if ( m_mgr == nullptr || !m_mgr->is_active() )
        {
            m_rows.clear();
            m_at = Position::none();
            return;
        }
        Position now = m_mgr->current_position();
        if ( now.is_valid() && now == m_at )
            return;
        address_space_at(m_mgr, &m_rows);
        m_at = now;
    }

    void MemoryMapChooser::refresh_open()
    {
        if ( find_widget(TITLE) != nullptr )
            refresh_chooser(TITLE);
    }

    size_t idaapi MemoryMapChooser::get_count() const
    {
        rebuild();
        return m_rows.size();
    }

    void idaapi MemoryMapChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                          chooser_item_attrs_t *attrs, size_t n) const
    {
        if ( n >= m_rows.size() )
            return;
        const AddressRegion &r = m_rows[n];
        cols->at(0).sprnt("0x%llX", (uint64_t)r.base);
        cols->at(1).sprnt("0x%llX", (uint64_t)r.end());
        cols->at(2).sprnt("0x%llX", r.size);
        if ( r.reserved )
            cols->at(3) = "reserved";
        else if ( r.protect != 0 )
            cols->at(3) = protection_text(r.protect);
        cols->at(4) = region_type_name(r.type);
        cols->at(5) = r.use;
        if ( r.since.is_valid() )
            cols->at(6) = format_position(r.since);

        // Memory that is writable and executable at once is what this view is
        // most often opened to find.
        if ( attrs != nullptr && !r.reserved && r.type != ITTD_REGION_IMAGE )
        {
            uchar perm = protection_perm(r.protect);
            if ( (perm & SEGPERM_EXEC) != 0 && (perm & SEGPERM_WRITE) != 0 )
                attrs->flags |= CHITEM_BOLD;
        }
    }

    ea_t idaapi MemoryMapChooser::get_ea(size_t n) const
    {
        return n < m_rows.size() ? m_rows[n].base : BADADDR;
    }

    chooser_t::cbret_t idaapi MemoryMapChooser::enter(size_t n)
    {
        if ( n < m_rows.size() )
            jumpto(m_rows[n].base);
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi MemoryMapChooser::edit(size_t n)
    {
        if ( n >= m_rows.size() )
            return cbret_t(n, NOTHING_CHANGED);
        if ( !m_rows[n].since.is_valid() )
        {
            info("The recording does not say where this region was made: the "
                 "kernel made it, or it existed before the recording started.");
            return cbret_t(n, NOTHING_CHANGED);
        }
        if ( m_mgr != nullptr && m_mgr->is_active() )
        {
            m_mgr->set_next_position(m_rows[n].since);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    chooser_t::cbret_t idaapi MemoryMapChooser::refresh(ssize_t n)
    {
        rebuild();
        return cbret_t(n, ALL_CHANGED);
    }
}
