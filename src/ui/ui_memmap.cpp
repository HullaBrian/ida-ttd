// The reconstructed memory map: the change timeline, the map at the playhead,
// and re-reading memory from the recording.
#include "ui/ui.h"
#include "ui/names.h"
#include "plugin/settings.h"

#include <expr.hpp>

namespace idattd
{
    //=======================================================================
    // MemoryTimelineChooser
    //=======================================================================
    static const int   g_mm_widths[] = { 16, 8, 11, 18, 20, 11, 32, 32, 80 };
    static const char *g_mm_header[] = { "Position", "Thread", "Change",
                                         "Base", "Size", "Protection",
                                         "Requested by", "API", "Call chain" };

    // NtFreeVirtualMemory's "protection" argument is really its free type.
    static const uint32_t MEM_RELEASE_BIT  = 0x8000;
    static const uint32_t MEM_DECOMMIT_BIT = 0x4000;

    MemoryTimelineChooser::MemoryTimelineChooser(TraceManager *mgr, std::vector<RegionChange> &&rows)
        : chooser_t(0, qnumber(g_mm_widths), g_mm_widths, g_mm_header, nullptr),
          m_mgr(mgr), m_rows(std::move(rows))
    {
        // A member: chooser_base_t keeps the pointer, not a copy.
        m_title.sprnt("TTD memory timeline [%d]", (int)m_rows.size());
        make_title_unique(&m_title);
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
        // A call on another process is left out of this process's map, but
        // that it happened is worth showing.
        if ( c.other_process )
            what.append(" (other process)");
        cols->at(2) = what;

        cols->at(3).sprnt("0x%llX", (uint64_t)c.base);
        if ( c.size == 0 )
            cols->at(4) = "whole region";
        else
            cols->at(4).sprnt("0x%llX", c.size);
        // Not exact: the kernel's out-parameters were not in the recording, so
        // the caller's request was rounded out to pages. A floor on the real
        // region, never an overstatement.
        if ( !c.exact )
            cols->at(4).append(" (at least)");

        if ( c.kind == RC_FREE )
            cols->at(5) = (c.protect & MEM_RELEASE_BIT) != 0 ? "release"
                        : (c.protect & MEM_DECOMMIT_BIT) != 0 ? "decommit" : "";
        else if ( c.kind == RC_UNMAPVIEW )
            cols->at(5) = "";
        else
            cols->at(5) = protection_text(c.protect);

        // Who wanted the memory, and the API they called. The instruction that
        // invoked the syscall is nearly always an unnamed helper in the stub's
        // DLL, so it is not a column; double-click travels there, with the
        // whole stack live.
        ea_t origin = chain_origin(m_mgr, c);
        cols->at(6) = origin != BADADDR ? described(origin) : qstring();
        cols->at(7) = c.api != BADADDR ? described(c.api) : qstring();
        // Every recorded frame, innermost first. One call the program makes
        // (loading a DLL, its malloc) can be behind dozens of changes that
        // "Requested by" attributes alike; the library frames inside it, and
        // the program's frames beyond it, are what tell them apart.
        for ( uint8_t k = 0; k < c.chain_n; k++ )
        {
            if ( c.chain[k] == BADADDR )
                continue;
            if ( !cols->at(8).empty() )
                cols->at(8).append(" <- ");
            cols->at(8).append(described(c.chain[k]));
        }
    }

    const qstring &MemoryTimelineChooser::described(ea_t ea) const
    {
        const size_t names = get_nlist_size();
        if ( names != m_namesSeen )
        {
            m_described.clear();
            m_namesSeen = names;
        }
        auto it = m_described.find(ea);
        if ( it == m_described.end() )
            it = m_described.emplace(ea, describe_address(m_mgr, ea)).first;
        return it->second;
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
        // The call, not the return: the return is inside the syscall stub,
        // not the function the row names.
        if ( n < m_rows.size() )
            travel_to(m_mgr, m_rows[n].call_pos.is_valid() ? m_rows[n].call_pos : m_rows[n].pos, m_made);
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

        // A selection in the disassembly, else ask (the menu, nothing selected).
        ea_t lo = BADADDR, hi = BADADDR;
        if ( !read_range_selection(nullptr, &lo, &hi) || lo >= hi )
        {
            ea_t here = get_screen_ea();
            if ( here == BADADDR )
            {
                warning("Put the cursor on an address, or select a range, first.");
                return 1;
            }
            // Default to the enclosing function, else a page, clipped to the
            // cursor's segment.
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
            if ( ask_form(form, &lo, &hi) <= 0 )
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
    // Build the change timeline if this database has none yet, asking first
    // since it replays the whole recording. False when there is none after.
    static bool ensure_timeline(TraceManager *mgr, const char *declined_note)
    {
        MemoryMap &map = mgr->memmap_for_update();
        if ( !map.empty() )
            return true;

        qstring q;
        q.sprnt("Reconstructing the memory map replays the whole recording "
                "once, watching every call that allocates, protects or frees "
                "memory.\n\n"
                "That can take a while on a large trace. It is saved in the "
                "database afterwards, so this is paid once.%s\n\n"
                "Build it now?", declined_note);
        if ( ask_yn(ASKBTN_YES, "%s", q.c_str()) != ASKBTN_YES )
            return false;

        // The session's map, which IDA's segments and the scripts read too;
        // saved and handed to IDA there.
        bool cancelled = false;
        qstring err;
        if ( !session_memory_map(mgr, false, &cancelled, &err) )
        {
            if ( mgr->is_active() && !err.empty() && err.find("could not be built") != qstring::npos )
                warning("The memory map could not be built for this recording.\n\n"
                        "For a Microsoft TTD trace this happens when ntdll's export "
                        "table was never read during recording; for another kind of "
                        "recording, its backend may not record the memory map. The "
                        "output window has the details.");
            else if ( !err.empty() )
                warning("The memory map was not built: %s.", err.c_str());
            return false;
        }
        if ( mgr->memmap_for_update().empty() )
        {
            info("The recording made no memory allocations, protection changes "
                 "or frees that could be recovered.");
            return false;
        }
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
        // Without the timeline the map still has modules, stacks and the PEB,
        // just not the program's allocations.
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

    // The SDK cannot say; Qt's palette can (scripts/ida_ttd_qt.py). Asked
    // once: the theme changes only with a restart.
    static bool theme_is_dark()
    {
        static int dark = -1;
        if ( dark < 0 )
        {
            dark = 0;
            extlang_object_t py = find_extlang_by_name("Python");
            idc_value_t rv;
            qstring err;
            if ( py != nullptr && py->eval_snippet != nullptr && py->eval_expr != nullptr
              && py->eval_snippet("import ida_ttd_qt\n", &err)
              && py->eval_expr(&rv, BADADDR, "ida_ttd_qt.theme_is_dark()", &err)
              && rv.vtype == VT_LONG )
            {
                dark = rv.num != 0 ? 1 : 0;
            }
        }
        return dark == 1;
    }

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
        size_t map_size = m_mgr->memmap().size();
        if ( now.is_valid() && now == m_at && map_size == m_mapSize )
            return;
        address_space_at(m_mgr, &m_rows);
        // Rebuilt from the session being replayed, a fork's after a switch.
        m_made    = RecordingStamp{};
        m_at      = now;
        m_mapSize = map_size;
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

        // What this view is most often opened to find.
        if ( attrs != nullptr && !r.reserved && r.type != ITTD_REGION_IMAGE )
        {
            uchar perm = protection_perm(r.protect);
            if ( (perm & SEGPERM_EXEC) != 0 && (perm & SEGPERM_WRITE) != 0 )
                attrs->flags |= CHITEM_BOLD;
        }
        if ( attrs != nullptr && settings().memmap_flag_code && is_code_outside_modules(r) )
            attrs->color = theme_is_dark() ? 0x2A2A5C : 0xC8D2FF;   // muted red (0xBBGGRR)
    }

    ea_t idaapi MemoryMapChooser::get_ea(size_t n) const
    {
        return n < m_rows.size() ? m_rows[n].base : BADADDR;
    }

    // The column of the cell double-clicked in the chooser titled 'title', -1
    // when unknown: enter() is told the row only, and Qt knows the rest
    // (scripts/ida_ttd_qt.py).
    static int current_column(const char *title)
    {
        extlang_object_t py = find_extlang_by_name("Python");
        idc_value_t rv;
        qstring err, expr;
        // The titles passed here are the plugin's own, with no quotes in them.
        expr.sprnt("ida_ttd_qt.chooser_current_column('%s')", title);
        if ( py != nullptr && py->eval_snippet != nullptr && py->eval_expr != nullptr
          && py->eval_snippet("import ida_ttd_qt\n", &err)
          && py->eval_expr(&rv, BADADDR, expr.c_str(), &err)
          && rv.vtype == VT_LONG )
        {
            return (int)rv.num;
        }
        return -1;
    }

    static const int AM_COL_ALLOCATED = 6;      // "Allocated at"

    // Double-click: on "Allocated at", travel there (as Ctrl+E); anywhere
    // else, go to the region.
    chooser_t::cbret_t idaapi MemoryMapChooser::enter(size_t n)
    {
        if ( n >= m_rows.size() )
            return cbret_t(n, NOTHING_CHANGED);
        if ( current_column(TITLE) == AM_COL_ALLOCATED )
            return edit(n);
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
        travel_to(m_mgr, m_rows[n].since, m_made);
        return cbret_t(n, NOTHING_CHANGED);
    }

    // Asked for, so rebuilt even at the same position.
    chooser_t::cbret_t idaapi MemoryMapChooser::refresh(ssize_t n)
    {
        m_at = Position::none();
        rebuild();
        return cbret_t(n, ALL_CHANGED);
    }
}
