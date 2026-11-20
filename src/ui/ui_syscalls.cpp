// The recording's syscalls: the listing and the action that opens it.
#include "ui/ui.h"
#include "debugger/apidecode.h"

namespace idattd
{
    //=======================================================================
    // SyscallChooser
    //=======================================================================
    static const int   g_sc_widths[] = { 16, 8, 30, 36, 100 };
    static const char *g_sc_header[] = { "Position", "Thread", "Syscall", "Result", "Arguments" };

    SyscallChooser::SyscallChooser(TraceManager *mgr, std::vector<SyscallEvent> &&calls,
                                   std::vector<qstring> &&decoded)
        : ListingChooser(mgr, CH_CAN_EDIT | CH_CAN_REFRESH, qnumber(g_sc_widths), g_sc_widths, g_sc_header,
                         nullptr, std::move(calls)),
          m_decoded(std::move(decoded))
    {
        popup_names[POPUP_EDIT]    = "Decode arguments";
        popup_names[POPUP_REFRESH] = "Rebuild from the recording";
        set_unique_title(qstring().sprnt("TTD syscalls [%d]", (int)m_rows.size()));
        reset_rows();
    }

    // A call without a decoding shows its registers instead. They are read
    // here, for every such call in one batch behind a wait box, and never
    // from get_row: IDA draws every row to sort or filter a list, and reading
    // the recording there froze the UI (a seek is ~17 ms on Microsoft TTD).
    void SyscallChooser::reset_rows()
    {
        m_decoded.resize(m_rows.size());
        if ( m_made.current() )
            undecoded_syscall_arguments(m_mgr, m_rows, m_decoded, &m_args);
        else
            m_args.assign(m_rows.size(), std::nullopt);
    }

    void idaapi SyscallChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                        chooser_item_attrs_t *attrs, size_t n) const
    {
        if ( row(n) == nullptr )
            return;
        const SyscallEvent &c = *row(n);
        cols->at(0) = format_position(c.pos);
        if ( c.tid != 0 )
            cols->at(1).sprnt("0x%X", c.tid);
        if ( !c.name.empty() )
            cols->at(2) = c.name;
        else
            cols->at(2).sprnt("syscall 0x%X", c.number);

        // NTSTATUS (nearly all are Nt* calls); failures in the error color.
        uint32_t st = (uint32_t)c.result;
        const char *sn = c.result <= 0xFFFFFFFFull ? ntstatus_name(st) : nullptr;
        if ( sn != nullptr )
            cols->at(3).sprnt("0x%08X %s", st, sn);
        else
            cols->at(3).sprnt("0x%llX", (uint64_t)c.result);
        if ( c.result <= 0xFFFFFFFFull && (st & 0xC0000000u) == 0xC0000000u && attrs != nullptr )
            attrs->color = 0xC0C0FF;     // BGR: light red

        if ( !m_decoded[n].empty() )
        {
            cols->at(4) = m_decoded[n];
            return;
        }
        const std::optional<SyscallArgs> &a = m_args[n];
        if ( a.has_value() )
            cols->at(4).sprnt("r10=0x%llX, rdx=0x%llX, r8=0x%llX, r9=0x%llX",
                              (uint64_t)(*a)[0], (uint64_t)(*a)[1],
                              (uint64_t)(*a)[2], (uint64_t)(*a)[3]);
        else
            cols->at(4) = "(not read; Ctrl+E decodes it)";
    }

    // One call the full decoding did not reach (it was stopped).
    chooser_t::cbret_t idaapi SyscallChooser::edit(size_t n)
    {
        if ( n >= m_rows.size() || m_mgr == nullptr || !m_mgr->is_active() )
            return cbret_t(n, NOTHING_CHANGED);
        if ( api_signature(m_rows[n].name.c_str()) == nullptr )
        {
            const qstring &why = api_metadata_error();
            info("There is no signature for %s%s%s.",
                 m_rows[n].name.empty() ? "this syscall" : m_rows[n].name.c_str(),
                 why.empty() ? "" : ": ", why.c_str());
            return cbret_t(n, NOTHING_CHANGED);
        }
        // Its registers are read at the row's position: only on its own
        // recording.
        if ( !listing_is_current(m_made) )
            return cbret_t(n, NOTHING_CHANGED);
        std::vector<SyscallEvent> one{ m_rows[n] };
        std::vector<qstring> text;
        bool cancelled = false;
        if ( decode_syscalls(m_mgr, one, &text, &cancelled) && !cancelled && !text.empty() )
            m_decoded[n] = text[0];
        return cbret_t(n, ALL_CHANGED);
    }

    chooser_t::cbret_t idaapi SyscallChooser::refresh(ssize_t n)
    {
        std::vector<SyscallEvent> calls;
        std::vector<qstring> decoded;
        bool cancelled = false;
        if ( m_mgr == nullptr || !m_mgr->is_active()
          || !list_syscalls(m_mgr, &calls, &cancelled) || cancelled )
            return cbret_t(n, NOTHING_CHANGED);
        // Saved only when the decode ran to the end: a failed one leaves
        // every row blank, which would then be kept as the final answer.
        if ( decode_syscalls(m_mgr, calls, &decoded, &cancelled) && !cancelled )
            save_syscalls(calls, decoded);
        restamp(std::move(calls));
        m_decoded = std::move(decoded);
        reset_rows();
        return cbret_t(n, ALL_CHANGED);
    }

    //=======================================================================
    // Syscalls action
    //=======================================================================
    static bool backend_lists_syscalls(TraceManager *mgr)
    {
        return mgr != nullptr && mgr->is_active() && mgr->backend() != nullptr
            && mgr->backend()->capabilities().syscalls;
    }

    // The list saved in the database, else listed and decoded now behind a
    // cancellable wait box, and saved if that ran to the end.
    int idaapi SyscallsHandler::activate(action_activation_ctx_t *)
    {
        if ( !backend_lists_syscalls(mgr()) )
        {
            warning("This recording's backend cannot list its syscalls.");
            return 1;
        }
        std::vector<SyscallEvent> calls;
        std::vector<qstring> decoded;
        bool cancelled = false;
        if ( load_syscalls(&calls, &decoded) )
        {
            msg("[ida-ttd] %d syscall(s), as saved in the database; Refresh (Ctrl+U) in the list "
                "rebuilds it.\n", (int)calls.size());
        }
        else
        {
            if ( !list_syscalls(mgr(), &calls, &cancelled) )
            {
                warning("The recording's backend could not list its syscalls.");
                return 1;
            }
            if ( cancelled )
            {
                msg("[ida-ttd] syscalls: stopped.\n");
                return 1;
            }
            const bool ran = decode_syscalls(mgr(), calls, &decoded, &cancelled);
            if ( cancelled || !ran )
                msg("[ida-ttd] %d syscall(s); decoding their arguments %s, so they are shown "
                    "undecoded and not saved (Ctrl+E decodes one).\n", (int)calls.size(),
                    cancelled ? "was stopped" : "failed");
            else
                save_syscalls(calls, decoded);
        }
        if ( calls.empty() )
        {
            info("The recording made no syscalls.");
            return 1;
        }
        SyscallChooser *ch = new SyscallChooser(mgr(), std::move(calls), std::move(decoded));
        ch->choose();
        return 1;
    }

    action_state_t idaapi SyscallsHandler::update(action_update_ctx_t *)
    {
        return backend_lists_syscalls(mgr()) ? AST_ENABLE : AST_DISABLE;
    }
}
