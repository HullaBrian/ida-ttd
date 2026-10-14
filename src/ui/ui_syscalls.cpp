// The recording's syscalls: the listing and the action that opens it.
#include "ui/ui.h"
#include "debugger/apidecode.h"

namespace idattd
{
    //=======================================================================
    // SyscallChooser
    //=======================================================================
    static const int   g_sc_widths[] = { 16, 8, 30, 36, 60, 80 };
    static const char *g_sc_header[] = { "Position", "Thread", "Syscall", "Result",
                                         "Arguments (r10, rdx, r8, r9)", "Decoded (Ctrl+E)" };

    // Arguments are read in chunks as rows are shown: each one is a register
    // reconstruction, and a long recording makes tens of thousands of calls.
    static const size_t ARG_CHUNK = 64;

    SyscallChooser::SyscallChooser(TraceManager *mgr, std::vector<SyscallEvent> &&calls)
        : chooser_t(CH_CAN_EDIT, qnumber(g_sc_widths), g_sc_widths, g_sc_header, nullptr),
          m_mgr(mgr), m_calls(std::move(calls))
    {
        popup_names[POPUP_EDIT] = "Decode arguments";
        m_title.sprnt("TTD syscalls [%d]", (int)m_calls.size());
        title = m_title.c_str();
        m_args.resize(m_calls.size());
        m_argsRead.resize((m_calls.size() + ARG_CHUNK - 1) / ARG_CHUNK, false);
    }

    size_t idaapi SyscallChooser::get_count() const
    {
        return m_calls.size();
    }

    const std::optional<SyscallArgs> &SyscallChooser::args_of(size_t n) const
    {
        size_t chunk = n / ARG_CHUNK;
        if ( !m_argsRead[chunk] && m_mgr != nullptr && m_mgr->is_active() )
        {
            m_argsRead[chunk] = true;
            std::vector<std::optional<SyscallArgs>> got;
            syscall_arguments(m_mgr->backend(), m_calls, chunk * ARG_CHUNK, ARG_CHUNK, &got);
            for ( size_t i = 0; i < got.size(); i++ )
                m_args[chunk * ARG_CHUNK + i] = got[i];
        }
        return m_args[n];
    }

    void idaapi SyscallChooser::get_row(qstrvec_t *cols, int * /*icon*/,
                                        chooser_item_attrs_t *attrs, size_t n) const
    {
        if ( n >= m_calls.size() )
            return;
        const SyscallEvent &c = m_calls[n];
        cols->at(0) = format_position(c.pos);
        if ( c.tid != 0 )
            cols->at(1).sprnt("0x%X", c.tid);
        if ( !c.name.empty() )
            cols->at(2) = c.name;
        else
            cols->at(2).sprnt("syscall 0x%X", c.number);

        // NTSTATUS for the Nt* calls, which is nearly all of them; a failure
        // is shown in the error colour so a scroll down the list finds them.
        uint32_t st = (uint32_t)c.result;
        const char *sn = c.result <= 0xFFFFFFFFull ? ntstatus_name(st) : nullptr;
        if ( sn != nullptr )
            cols->at(3).sprnt("0x%08X %s", st, sn);
        else
            cols->at(3).sprnt("0x%llX", (uint64_t)c.result);
        if ( c.result <= 0xFFFFFFFFull && (st & 0xC0000000u) == 0xC0000000u && attrs != nullptr )
            attrs->color = 0xC0C0FF;     // BGR: light red

        const std::optional<SyscallArgs> &a = args_of(n);
        if ( a.has_value() )
            cols->at(4).sprnt("0x%llX, 0x%llX, 0x%llX, 0x%llX",
                              (uint64_t)(*a)[0], (uint64_t)(*a)[1],
                              (uint64_t)(*a)[2], (uint64_t)(*a)[3]);
        auto d = m_decoded.find(n);
        if ( d != m_decoded.end() )
            cols->at(5) = d->second;
    }

    // Decoding one call costs two seeks -- the arguments at the call, the out
    // parameters just after it -- which is too much to pay for every row
    // drawn, so it is done when asked.
    chooser_t::cbret_t idaapi SyscallChooser::edit(size_t n)
    {
        if ( n >= m_calls.size() || m_mgr == nullptr || !m_mgr->is_active() )
            return cbret_t(n, NOTHING_CHANGED);
        const SyscallEvent &c = m_calls[n];
        const win32meta::FuncSig *sig = api_signature(c.name.c_str());
        if ( sig == nullptr )
        {
            const qstring &why = api_metadata_error();
            info("There is no signature for %s%s%s.", c.name.empty() ? "this syscall" : c.name.c_str(),
                 why.empty() ? "" : ": ", why.c_str());
            return cbret_t(n, NOTHING_CHANGED);
        }
        ITraceBackend *b = m_mgr->backend();
        // The syscall convention, from the 64-bit side: always on Sogen; a
        // Microsoft x86 recording holds the 32-bit side, arguments on the stack.
        const bool wide = b->info().is64 || qstrcmp(b->id(), "sogen") == 0;
        CursorPtr cur = b->make_cursor();
        if ( !cur || !cur->seek(c.pos) )
            return cbret_t(n, NOTHING_CHANGED);
        // At the syscall instruction the arguments are where a callee finds
        // them: r10 for rcx, and the stack one return address deep (two on
        // x86: the return into the stub, then the stub's own). Seen from the
        // call site, which is what the decoder reads.
        GuestView v = guest_view(cur.get());
        auto regs = v.regs;
        v.regs = [regs, wide](ittd_regs *r)
        {
            if ( !regs || !regs(r) )
                return false;
            if ( wide )
                r->gp[ITTD_REG_RCX] = r->gp[10];
            r->gp[ITTD_REG_RSP] += 8;
            return true;
        };
        DecodedCall dc;
        decode_api_args(v, *sig, wide, &dc);
        CursorPtr after = b->make_cursor();
        if ( after && after->seek(b->position_add(c.pos, 1)) )
            decode_api_outs(guest_view(after.get()), &dc);
        qstring text;
        for ( const DecodedArg &a : dc.args )
        {
            if ( !text.empty() )
                text.append(", ");
            text.cat_sprnt("%s=%s", a.name.c_str(), a.text.c_str());
        }
        m_decoded[n] = text;
        msg("[ida-ttd] %s %s(%s) = %s\n", format_position(c.pos).c_str(), c.name.c_str(), text.c_str(),
            decode_api_return(dc, c.result).c_str());
        return cbret_t(n, ALL_CHANGED);
    }

    chooser_t::cbret_t idaapi SyscallChooser::enter(size_t n)
    {
        if ( m_mgr != nullptr && m_mgr->is_active() && n < m_calls.size() )
        {
            m_mgr->set_next_position(m_calls[n].pos);
            request_continue_process();
            run_requests();
        }
        return cbret_t(n, NOTHING_CHANGED);
    }

    //=======================================================================
    // Syscalls action
    //=======================================================================
    static bool backend_lists_syscalls(TraceManager *mgr)
    {
        return mgr != nullptr && mgr->is_active() && mgr->backend() != nullptr
            && mgr->backend()->capabilities().syscalls;
    }

    int idaapi SyscallsHandler::activate(action_activation_ctx_t *)
    {
        if ( !backend_lists_syscalls(mgr()) )
        {
            warning("This recording's backend cannot list its syscalls.");
            return 1;
        }
        std::vector<SyscallEvent> calls;
        bool cancelled = false;
        if ( !list_syscalls(mgr(), &calls, &cancelled) )
        {
            warning("The recording's backend could not list its syscalls.");
            return 1;
        }
        msg("[ida-ttd] %d syscall(s) in the recording%s.\n", (int)calls.size(),
            cancelled ? " (stopped early)" : "");
        if ( calls.empty() )
        {
            info("The recording made no syscalls.");
            return 1;
        }
        SyscallChooser *ch = new SyscallChooser(mgr(), std::move(calls));
        ch->choose();
        return 1;
    }

    action_state_t idaapi SyscallsHandler::update(action_update_ctx_t *)
    {
        return backend_lists_syscalls(mgr()) ? AST_ENABLE : AST_DISABLE;
    }
}
