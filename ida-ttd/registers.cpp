#include "registers.h"

namespace idattd
{
    //-----------------------------------------------------------------------
    // Register class names. The order/index is irrelevant; the mask in each
    // register_info_t::register_class_mask is what associates a register to a
    // class. The default_regclasses mask below selects which classes IDA prints
    // by default.
    static const char *g_reg_classes[] =
    {
        "General registers",
        "Segment registers",
        nullptr
    };

    //-----------------------------------------------------------------------
    // x86 (32-bit) register table. The order MUST match fill_regvals().
    static register_info_t g_x86_regs[] =
    {
        { "EAX", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "ECX", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "EDX", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "EBX", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "ESP", REGISTER_ADDRESS | REGISTER_SP,  REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "EBP", REGISTER_ADDRESS | REGISTER_FP,  REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "ESI", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "EDI", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "EIP", REGISTER_ADDRESS | REGISTER_IP,  REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "EFL", 0,                               REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "CS",  REGISTER_CS,                     REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "DS",  0,                               REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "SS",  REGISTER_SS,                     REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "ES",  0,                               REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "FS",  0,                               REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "GS",  0,                               REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
    };

    //-----------------------------------------------------------------------
    // x64 register table. The order MUST match fill_regvals().
    static register_info_t g_x64_regs[] =
    {
        { "RAX", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "RCX", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "RDX", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "RBX", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "RSP", REGISTER_ADDRESS | REGISTER_SP,  REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "RBP", REGISTER_ADDRESS | REGISTER_FP,  REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "RSI", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "RDI", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "R8",  REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "R9",  REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "R10", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "R11", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "R12", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "R13", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "R14", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "R15", REGISTER_ADDRESS,                REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "RIP", REGISTER_ADDRESS | REGISTER_IP,  REGCLASS_GENERAL, dt_qword, nullptr, 0 },
        { "EFL", 0,                               REGCLASS_GENERAL, dt_dword, nullptr, 0 },
        { "CS",  REGISTER_CS,                     REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "DS",  0,                               REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "SS",  REGISTER_SS,                     REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "ES",  0,                               REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "FS",  0,                               REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
        { "GS",  0,                               REGCLASS_SEGMENT, dt_word,  nullptr, 0 },
    };

    //-----------------------------------------------------------------------
    int register_count(bool is64)
    {
        return is64 ? qnumber(g_x64_regs) : qnumber(g_x86_regs);
    }

    //-----------------------------------------------------------------------
    void configure_debugger(debugger_t &dbg, bool is64)
    {
        dbg.version   = IDD_INTERFACE_VERSION;
        dbg.name      = "ttd";
        // NB: do NOT reuse DEBUGGER_ID_TRACE_REPLAYER (12) -- IDA's built-in
        // replay_user.dll already claims it and IDA rejects duplicate IDs.
        // Use a private value outside the known DEBUGGER_ID_ range.
        dbg.id        = 0x100;
        dbg.processor = "metapc";

        // FAKE_MEMORY would make IDA read from the idb only; we provide real
        // (recorded) memory, so we do NOT set it. SAFE: we only replay, never
        // run code. TTD: enables backwards execution. We deliberately do not
        // set DEBTHREAD so that all callbacks run on the main thread, keeping
        // UI/chooser calls safe.
        dbg.flags = DBG_FLAG_CAN_CONT_BPT
                  | DBG_FLAG_SAFE
                  | DBG_FLAG_DEBUG_DLL
                  | DBG_FLAG_TTD
                  | DBG_HAS_GET_PROCESSES
                  | DBG_HAS_SET_RESUME_MODE;

        dbg.regclasses         = g_reg_classes;
        dbg.default_regclasses = REGCLASS_GENERAL;
        dbg.registers          = is64 ? g_x64_regs : g_x86_regs;
        dbg.nregisters         = register_count(is64);

        dbg.memory_page_size = 0x1000;
        dbg.bpt_bytes        = (const uchar *)"\xCC";
        dbg.bpt_size         = 1;
        dbg.filetype         = inf_get_filetype();

        // Advertise the full forward step set plus backward single-step. With
        // DBG_FLAG_TTD this makes IDA render its native debugger toolbar/menu
        // buttons (step into/over/out, run, and their backward variants) using
        // IDA's own icons -- no custom toolbar needed.
        dbg.resume_modes = DBG_RESMOD_STEP_INTO
                         | DBG_RESMOD_STEP_OVER
                         | DBG_RESMOD_STEP_OUT
                         | DBG_RESMOD_STEP_BACKINTO;
    }

    //-----------------------------------------------------------------------
    void fill_regvals(const CROSS_PLATFORM_CONTEXT &ctx, bool is64, regval_t *values)
    {
        if ( is64 )
        {
            const AMD64_CONTEXT &c = ctx.Amd64Context;
            int i = 0;
            values[i++].set_int(c.Rax);
            values[i++].set_int(c.Rcx);
            values[i++].set_int(c.Rdx);
            values[i++].set_int(c.Rbx);
            values[i++].set_int(c.Rsp);
            values[i++].set_int(c.Rbp);
            values[i++].set_int(c.Rsi);
            values[i++].set_int(c.Rdi);
            values[i++].set_int(c.R8);
            values[i++].set_int(c.R9);
            values[i++].set_int(c.R10);
            values[i++].set_int(c.R11);
            values[i++].set_int(c.R12);
            values[i++].set_int(c.R13);
            values[i++].set_int(c.R14);
            values[i++].set_int(c.R15);
            values[i++].set_int(c.Rip);
            values[i++].set_int(c.EFlags);
            values[i++].set_int(c.SegCs);
            values[i++].set_int(c.SegDs);
            values[i++].set_int(c.SegSs);
            values[i++].set_int(c.SegEs);
            values[i++].set_int(c.SegFs);
            values[i++].set_int(c.SegGs);
        }
        else
        {
            const X86_NT5_CONTEXT &c = ctx.X86Nt5Context;
            int i = 0;
            values[i++].set_int(c.Eax);
            values[i++].set_int(c.Ecx);
            values[i++].set_int(c.Edx);
            values[i++].set_int(c.Ebx);
            values[i++].set_int(c.Esp);
            values[i++].set_int(c.Ebp);
            values[i++].set_int(c.Esi);
            values[i++].set_int(c.Edi);
            values[i++].set_int(c.Eip);
            values[i++].set_int(c.EFlags);
            values[i++].set_int(c.SegCs);
            values[i++].set_int(c.SegDs);
            values[i++].set_int(c.SegSs);
            values[i++].set_int(c.SegEs);
            values[i++].set_int(c.SegFs);
            values[i++].set_int(c.SegGs);
        }
    }
}
