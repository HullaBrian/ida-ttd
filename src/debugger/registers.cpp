#include "debugger/registers.h"

namespace idattd
{
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

    // x86 (32-bit) register table. The order must match fill_regvals().
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

    // x64 register table. The order must match fill_regvals().
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

    int register_count(bool is64)
    {
        return is64 ? qnumber(g_x64_regs) : qnumber(g_x86_regs);
    }

    void configure_debugger(debugger_t &dbg, bool is64)
    {
        dbg.version   = IDD_INTERFACE_VERSION;
        dbg.name      = "ttd";
        // NB: do not reuse DEBUGGER_ID_TRACE_REPLAYER (12) -- IDA's built-in
        // replay_user.dll already claims it and IDA rejects duplicate IDs.
        // Use a private value outside the known DEBUGGER_ID_ range.
        dbg.id        = 0x100;
        dbg.processor = "metapc";

        // FAKE_MEMORY would make IDA read from the idb only; we provide real
        // (recorded) memory, so we do not set it. SAFE: we only replay, never
        // run code. TTD: enables backwards execution. We deliberately do not
        // set DEBTHREAD so that all callbacks run on the main thread, keeping
        // UI/chooser calls safe.
        dbg.flags = DBG_FLAG_CAN_CONT_BPT
                  | DBG_FLAG_SAFE
                  | DBG_FLAG_DEBUG_DLL
                  | DBG_FLAG_TTD
                  | DBG_HAS_GET_PROCESSES
                  | DBG_HAS_SET_RESUME_MODE
                  // Read and write breakpoints of any size and alignment:
                  // both backends watch a byte range, with no debug
                  // registers to run out of. Without these IDA refused a
                  // data breakpoint before ever passing it on.
                  | DBG_FLAG_ANYSIZE_HWBPT
                  | DBG_HAS_CHECK_BPT;

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
        //
        // BACKINTO is the only backward resume mode the SDK defines (idd.hpp:
        // RESMOD_BACKINTO is the last entry before RESMOD_MAX). Backward step-over
        // and step-out are not separate modes: IDA signals the direction through
        // ev_set_backwards and then sends the ordinary RESMOD_OVER / RESMOD_OUT,
        // which TraceManager::on_resume dispatches on its stored direction.
        dbg.resume_modes = DBG_RESMOD_STEP_INTO
                         | DBG_RESMOD_STEP_OVER
                         | DBG_RESMOD_STEP_OUT
                         | DBG_RESMOD_STEP_BACKINTO;
    }

    void fill_regvals(const ittd_regs &r, bool is64, regval_t *values)
    {
        // The table order above, which for x64 is ittd_regs' own order up to
        // RIP. A 32-bit target has its registers in the low halves.
        static const int x86_gp[] = {
            ITTD_REG_RAX, ITTD_REG_RCX, ITTD_REG_RDX, ITTD_REG_RBX,
            ITTD_REG_RSP, ITTD_REG_RBP, ITTD_REG_RSI, ITTD_REG_RDI, ITTD_REG_RIP,
        };
        static const int seg_order[] = {
            ITTD_SEG_CS, ITTD_SEG_DS, ITTD_SEG_SS, ITTD_SEG_ES, ITTD_SEG_FS, ITTD_SEG_GS,
        };
        int i = 0;
        if ( is64 )
        {
            for ( int k = 0; k < ITTD_REG_GP_COUNT; k++ )
                values[i++].set_int(r.gp[k]);
        }
        else
        {
            for ( int k : x86_gp )
                values[i++].set_int((uint32_t)r.gp[k]);
        }
        values[i++].set_int((uint32_t)r.rflags);
        for ( int k : seg_order )
            values[i++].set_int(r.seg[k]);
    }

}
