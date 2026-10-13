#pragma once

#include "common/pch.h"
#include "abi/ida_ttd_backend.h"

namespace idattd
{
    // Register class masks reported to IDA (debugger_t::regclasses).
    enum RegClass
    {
        REGCLASS_GENERAL = 0x01,
        REGCLASS_SEGMENT = 0x02,
    };

    // Number of registers in each architecture's register table.
    int register_count(bool is64);

    // Fill the debugger_t metadata that describes registers/classes for the
    // given architecture (selected from the IDB bitness). Also sets the
    // processor, breakpoint bytes, page size, flags and resume modes.
    void configure_debugger(debugger_t &dbg, bool is64);

    // The same table filled from the ABI's canonical register set, which is
    // what every backend produces. 'values' has register_count(is64) entries.
    void fill_regvals(const ittd_regs &regs, bool is64, regval_t *values);

    // What a fork calls the table's register 'regidx': an ITTD_REG_* index,
    // or FORK_REG_RFLAGS. -1 for one a fork cannot change (the segments).
    int fork_register_index(int regidx, bool is64);
}
