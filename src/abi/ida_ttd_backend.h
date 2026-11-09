/*
 * ida-ttd backend ABI
 *
 * The boundary between the ida-ttd core plugin and a backend DLL that reads
 * one kind of recording. The core loads the DLL, asks whether it handles a
 * file, and then talks to it only through the function table below.
 *
 * ---------------------------------------------------------------------------
 * This file is placed in the public domain (CC0-1.0), separately from the rest
 * of ida-ttd, which is Apache-2.0 OR GPL-2.0-only. A backend has to include it
 * in order to exist, and the licence of the interface must not constrain the
 * licence of an implementation. See docs/modular-backends.md.
 * ---------------------------------------------------------------------------
 *
 * Why plain C:
 *
 *  - A backend may be built by a different toolchain than the core, which
 *    rules out std:: types, exceptions, RTTI and a shared CRT across the
 *    boundary.
 *  - Nothing here comes from the IDA SDK. A backend never links it, never sees
 *    an ea_t, qstring or regval_t, and never calls into IDA. That keeps every
 *    IDA dependency in the core and lets a backend be licensed independently
 *    of ida-ttd and the IDA SDK.
 *  - Bulk results go into caller-provided arrays of fixed-layout structs: no
 *    allocator shared across the boundary, no marshalling on hot paths.
 *
 * Conventions:
 *
 *  - Every call returns ITTD_OK or a negative ITTD_E* code. On error,
 *    ittd_last_error() gives a readable reason for that handle.
 *  - No exception may escape an entry point.
 *  - Addresses are guest virtual addresses as uint64_t; ITTD_BADADDR means
 *    "no address".
 *  - A "count query" is called twice: with buf == NULL to learn the count,
 *    then with an array that large. Both calls must agree for an unchanged
 *    recording. If the array is smaller than the count, the backend fills what
 *    fits, writes the full count to *out_count and returns ITTD_OK, so the
 *    caller can tell it was short. When the count is zero the core does not
 *    make the second call, so a backend that keeps an answer between the two
 *    calls must not rely on the fill to release it.
 *  - Strings are inline, NUL-terminated, fixed-size UTF-8 char arrays, so a
 *    result array is one memcpy and the caller owns all the memory.
 *  - Handles are opaque. A cursor belongs to the backend handle that made it
 *    and must be closed before it.
 */

#ifndef IDA_TTD_BACKEND_H
#define IDA_TTD_BACKEND_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ version */

/*
 * Bumped for any change that is not purely additive. The core passes the
 * version it was built against to the entry point; a backend that cannot speak
 * it returns NULL, and the core names the mismatch instead of reading a table
 * it does not understand.
 *
 * Not published yet, so every change still bumps it rather than keeping an old
 * layout alive. 2: ittd_module gained timestamp and checksum; the table gained
 * 'size' and the entries after query_frame_entry.
 */
#define ITTD_ABI_VERSION 2u

#define ITTD_BADADDR 0xFFFFFFFFFFFFFFFFull

/* ------------------------------------------------------------- status codes */

#define ITTD_OK                0
#define ITTD_E_UNSUPPORTED    -1   /* the backend does not implement this */
#define ITTD_E_NOT_OPEN       -2   /* no recording is open on this handle */
#define ITTD_E_BAD_ARG        -3
#define ITTD_E_OPEN_FAILED    -4   /* the file is not a recording this backend reads */
#define ITTD_E_NO_POSITION    -5   /* the position is not in this recording */
#define ITTD_E_CANCELLED      -6   /* the caller's progress sink said to stop */
/* A replay (fork_open, query_strings, query_buffers) was refused because the
 * recording was made against the host and ITTD_FORK_ALLOW_HOST was not given. */
#define ITTD_E_HOST_REPLAY    -7
/* A replay found no registry hives where it looked (ittd_fork_settings). */
#define ITTD_E_NO_REGISTRY    -8
/* A replay was refused because the registry hives it was given are not the
 * ones the recording was made with, and ITTD_FORK_ANY_REGISTRY was not given. */
#define ITTD_E_REGISTRY_MISMATCH -9
#define ITTD_E_FAILED        -100  /* anything else; see ittd_last_error */

/* ----------------------------------------------------------------- position */

/*
 * A point in a recording, as the backend means it.
 *
 * Two 64-bit words the core does not interpret: Microsoft TTD uses (sequence,
 * steps), Sogen a single instruction counter. Lexicographic order on (hi, lo)
 * must be the recording's own chronology; both satisfy that.
 *
 * Three values are reserved as sentinels. A backend translates them to its
 * engine's terms and must not assume the bit patterns mean anything there.
 *
 *   NONE  = { UINT64_MAX, UINT64_MAX }      "no position"
 *   BEGIN = { 0, 0 }                        "the start of the recording"
 *   END   = { UINT64_MAX, UINT64_MAX - 1 }  "the end of the recording"
 *
 * A cursor at a position shows the state *before* the instruction at its
 * program counter runs (Microsoft's meaning). Sogen's position N is the state
 * *after* instruction N, so its backend hands out N - 1 for "at instruction
 * N". The backend owns that off-by-one, so no position the core holds means
 * two different things.
 */
typedef struct ittd_position
{
    uint64_t hi;
    uint64_t lo;
} ittd_position;

typedef struct ittd_position_range
{
    ittd_position first;    /* BEGIN for "from the start" */
    ittd_position last;     /* END for "to the end" */
} ittd_position_range;

/* --------------------------------------------------------------- the trace */

/* Capability bits. The core checks these before offering a command, so no
 * action is registered that could only report that it does not work. */
#define ITTD_CAP_ACCESS_QUERIES   0x0001u  /* accesses to a range can be listed */
#define ITTD_CAP_CALL_QUERIES     0x0002u  /* calls and returns can be listed */
/* The recording says where memory was mapped, unmapped and reprotected, with
 * the protection, so query_mapping_changes is a read rather than a
 * reconstruction. Knowing *that* a range changed is not enough to set it. */
#define ITTD_CAP_MAPPING_CHANGES  0x0004u
#define ITTD_CAP_SYSCALLS         0x0008u  /* dispatched syscalls are recorded */
#define ITTD_CAP_RECORDED_EXPORTS 0x0010u  /* module exports come out of the recording */
#define ITTD_CAP_CHEAP_SEEK       0x0020u  /* seeking is cheap enough to do per listing row */
#define ITTD_CAP_REVERSE_STEP     0x0040u  /* the recording can be stepped backwards */
#define ITTD_CAP_PREPARE          0x0080u  /* prepare() has something to do */
#define ITTD_CAP_EXCEPTIONS       0x0100u  /* dispatched exceptions can be listed */
/* Reading a page of memory costs about a copy, so the core can let IDA
 * analyse a whole module (reading all of its code) when its symbols load.
 * Without it the core applies the names and skips that analysis. */
#define ITTD_CAP_CHEAP_READS      0x0200u
/* query_self_modifying answers: the recording has the write and execute
 * events to find code the program wrote before running it. */
#define ITTD_CAP_SELF_MODIFYING   0x0400u
/* The recording can be forked: replayed to a position, changed there, and run
 * on into a new recording (fork_open and the fork_* calls). */
#define ITTD_CAP_FORK             0x0800u
/* query_strings and query_buffers answer: the recording is replayed from
 * start to end with a scanner watching memory. Needs what a fork needs. */
#define ITTD_CAP_REPLAY_SCANS     0x1000u
/* regs_at answers many positions for much less than a seek and a register
 * read at each: registers are expensive to rebuild (Sogen replays from a
 * snapshot), and a batch rebuilds each stretch once for all its positions.
 * The core then reads registers for a whole listing up front; without the
 * bit it reads them through the cursor it already has at each position. */
#define ITTD_CAP_BATCH_REGS       0x2000u

#define ITTD_NAME_MAX  256
#define ITTD_PATH_MAX  520

typedef struct ittd_trace_info
{
    uint32_t      is64;             /* bitness of the recorded program, not the host */
    uint32_t      capabilities;     /* ITTD_CAP_* */
    /* Identity of this recording: stable across opens of the same file,
     * different for a re-recording of the same program. The core stores it in
     * the database so results cached for one recording are not shown for
     * another. Zero means unknown, and the core then caches nothing that a
     * changed recording would make wrong.
     *
     * A wider engine id is folded to 64 bits; Sogen's trace::id() is 128
     * random bits, so any 64 of them will do. */
    uint64_t      fingerprint;
    ittd_position first;            /* first recorded position */
    ittd_position last;             /* last recorded position */
    char          main_module[ITTD_NAME_MAX];  /* "sample.exe" */
    char          backend_name[ITTD_NAME_MAX]; /* "Microsoft TTD", "Sogen" */
} ittd_trace_info;

typedef struct ittd_module
{
    uint64_t      base;
    uint64_t      size;
    ittd_position loaded;
    ittd_position unloaded;         /* NONE while still mapped at the end */
    /* The PE header's machine: 0x8664 for x64 code, 0x14c for 32-bit code in a
     * WoW64 process, where both kinds sit side by side. 0 when the recording
     * does not say, and the core then reads the PE header itself. */
    uint32_t      machine;
    /* The image's TimeDateStamp and CheckSum as recorded, which tell a file
     * on this machine apart from another build of the same DLL. 0 when the
     * recording does not say; the core then reads the headers. */
    uint32_t      timestamp;
    uint32_t      checksum;
    uint32_t      reserved;
    char          name[ITTD_NAME_MAX];   /* base name, as recorded */
    char          path[ITTD_PATH_MAX];   /* full path on the recording machine */
} ittd_module;

typedef struct ittd_thread
{
    uint32_t      tid;
    uint32_t      reserved;
    ittd_position created;
    ittd_position exited;           /* NONE if it was alive at the end */
    /* 0 where the recording does not say. teb32 is the 32-bit TEB of a WoW64
     * thread, which has a separate 32-bit stack. The stack bounds are those at
     * creation (or at the start of the recording); a fiber switch rewrites
     * them in the TEB, so the core reads the TEB for a later position. */
    uint64_t      teb;
    uint64_t      teb32;
    uint64_t      stack_base;       /* the top: NT_TIB.StackBase */
    uint64_t      stack_limit;      /* the bottom: NT_TIB.StackLimit */
    char          name[ITTD_NAME_MAX];   /* empty when the recording does not say */
} ittd_thread;

/* One thing worth putting on the timeline. */
#define ITTD_EV_THREAD_START   1u
#define ITTD_EV_THREAD_EXIT    2u
#define ITTD_EV_MODULE_LOAD    3u
#define ITTD_EV_MODULE_UNLOAD  4u
#define ITTD_EV_EXCEPTION      5u
#define ITTD_EV_OTHER        100u

typedef struct ittd_trace_event
{
    ittd_position pos;
    uint32_t      kind;             /* ITTD_EV_* */
    uint32_t      tid;
    char          text[ITTD_NAME_MAX];   /* what to show in the listing */
} ittd_trace_event;

/* ------------------------------------------------------------------ access */

#define ITTD_ACCESS_READ   0x1u
#define ITTD_ACCESS_WRITE  0x2u
#define ITTD_ACCESS_EXEC   0x4u
#define ITTD_ACCESS_ALL    0x7u

typedef struct ittd_access
{
    ittd_position pos;
    uint64_t      pc;               /* the instruction that did it */
    uint64_t      addr;             /* the address it touched */
    uint32_t      size;
    uint32_t      kind;             /* one ITTD_ACCESS_* value */
    uint32_t      tid;
    uint32_t      reserved;
} ittd_access;

/* Set when the callee was reached by a jump (a tail call, an import thunk) or
 * by anything else that was not a call instruction. Such an entry has no
 * return of its own: the function it jumped from returns for it. */
#define ITTD_CALL_F_NOT_CALL  0x1u

/*
 * One entry into a function. Three positions, because the three questions
 * asked of a call are answered at three places:
 *
 *   pos        at the call instruction: who called, and from where.
 *              NONE when the thread began inside the callee.
 *   entry_pos  at the callee's first instruction: the arguments, before the
 *              callee has touched them.
 *   ret_pos    just after the return has executed, with the program counter
 *              back at the return address: the return value. NONE when the
 *              recording does not show the return (it had not returned by
 *              the end, it unwound, it was entered by a jump, or the backend
 *              cannot pair returns).
 */
typedef struct ittd_call
{
    ittd_position pos;
    ittd_position entry_pos;
    ittd_position ret_pos;
    uint64_t      site;             /* the call instruction; ITTD_BADADDR with pos NONE */
    uint64_t      target;           /* where it actually went */
    uint32_t      tid;
    uint32_t      flags;            /* ITTD_CALL_F_* */
} ittd_call;

/* One indirect branch site and one target it reached. A site that reached
 * several targets appears once per target; the core groups them. */
typedef struct ittd_call_target
{
    uint64_t      site;
    uint64_t      target;
    uint64_t      hits;             /* times this site reached this target */
    /* The first time it did, so a listing can offer to go there. NONE when the
     * backend does not know. */
    ittd_position first_pos;
    uint32_t      flags;            /* ITTD_CALL_F_NOT_CALL for a jump */
    uint32_t      reserved;
} ittd_call_target;

/* query_indirect: also report indirect jumps (switch tables, import thunks),
 * where IDA's graph breaks as often as at a call. */
#define ITTD_INDIRECT_JUMPS  0x1u

/*
 * An exception the system dispatched to the program: a fault, a breakpoint, a
 * single step, or one raised through the kernel.
 *
 * A software exception that never leaves user mode (a C++ throw, most
 * RaiseException calls) is not dispatched by the system on x64 and may be
 * missing here; the core finds those as calls to ntdll!RtlRaiseException.
 */
typedef struct ittd_exception
{
    ittd_position pos;              /* the dispatch begins */
    ittd_position raise_pos;        /* at the instruction that raised it; NONE if unknown */
    uint64_t      address;          /* ExceptionAddress */
    /* ExceptionInformation[0..1]. For an access violation: 0 read, 1 write,
     * 8 execute, then the address that was accessed. */
    uint64_t      information[2];
    uint32_t      code;             /* ExceptionCode; 0 when the record was not found */
    uint32_t      flags;            /* ExceptionFlags */
    uint32_t      tid;
    uint32_t      reserved;
} ittd_exception;

/*
 * A syscall the program made, as the recording dispatched it. Only listed by
 * a backend with ITTD_CAP_SYSCALLS.
 *
 * The arguments are the registers at 'pos' (r10, rdx, r8, r9, then the
 * stack), which regs_at reads in a batch.
 */
typedef struct ittd_syscall
{
    ittd_position pos;              /* at the syscall instruction */
    uint64_t      result;           /* the value it returned in rax */
    uint32_t      number;           /* the syscall number (eax going in) */
    uint32_t      tid;              /* 0 when unknown */
    char          name[64];         /* "NtCreateFile"; empty when unknown */
} ittd_syscall;

/* One out parameter of a syscall, for query_out_values: where it points,
 * and what it held when the call was made. */
typedef struct ittd_out_slot
{
    ittd_position call;             /* the syscall instruction */
    uint64_t      addr;             /* the out parameter's target */
    uint64_t      before;           /* its value at the call */
    uint32_t      tid;              /* the calling thread */
    uint32_t      width;            /* 4 or 8 bytes */
} ittd_out_slot;

/* One read of read_memory_at: 'size' bytes at 'addr' as they were at 'pos',
 * into the caller's buffers at 'offset'. */
typedef struct ittd_mem_read
{
    ittd_position pos;
    uint64_t      addr;
    uint64_t      offset;
    uint64_t      size;
} ittd_mem_read;

/* One cell of query_access_heat: the accesses to one page in one slice of
 * the recording's time. */
typedef struct ittd_heat_cell
{
    uint64_t page;                  /* address >> page_shift */
    uint32_t slice;                 /* 0 .. slices - 1 */
    uint32_t reads;
    uint32_t writes;                /* the program's and the system's */
    uint32_t executes;              /* instructions run from the page */
} ittd_heat_cell;

/*
 * Code the program wrote and then ran: an executed instruction some of whose
 * bytes an earlier instruction of the program wrote. Writes the system made
 * (the loader mapping an image, a syscall filling a buffer) do not count.
 * One entry per executed address, with the write that made it and its first
 * execution.
 */
typedef struct ittd_selfmod
{
    uint64_t      address;          /* the instruction executed */
    uint64_t      size;             /* its length */
    ittd_position write_pos;        /* at the instruction that wrote it */
    uint64_t      write_ip;         /* that instruction's address */
    ittd_position execute_pos;      /* at its first execution */
    uint64_t      executions;       /* how often it ran after the write */
} ittd_selfmod;

/* One breakpoint: an execution of 'addr', or a read or write of any byte of
 * [addr, addr + size). */
typedef struct ittd_breakpoint
{
    uint64_t addr;
    uint64_t size;                  /* 1 for an execute breakpoint */
    uint32_t kinds;                 /* ITTD_ACCESS_* */
    uint32_t reserved;
} ittd_breakpoint;

typedef struct ittd_symbol
{
    uint64_t ea;
    uint32_t is_export;             /* 0 for an internal name */
    uint32_t reserved;
    char     name[ITTD_NAME_MAX];
} ittd_symbol;

typedef struct ittd_range
{
    uint64_t start;
    uint64_t end;                   /* exclusive */
} ittd_range;

/* One mapping, protection change or unmapping the recording made. Only
 * meaningful with ITTD_CAP_MAPPING_CHANGES; a backend without it reconstructs
 * the same information some other way and reports it through this struct. */
#define ITTD_MAP_ALLOC      0u
#define ITTD_MAP_PROTECT    1u
#define ITTD_MAP_FREE       2u
#define ITTD_MAP_MAPVIEW    3u
#define ITTD_MAP_UNMAPVIEW  4u
/* Not an operation but its outcome: [base, base + size) is now in 'state',
 * with 'protect', 'alloc_base' and 'region_type'. A backend that records the
 * region bookkeeping rather than the calls (Sogen) reports every change this
 * way; applying it is a plain overwrite. */
#define ITTD_MAP_STATE      5u

#define ITTD_MAP_F_EXACT          0x1u  /* base/size are the kernel's own answer */
#define ITTD_MAP_F_OTHER_PROCESS  0x2u  /* the call targeted another process */
#define ITTD_MAP_F_IN_MODULE      0x4u  /* the range lies inside a loaded module */
/* Part of the map as it stood when recording began, rather than a change made
 * during it: the image, ntdll, the PEB and TEBs, the stacks. Such entries come
 * first, at the first position, and are always ITTD_MAP_STATE. */
#define ITTD_MAP_F_AT_START       0x8u

/* ittd_mapping_change.state, .mem_type, .protect and .alloc_protect carry
 * Windows' own MEMORY_BASIC_INFORMATION values: MEM_COMMIT/RESERVE/FREE;
 * MEM_PRIVATE/MAPPED/IMAGE; PAGE_* with PAGE_GUARD and the other modifiers
 * kept. Both engines and the core's memory map use them natively, so an ABI
 * vocabulary would only add translation. Zero is "unknown".
 *
 * region_type is finer than mem_type: it tells a file view from a view of a
 * pagefile-backed section, and names memory Windows has no type for. */
#define ITTD_REGION_UNKNOWN  0u   /* or free */
#define ITTD_REGION_PRIVATE  1u
#define ITTD_REGION_IMAGE    2u
#define ITTD_REGION_MAPPED   3u   /* a view of a file */
#define ITTD_REGION_SECTION  4u   /* a view of a pagefile-backed section */
#define ITTD_REGION_MMIO     5u   /* device or host-aliased memory */
#define ITTD_REGION_HOST     6u   /* reserved by the recording host, not the program */

#define ITTD_CHAIN_MAX 8

typedef struct ittd_mapping_change
{
    ittd_position pos;              /* where the change took effect */
    ittd_position call_pos;         /* where it was asked for; NONE if unknown */
    uint64_t      base;
    uint64_t      size;             /* 0 on a whole-region release */
    uint64_t      api;              /* the routine that was called; BADADDR if unknown */
    /* The call chain that led here, innermost first, one frame per module
     * boundary crossed: a heap allocation twenty frames deep in the allocator
     * still reaches the code that wanted the memory. */
    uint64_t      chain[ITTD_CHAIN_MAX];
    uint32_t      chain_n;
    uint32_t      kind;             /* ITTD_MAP_* */
    uint32_t      protect;          /* PAGE_* on Windows, or the free type */
    uint32_t      flags;            /* ITTD_MAP_F_* */
    uint32_t      tid;
    uint32_t      reserved;
    /* What the range looks like afterwards, as VirtualQuery would say (see
     * above for the values). Zero where the backend cannot tell; required for
     * ITTD_MAP_STATE, where 'protect' is the protection of committed memory
     * and 0 otherwise. */
    uint64_t      alloc_base;       /* AllocationBase; 0 for free memory or unknown */
    uint32_t      state;            /* MEM_COMMIT / MEM_RESERVE / MEM_FREE */
    uint32_t      mem_type;         /* MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE */
    uint32_t      alloc_protect;    /* AllocationProtect */
    uint32_t      region_type;      /* ITTD_REGION_* */
    /* The mapped file of a file view: index into query_mapping_files' list
     * plus one; 0 for none. An index rather than an inline name because the
     * same file is mapped many times and a path is 520 bytes. Images carry
     * none: the module list names them. */
    uint32_t      file;
    uint32_t      reserved2;
} ittd_mapping_change;

/* One entry of query_mapping_files. */
typedef struct ittd_name
{
    char name[ITTD_PATH_MAX];
} ittd_name;

/* --------------------------------------------------------------- registers */

/*
 * A canonical x86-64 register set.
 *
 * The core maps this onto IDA's register array; a backend DLL must not see
 * IDA's regval_t. Both engines have something close already (Microsoft's
 * CROSS_PLATFORM_CONTEXT, Sogen's save_registers blob), so it is cheap to
 * produce.
 */
#define ITTD_REG_RAX  0
#define ITTD_REG_RCX  1
#define ITTD_REG_RDX  2
#define ITTD_REG_RBX  3
#define ITTD_REG_RSP  4
#define ITTD_REG_RBP  5
#define ITTD_REG_RSI  6
#define ITTD_REG_RDI  7
#define ITTD_REG_R8   8
#define ITTD_REG_R15 15
#define ITTD_REG_RIP 16
#define ITTD_REG_GP_COUNT 17

#define ITTD_SEG_CS 0
#define ITTD_SEG_SS 1
#define ITTD_SEG_DS 2
#define ITTD_SEG_ES 3
#define ITTD_SEG_FS 4
#define ITTD_SEG_GS 5
#define ITTD_SEG_COUNT 6

/* Which groups the backend actually filled. */
#define ITTD_REGS_GP   0x1u
#define ITTD_REGS_SEG  0x2u
#define ITTD_REGS_XMM  0x4u
#define ITTD_REGS_FPU  0x8u

typedef struct ittd_regs
{
    uint64_t gp[ITTD_REG_GP_COUNT];   /* indexed by ITTD_REG_* */
    uint64_t rflags;
    uint64_t fs_base;
    uint64_t gs_base;
    uint16_t seg[ITTD_SEG_COUNT];     /* indexed by ITTD_SEG_* */
    uint16_t reserved[2];
    uint32_t have;                    /* ITTD_REGS_* */
    uint8_t  xmm[16][16];
} ittd_regs;

/* ------------------------------------------------------------------- forks */

/*
 * A fork is the recorded program brought back to life at a position: an
 * emulator replayed to it, whose registers and memory can be changed before
 * it runs on, recording into a new trace that starts at that position. The
 * parent is not touched.
 *
 * Replaying needs what the recording ran against outside its checkpoints: the
 * registry hives, and for a recording made against the host (no emulation
 * root) the host's system DLLs. A replay elsewhere may diverge before
 * reaching the position; fork_open then fails, naming what differs.
 */
typedef struct ittd_fork ittd_fork;   /* opaque */

/* A syscall or host write whose result differs from the recording is a
 * divergence, instead of taking the recorded result. */
#define ITTD_FORK_STRICT      0x1u
/* Replay a recording made against the host (no emulation root). Its program
 * runs again against this machine's files and network, repeating whatever it
 * created, renamed, deleted or sent. Without the flag a backend refuses. */
#define ITTD_FORK_ALLOW_HOST  0x2u
/* Replay with registry hives that are not the ones the recording was made
 * with (check_registry). The replay then diverges wherever the program reads
 * a key that differs. Without the flag a backend that can tell refuses. */
#define ITTD_FORK_ANY_REGISTRY 0x4u

/* What replaying a recording needs, as far as the recording says
 * (replay_env), so the core can look for it first and name what is missing. */
typedef struct ittd_replay_env
{
    uint32_t size;                  /* sizeof(ittd_replay_env), set by the caller */
    /* Non-zero: made against the host, not an emulation root. A replay then
     * needs ITTD_FORK_ALLOW_HOST, and the system DLLs of the machine it was
     * made on. */
    uint32_t host;
    /* Non-zero: the recording names the registry hives it was made with, so
     * check_registry can tell the right ones from others. */
    uint32_t registry_known;
    /* Non-zero: the recording carries what it read of its hives, so a replay
     * needs no hive files. A fork that reads further than the recording did
     * still needs the recording's own hives (check_registry finds them). */
    uint32_t registry_carried;
    /* Whether this machine has the system DLLs the recording was made with
     * (its emulation root's, or for the host this machine's own):
     * ITTD_DLLS_*. A replay with others diverges early. */
    uint32_t system_dlls;
    /* Where the recording's own environment keeps its hives (the emulation
     * root's registry folder), whether or not it exists here; empty for a
     * recording made against the host. */
    char     registry_hint[ITTD_PATH_MAX];
    /* The emulation root it was made with; empty for the host. */
    char     emulation_root[ITTD_PATH_MAX];
    /* The Windows it ran on, as "10.0.26100.1"; empty when not recorded. */
    char     windows_version[ITTD_NAME_MAX];
} ittd_replay_env;

#define ITTD_DLLS_UNKNOWN 0u    /* the recording does not say, or they cannot be read */
#define ITTD_DLLS_SAME    1u
#define ITTD_DLLS_DIFFER  2u

/* check_registry: the folder holds hives, and the recording does not say
 * which it was made with. */
#define ITTD_REGISTRY_UNVERIFIED 1

typedef struct ittd_fork_settings
{
    uint32_t    size;               /* sizeof(ittd_fork_settings) */
    uint32_t    flags;              /* ITTD_FORK_* */
    /* The folder holding the registry hives (SYSTEM, SOFTWARE, SAM, SECURITY,
     * HARDWARE, NTUSER.DAT). NULL or empty: the backend's default. Only used
     * for a recording made against the host; one made in an emulation root
     * loads <emulation_root>\registry. */
    const char *registry_dir;
    /* The emulation root. NULL: the one the recording was made with (empty
     * for the host). Set it when that root lives elsewhere on this machine. */
    const char *emulation_root;
} ittd_fork_settings;

/* A string the program had in memory at some point: ASCII or UTF-16LE text
 * of at least the asked-for length, found by watching every write during a
 * replay (and the memory at the start). */
typedef struct ittd_string_hit
{
    uint64_t      address;
    /* At the write that completed it; the start of the recording for text
     * that was there from the beginning. */
    ittd_position pos;
    uint32_t      wide;             /* 1: UTF-16LE in memory */
    uint32_t      length;           /* in characters */
    char          text[ITTD_NAME_MAX];   /* UTF-8, cut to fit */
} ittd_string_hit;

/* A buffer the program filled: a run of memory written by the same code,
 * classified by what it holds ("pe", "text", ...). */
typedef struct ittd_buffer_hit
{
    uint64_t      address;
    uint64_t      size;
    ittd_position first_pos;        /* at its first write */
    ittd_position last_pos;         /* at its last write */
    uint64_t      writer_ip;        /* the instruction that wrote it */
    uint64_t      writes;
    char          kind[32];
    char          preview[ITTD_NAME_MAX];
} ittd_buffer_hit;

/* ------------------------------------------------------- progress and stop */

/*
 * How a long query reports progress and asks whether to stop. The core
 * implements it with a wait box on IDA's main thread.
 *
 * A backend may call these from any thread, but must not assume they are
 * cheap or call them while holding a lock it needs to make progress. A fast
 * query may ignore the sink. A null sink means "no progress, never
 * cancelled".
 */
/* visit_positions: memory at the position being visited, and the callback. */
typedef size_t (*ittd_read_fn)(void *read_ctx, uint64_t addr, void *buf, size_t size);
typedef void (*ittd_visit_fn)(void *ud, size_t index, int phase, ittd_read_fn read, void *read_ctx);

typedef struct ittd_progress
{
    void *ud;
    /* 0..1000, so a long query can show tenths of a percent. */
    void (*report)(void *ud, uint32_t permille);
    /* Non-zero means stop as soon as convenient and return ITTD_E_CANCELLED,
     * or ITTD_OK with what was gathered and *out_truncated set. */
    int  (*cancelled)(void *ud);
} ittd_progress;

/* --------------------------------------------------------- stopping reasons */

#define ITTD_STOP_STEPPED     0   /* the movement completed */
#define ITTD_STOP_BREAKPOINT  1   /* a breakpoint was hit on the way */
#define ITTD_STOP_BOUNDARY    2   /* the start or end of the recording */
#define ITTD_STOP_FAILED      3

/* ------------------------------------------------------------------ handles */

typedef struct ittd_backend ittd_backend;   /* opaque */
typedef struct ittd_cursor  ittd_cursor;    /* opaque */

/* ---------------------------------------------------------- the call table */

/*
 * One instance per backend module, returned by the entry point. The core keeps
 * the pointer for the life of the process, so the table must be static.
 *
 * Any function pointer may be NULL, meaning ITTD_E_UNSUPPORTED; the core
 * checks before calling, so a backend fills in only what it implements.
 */
typedef struct ittd_backend_api
{
    uint32_t    abi_version;        /* must equal the version asked for */
    /* sizeof(ittd_backend_api) as the backend was built. The table grows at
     * its end; entries past 'size' are absent, and the core checks it before
     * using anything added after the first table. */
    uint32_t    size;

    /* ---- identity, before anything is open ---------------------------- */

    /* Short id used in the database and in build switches: "msttd", "sogen".
     * It is stored in the trace-link record, so changing it orphans existing
     * databases. */
    const char *(*id)(void);
    const char *(*display_name)(void);
    /* The File > Open filter fragment, e.g. "Microsoft TTD trace (*.run)". */
    const char *(*file_filter)(void);
    /* Non-zero if this backend handles 'path'. Asked of every loaded backend
     * in load order, so it must be cheap: a signature read at most, never a
     * full open. */
    int         (*can_open)(const char *path);

    /* ---- the session -------------------------------------------------- */

    /* NULL on failure, with the reason in ittd_last_error on the module. */
    ittd_backend *(*open)(const char *path);
    void          (*close)(ittd_backend *b);
    /* Valid for the backend handle, or for the module when b is NULL. Owned by
     * the backend and valid until the next call on the same handle. */
    const char   *(*last_error)(ittd_backend *b);
    int           (*info)(ittd_backend *b, ittd_trace_info *out);

    /* One-off work per recording that makes seeks fast: building Microsoft's
     * memory index, filling Sogen's keyframes. The core offers it when a
     * session starts, and the user may decline. Only called when
     * ITTD_CAP_PREPARE is set. */
    int (*prepare)(ittd_backend *b, const ittd_progress *progress);

    /* ---- positions ---------------------------------------------------- */

    /* Render 'p' into 'buf' (NUL-terminated, truncated if it does not fit). */
    int (*format_position)(ittd_backend *b, ittd_position p, char *buf, size_t buf_size);
    int (*parse_position)(ittd_backend *b, const char *text, ittd_position *out);
    /* What to put next to the input box, e.g. "Sequence:Steps in hex". */
    const char *(*position_syntax)(ittd_backend *b);

    /* ---- cursors ------------------------------------------------------ */

    /* A movable viewpoint. The core makes one for the debugger's playhead and
     * one per concurrent query, so a query never moves what the user sees. */
    ittd_cursor *(*cursor_open)(ittd_backend *b);
    void         (*cursor_close)(ittd_cursor *c);

    int (*cursor_position)(ittd_cursor *c, ittd_position *out);
    /* Move to 'p', resolving the BEGIN/END sentinels. */
    int (*cursor_seek)(ittd_cursor *c, ittd_position p);
    int (*cursor_thread)(ittd_cursor *c, uint32_t *out_tid);
    int (*cursor_regs)(ittd_cursor *c, ittd_regs *out);

    /*
     * Bytes as the recording has them at this position.
     *
     * 'known' gets one ITTD_KNOWN_* byte per requested byte. Unknown bytes are
     * left untouched; the core fills them from the module's on-disk image,
     * which is the same job for every backend. A placeholder byte is written
     * as zero, but the core still prefers the image for it: an engine that
     * knows a page is mapped but not its value says "zero", and believing
     * that once cost a string literal its first bytes.
     *
     * *out_known receives the number of bytes marked known.
     */
    int (*cursor_read_memory)(ittd_cursor *c, uint64_t ea, void *buf, uint8_t *known,
                              size_t size, size_t *out_known);
#define ITTD_KNOWN_NO          0u   /* nothing to serve */
#define ITTD_KNOWN_YES         1u   /* the recording's value */
#define ITTD_KNOWN_PLACEHOLDER 2u   /* mapped, but the value is not known: zero */

    /* The threads alive at this position. A count query. */
    int (*cursor_threads)(ittd_cursor *c, ittd_thread *buf, size_t cap, size_t *out_count);

    /* ---- navigation --------------------------------------------------- */

    /*
     * Stepping is a strategy, not a primitive. "Step over backwards" for a
     * replay engine is: rewind, notice the cursor landed in a callee that had
     * just returned, rewind out of it. For an indexed trace it is a read of
     * the previous execute event at this frame's depth. Each has a cheap route
     * the other lacks, so the whole family belongs to the backend.
     *
     * Each moves 'c' and writes an ITTD_STOP_* value to *out_stop. 'forward'
     * is non-zero for forwards. All honour the nav_breakpoints set.
     */
    int (*nav_step)(ittd_cursor *c, int forward, int *out_stop);
    int (*nav_step_over)(ittd_cursor *c, int forward, int *out_stop);
    int (*nav_step_out)(ittd_cursor *c, int forward, int *out_stop);
    int (*nav_run)(ittd_cursor *c, int forward, int *out_stop);
    int (*nav_run_to)(ittd_cursor *c, uint64_t addr, int forward, int *out_stop);

    /* Breakpoints as the whole set: both engines key them by address, and
     * replacing the set is cheaper and harder to get wrong than reconciling
     * adds and deletes. An execute breakpoint stops with the program counter
     * on 'addr'; a data breakpoint stops at the instruction that made the
     * access. */
    int (*nav_breakpoints)(ittd_cursor *c, const ittd_breakpoint *bpts, size_t count);

    /* ---- enumeration -------------------------------------------------- */

    int (*modules)(ittd_backend *b, ittd_module *buf, size_t cap, size_t *out_count);
    int (*threads)(ittd_backend *b, ittd_thread *buf, size_t cap, size_t *out_count);
    int (*timeline)(ittd_backend *b, ittd_trace_event *buf, size_t cap, size_t *out_count);

    /* ---- whole-trace queries ------------------------------------------ */

    /*
     * Each may take minutes on one backend and microseconds on another:
     * Microsoft replays the recording with a watchpoint armed, Sogen reads a
     * page index. That is why the ABI asks questions instead of offering
     * watchpoints and a replay loop.
     *
     * All are count queries, take an optional progress sink, and set
     * *out_truncated when a cap or a cancellation makes the answer a prefix.
     */
    int (*query_accesses)(ittd_backend *b, uint64_t lo, uint64_t hi, uint32_t kinds,
                          ittd_position_range when,
                          ittd_access *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress);

    /* The distinct addresses inside 'ranges' that the recording executed.
     * Separate from query_accesses because coverage wants a set, not millions
     * of events, and both backends produce one much more cheaply. */
    int (*query_executed)(ittd_backend *b, const ittd_range *ranges, size_t nranges,
                          uint64_t *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress);

    /* Every call, within 'when', to one of 'targets' (ntargets == 0 means
     * every call). */
    int (*query_calls)(ittd_backend *b, const uint64_t *targets, size_t ntargets,
                       ittd_position_range when,
                       ittd_call *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *progress);

    /* Where every indirect call made from inside 'ranges' went, and with
     * ITTD_INDIRECT_JUMPS in 'flags' every indirect jump too. Separate from
     * query_calls because the answer is grouped by site, not by invocation.
     * A branch that faulted instead of reaching its target is left out. */
    int (*query_indirect)(ittd_backend *b, const ittd_range *ranges, size_t nranges,
                          uint32_t flags,
                          ittd_call_target *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress);

    /* Every mapping, protection change and unmapping. With
     * ITTD_CAP_MAPPING_CHANGES they are read from the recording; without, they
     * are reconstructed, which is expensive and uses the progress sink. */
    int (*query_mapping_changes)(ittd_backend *b,
                                 ittd_mapping_change *buf, size_t cap, size_t *out_count,
                                 int *out_truncated, const ittd_progress *progress);

    /* ---- symbols ------------------------------------------------------ */

    /*
     * Named addresses the recording knows about, and function bounds.
     *
     * Microsoft TTD records neither, so its backend parses the export
     * directory and .pdata out of guest memory; Sogen stores every module's
     * export directory in the trace. Either way the core gets a list and
     * applies IDA names.
     */
    int (*module_symbols)(ittd_backend *b, uint64_t base,
                          ittd_symbol *buf, size_t cap, size_t *out_count);
    int (*module_functions)(ittd_backend *b, uint64_t base,
                            ittd_range *buf, size_t cap, size_t *out_count);

    /* ---- later additions ---------------------------------------------- */

    /* Every exception the system dispatched, in order. A count query. Only
     * called when ITTD_CAP_EXCEPTIONS is set. */
    int (*query_exceptions)(ittd_backend *b,
                            ittd_exception *buf, size_t cap, size_t *out_count,
                            int *out_truncated, const ittd_progress *progress);

    /*
     * The registers at each of 'count' positions, into out[0..count): for
     * argument and return values down a call listing (two positions per call,
     * thousands of calls).
     *
     * A batch because neighbouring positions share work: Sogen measured half
     * the time for positions in order against the same ones shuffled.
     * Positions may come in any order; a backend that cares sorts a copy.
     *
     * out[i].have is 0 for a position the backend could not reconstruct; that
     * is not an error. NULL means the core seeks a scratch cursor instead.
     */
    int (*regs_at)(ittd_backend *b, const ittd_position *positions, size_t count,
                   ittd_regs *out, const ittd_progress *progress);

    /* The file names ittd_mapping_change.file refers to, in index order. A
     * count query, valid after query_mapping_changes. */
    int (*query_mapping_files)(ittd_backend *b, ittd_name *buf, size_t cap,
                               size_t *out_count);

    /*
     * The instructions executed within 'when', in order, as ITTD_ACCESS_EXEC
     * accesses whose pc is the instruction, on thread 'tid' (0: every
     * thread). The core walks them to lay out runtime-only code and to find
     * where a function began.
     *
     * Not a count query, because a replay engine cannot count without doing
     * all the work: the backend fills at most 'cap' entries, writes how many
     * to *out_count, and sets *out_truncated when the range held more. The
     * caller keeps 'when' short.
     */
    int (*query_instructions)(ittd_backend *b, ittd_position_range when, uint32_t tid,
                              ittd_access *buf, size_t cap, size_t *out_count,
                              int *out_truncated, const ittd_progress *progress);

    /* A position about 'delta' instructions from 'p' (negative: earlier),
     * worked out without seeking and clamped to the recording. "About"
     * because every thread's instructions count. Used to open a window of
     * context around the playhead. */
    int (*position_add)(ittd_backend *b, ittd_position p, int64_t delta, ittd_position *out);

    /*
     * The call that entered thread 'tid''s frame at 'at': the call
     * instruction's position and its target (the function's entry). Searches
     * back about 'max_back' instructions at most; ITTD_E_FAILED when the call
     * is further back or the thread is in its outermost frame. Calls are
     * matched with returns, so a frame entered and left in between does not
     * count. Runs on every stop in code outside any module, so it must be
     * cheap for small 'max_back'.
     */
    int (*query_frame_entry)(ittd_backend *b, ittd_position at, uint32_t tid, uint64_t max_back,
                             ittd_position *out_call, uint64_t *out_entry);

    /* ---- added to the first table: the core checks 'size' first --------- */

    /* The host's log, for diagnostics a backend would otherwise drop: one
     * line per call, newline included. set_log is called before anything is
     * opened; the callback may then be called from any thread. */
    void (*set_log)(void (*log)(void *ud, const char *line), void *ud);

    /* Non-zero when prepare() has nothing left to do for the open recording;
     * asked before offering a long preparation. */
    int (*prepared)(ittd_backend *b);

    /* The registers of thread 'tid' at the cursor's position, for the host's
     * thread list. ITTD_E_UNSUPPORTED when only the current thread's are
     * known. */
    int (*cursor_thread_regs)(ittd_cursor *c, uint32_t tid, ittd_regs *out);

    /* Rebuild [lo, hi) as of the cursor's position from the recording's own
     * writes, for memory a position read cannot answer (an unpacker's output
     * before it runs), and serve it from then on. 'replace' discards anything
     * rebuilt for the range before. *out_bytes is the number recovered (0 for
     * a backend whose reads are complete). */
    int (*cursor_rebuild_range)(ittd_cursor *c, uint64_t lo, uint64_t hi, int replace,
                                uint64_t *out_bytes);

    /* A message for the user about the last movement on 'c', shown after the
     * stop ("this frame does not return anywhere"), NUL-terminated into 'buf';
     * empty when there is none. Taking it clears it. */
    int (*nav_take_notice)(ittd_cursor *c, char *buf, size_t buf_size);

    /* Progress and Cancel for later movements on 'c'; NULL clears it. The
     * core sets one around each movement and clears it after, and the pointer
     * stays valid until then. Movements run on the host's main thread. */
    int (*nav_set_progress)(ittd_cursor *c, const ittd_progress *progress);

    /* Every syscall the program made, in order. A count query. Only called
     * when ITTD_CAP_SYSCALLS is set. */
    int (*query_syscalls)(ittd_backend *b,
                          ittd_syscall *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress);

    /* Every instruction the program wrote before running it, by address. A
     * count query over the whole recording; expect seconds. Only called when
     * ITTD_CAP_SELF_MODIFYING is set. */
    int (*query_self_modifying)(ittd_backend *b,
                                ittd_selfmod *buf, size_t cap, size_t *out_count,
                                int *out_truncated, const ittd_progress *progress);

    /* ---- forks (ITTD_CAP_FORK) ---------------------------------------- */

    /* Replay to 'at' and hold the program there. Expensive: a checkpoint
     * restore plus up to a checkpoint interval of verified replay. */
    int (*fork_open)(ittd_backend *b, ittd_position at, const ittd_fork_settings *settings,
                     const ittd_progress *progress, ittd_fork **out);
    /* The registers of the thread that runs next, which a set changes. */
    int (*fork_regs)(ittd_fork *f, ittd_regs *out);
    /* The groups 'have' names are written: GP (with rflags) and SEG bases. */
    int (*fork_set_regs)(ittd_fork *f, const ittd_regs *regs);
    int (*fork_write_memory)(ittd_fork *f, uint64_t ea, const void *buf, size_t size);
    /* Run on from the fork, recording into 'path', until the program exits or
     * 'max_instructions' ran (0: no limit). 'note' goes into the new trace's
     * manifest. Can be called once per fork. */
    int (*fork_record)(ittd_fork *f, const char *path, uint64_t max_instructions,
                       const char *note, const ittd_progress *progress,
                       uint64_t *out_instructions);
    void (*fork_close)(ittd_fork *f);

    /* ---- replay scans (ITTD_CAP_REPLAY_SCANS) ------------------------- */

    /* Count queries over a full replay of the recording (tens of seconds on a
     * large one). 'settings' as for fork_open. A backend keeps the answer, so
     * the fill call of count-then-fill costs nothing. */
    int (*query_strings)(ittd_backend *b, const ittd_fork_settings *settings, uint32_t min_length,
                         ittd_string_hit *buf, size_t cap, size_t *out_count,
                         int *out_truncated, const ittd_progress *progress);
    int (*query_buffers)(ittd_backend *b, const ittd_fork_settings *settings,
                         ittd_buffer_hit *buf, size_t cap, size_t *out_count,
                         int *out_truncated, const ittd_progress *progress);

    /* What the last query_strings or query_buffers could not cover, in words,
     * or "" when it covered the whole recording. A replay that diverges (this
     * machine's files differ from the recorded ones) resumes at the next
     * checkpoint; this names the stretches it skipped. */
    const char *(*scan_notice)(ittd_backend *b);

    /* ---- value origins ------------------------------------------------ */

    /* The last instruction of thread 'tid' before 'at' that changed register
     * 'reg' (ITTD_REG_*, or ITTD_ORIGIN_XMM0 + n for xmm n), looking back
     * about 'max_back' of the thread's steps at most. *out_pos is that
     * instruction's position, before it ran; *out_found is zero when nothing
     * in the window changed the register. Optional: without it the core steps
     * back one instruction at a time. */
    int (*query_register_change)(ittd_backend *b, ittd_position at, uint32_t tid, uint32_t reg,
                                 uint64_t max_back, ittd_position *out_pos, int *out_found,
                                 const ittd_progress *progress);

    /* ---- the memory heatmap ------------------------------------------- */

    /* Every access the recording made, counted by page (1 << page_shift
     * bytes) and by slice of time ('slices' equal stretches on the backend's
     * own clock). Empty cells are left out. A count query over the whole
     * recording; expect seconds. Optional. */
    int (*query_access_heat)(ittd_backend *b, uint32_t page_shift, uint32_t slices,
                             ittd_heat_cell *buf, size_t cap, size_t *out_count,
                             int *out_truncated, const ittd_progress *progress);
    /* Where slice 'slice' of 'slices' begins. */
    int (*heat_slice_position)(ittd_backend *b, uint32_t slices, uint32_t slice, ittd_position *out);

    /* ---- syscall out parameters ---------------------------------------- */

    /* What each syscall wrote through an out parameter: values[i] and
     * known[i] (non-zero when found) for slots[i]. Microsoft TTD does not
     * record the kernel's writes where they happen, so its backend finds the
     * value where the program first reads it. Optional: without it the core
     * reads each slot one position after the call. */
    int (*query_out_values)(ittd_backend *b, const ittd_out_slot *slots, size_t count,
                            uint64_t *values, uint8_t *known, const ittd_progress *progress);

    /* ---- the memory heatmap, over part of the recording ---------------- */

    /* query_access_heat and heat_slice_position for the stretch 'when' only,
     * cut into 'slices' on the same clock: how the heatmap zooms in. Optional
     * (both or neither); without them the heatmap shows the whole recording
     * only. */
    int (*query_access_heat_window)(ittd_backend *b, uint32_t page_shift, uint32_t slices,
                                    ittd_position_range when,
                                    ittd_heat_cell *buf, size_t cap, size_t *out_count,
                                    int *out_truncated, const ittd_progress *progress);
    int (*heat_window_slice_position)(ittd_backend *b, uint32_t slices, uint32_t slice,
                                      ittd_position_range when, ittd_position *out);

    /* ---- the replay environment ---------------------------------------- */

    /* What a replay of this recording needs (ittd_replay_env). Optional
     * (both or neither), and only meaningful with ITTD_CAP_FORK or replay
     * scans; without them the core accepts any folder holding hives. */
    int (*replay_env)(ittd_backend *b, ittd_replay_env *out);
    /* Whether 'dir' holds the registry hives this recording was made with:
     * ITTD_OK when it does, ITTD_REGISTRY_UNVERIFIED when it holds hives and
     * the recording does not say which, ITTD_E_NO_REGISTRY when it holds
     * none, ITTD_E_REGISTRY_MISMATCH when they are others (ittd_last_error
     * says so in words). Reads every hive, so it takes a moment. */
    int (*check_registry)(ittd_backend *b, const char *dir);

    /* ---- memory at many positions -------------------------------------- */

    /* Each of 'reads' as cursor_read_memory would answer it at its position:
     * the bytes into buf[offset, offset + size) and one ITTD_KNOWN_* a byte
     * into known[] at the same offsets. The reads may come in any order and
     * share positions. A batch because a backend whose seeks are dear can
     * spread the positions over several cursors at once. Optional: without
     * it the core seeks a cursor to each position. */
    int (*read_memory_at)(ittd_backend *b, const ittd_mem_read *reads, size_t count,
                          uint8_t *buf, uint8_t *known, const ittd_progress *progress);

    /* ---- reading at many positions, as the reader goes ------------------- */

    /* Visit at[0..count), each with memory readable there, for reads that
     * depend on what was read (a pointer followed to a structure followed to
     * a string), which read_memory_at would need a round each for. For each
     * i, in no particular order and possibly from several threads at once:
     * fn(ud, i, 0, read, read_ctx) with the backend positioned at at[i];
     * then, when 'after' is given and after[i] is a position, fn(ud, i, 1,
     * read, read_ctx) at after[i] (the same cursor, moved on: cheap when
     * near). read(read_ctx, addr, buf, size) fills buf as cursor_read_memory
     * would and returns how many leading bytes are known (a placeholder
     * counts); it is valid only during that call of fn. fn must not call the
     * backend. Optional: a backend whose seeks are cheap, or that has no
     * cursor to spare per thread, leaves it NULL and the core uses
     * read_memory_at in rounds. ITTD_E_CANCELLED when 'progress' asked. */
    int (*visit_positions)(ittd_backend *b, const ittd_position *at, const ittd_position *after,
                           size_t count, ittd_visit_fn fn, void *ud, const ittd_progress *progress);
} ittd_backend_api;

/* query_register_change: xmm registers follow the general-purpose ones. */
#define ITTD_ORIGIN_XMM0 32u


/* ------------------------------------------------------------ entry point */

/*
 * The one symbol a backend module exports.
 *
 *   const ittd_backend_api *ida_ttd_backend(uint32_t abi_version);
 *
 * Returns a static table, or NULL when the backend cannot speak 'abi_version';
 * the core then names the mismatch instead of calling through a table it does
 * not understand.
 */
#define ITTD_ENTRY_POINT_NAME "ida_ttd_backend"

typedef const ittd_backend_api *(*ittd_entry_point)(uint32_t abi_version);

#ifdef __cplusplus
}       /* extern "C" */
#endif

#endif  /* IDA_TTD_BACKEND_H */
