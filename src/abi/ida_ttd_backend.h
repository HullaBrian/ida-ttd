/*
 * ida-ttd backend ABI
 *
 * The boundary between the ida-ttd core plugin and a backend module that knows
 * how to read one kind of recording. A backend is a separate DLL: the core
 * loads it, asks it whether it handles a file, and then talks to it only
 * through the function table below.
 *
 * ---------------------------------------------------------------------------
 * This file is placed in the public domain (CC0-1.0), separately from the rest
 * of ida-ttd, which is Apache-2.0. A backend has to include it in order to
 * exist, and the licence of the interface must not constrain the licence of an
 * implementation. See docs/modular-backends.md.
 * ---------------------------------------------------------------------------
 *
 * Why C, and why so plain:
 *
 *  - A backend may be built by a different toolchain than the core. Across a
 *    DLL boundary that rules out std:: types, exceptions, RTTI and anything
 *    that depends on a shared CRT. Nothing here is C++.
 *  - Nothing here comes from the IDA SDK. A backend never links the IDA SDK,
 *    never sees an ea_t, a qstring or a regval_t, and never calls into IDA.
 *    That keeps every IDA dependency in the core, and it is what lets a
 *    backend be licensed independently of both ida-ttd and the IDA SDK.
 *  - Bulk results are written into caller-provided arrays of fixed-layout
 *    structs, so there is no allocator shared across the boundary and no
 *    marshalling on the hot paths.
 *
 * Conventions:
 *
 *  - Every call returns ITTD_OK or a negative ITTD_E* code. On error,
 *    ittd_last_error() gives a human-readable reason for that handle.
 *  - A backend must not let an exception escape any entry point.
 *  - Addresses are guest virtual addresses as uint64_t. ITTD_BADADDR is the
 *    "no address" value.
 *  - A "count query" is called twice: once with buf == NULL to learn the
 *    count, once with an array that large. A backend must give the same answer
 *    both times for an unchanged recording. If the caller's array is smaller
 *    than the count, the backend fills what fits, writes the full count to
 *    *out_count, and returns ITTD_OK -- the caller can tell it was short.
 *  - Strings are inline, NUL-terminated, fixed-size char arrays in UTF-8.
 *    Fixed sizes rather than pointers so a result array is one memcpy and the
 *    caller owns all of the memory.
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
 * version it was built against to the entry point; a backend returns NULL if
 * it cannot speak that version, and the core then says so by name rather than
 * crashing on a mismatched table.
 */
#define ITTD_ABI_VERSION 1u

#define ITTD_BADADDR 0xFFFFFFFFFFFFFFFFull

/* ------------------------------------------------------------- status codes */

#define ITTD_OK                0
#define ITTD_E_UNSUPPORTED    -1   /* the backend does not implement this */
#define ITTD_E_NOT_OPEN       -2   /* no recording is open on this handle */
#define ITTD_E_BAD_ARG        -3
#define ITTD_E_OPEN_FAILED    -4   /* the file is not a recording we can read */
#define ITTD_E_NO_POSITION    -5   /* the position is not in this recording */
#define ITTD_E_CANCELLED      -6   /* the caller's progress sink said to stop */
#define ITTD_E_FAILED        -100  /* anything else; see ittd_last_error */

/* ----------------------------------------------------------------- position */

/*
 * A point in a recording, as the backend means it.
 *
 * Two 64-bit words and no interpretation by the core: Microsoft TTD numbers a
 * position (sequence, steps) and Sogen's is a single instruction counter.
 * Ordering is lexicographic on (hi, lo) and must be the recording's own
 * chronology, which both of those satisfy.
 *
 * Three values are reserved as sentinels, chosen outside the range of any real
 * position. A backend translates them to whatever its engine uses; it must not
 * assume the bit patterns mean anything there.
 *
 *   NONE  = { UINT64_MAX, UINT64_MAX }      "no position"
 *   BEGIN = { 0, 0 }                        "the start of the recording"
 *   END   = { UINT64_MAX, UINT64_MAX - 1 }  "the end of the recording"
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

/* Capability bits. The core checks these before offering a command, so an
 * action is never registered that would only apologise for not working. */
#define ITTD_CAP_ACCESS_QUERIES   0x0001u  /* accesses to a range can be listed */
#define ITTD_CAP_CALL_QUERIES     0x0002u  /* calls and returns can be listed */
#define ITTD_CAP_MAPPING_CHANGES  0x0004u  /* the recording says where memory was mapped */
#define ITTD_CAP_SYSCALLS         0x0008u  /* dispatched syscalls are recorded */
#define ITTD_CAP_RECORDED_EXPORTS 0x0010u  /* module exports come out of the recording */
#define ITTD_CAP_CHEAP_SEEK       0x0020u  /* seeking is cheap enough to do per listing row */
#define ITTD_CAP_REVERSE_STEP     0x0040u  /* the recording can be stepped backwards */
#define ITTD_CAP_PREPARE          0x0080u  /* prepare() has something to do */

#define ITTD_NAME_MAX  256
#define ITTD_PATH_MAX  520

typedef struct ittd_trace_info
{
    uint32_t      is64;             /* bitness of the recorded program, not the host */
    uint32_t      capabilities;     /* ITTD_CAP_* */
    /* Identity of this recording. Stable across opens of the same file, and
     * different for a re-recording of the same program. The core writes it into
     * the database so results cached against one recording are not shown
     * against another. Zero means "the backend cannot tell", and the core then
     * caches nothing that would be wrong if the recording changed. */
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
    char          name[ITTD_NAME_MAX];   /* base name, as recorded */
    char          path[ITTD_PATH_MAX];   /* full path on the recording machine */
} ittd_module;

typedef struct ittd_thread
{
    uint32_t      tid;
    uint32_t      reserved;
    ittd_position created;
    ittd_position exited;           /* NONE if it was alive at the end */
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

typedef struct ittd_call
{
    ittd_position pos;              /* the call */
    ittd_position ret_pos;          /* the matching return; NONE if unseen */
    uint64_t      site;             /* the call instruction */
    uint64_t      target;           /* where it actually went */
    uint32_t      tid;
    uint32_t      reserved;
} ittd_call;

/* One indirect call site and one target it reached. A site that reached
 * several targets appears once per target; the core groups them. */
typedef struct ittd_call_target
{
    uint64_t site;
    uint64_t target;
    uint64_t hits;                  /* times this site reached this target */
} ittd_call_target;

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

#define ITTD_MAP_F_EXACT          0x1u  /* base/size are the kernel's own answer */
#define ITTD_MAP_F_OTHER_PROCESS  0x2u  /* the call targeted another process */
#define ITTD_MAP_F_IN_MODULE      0x4u  /* the range lies inside a loaded module */

#define ITTD_CHAIN_MAX 8

typedef struct ittd_mapping_change
{
    ittd_position pos;              /* where the change took effect */
    ittd_position call_pos;         /* where it was asked for; NONE if unknown */
    uint64_t      base;
    uint64_t      size;             /* 0 on a whole-region release */
    uint64_t      api;              /* the routine that was called; BADADDR if unknown */
    /* The call chain that led here, innermost first: one frame per module
     * boundary crossed, so a heap allocation twenty frames deep inside the
     * allocator still reaches the code that wanted the memory. */
    uint64_t      chain[ITTD_CHAIN_MAX];
    uint32_t      chain_n;
    uint32_t      kind;             /* ITTD_MAP_* */
    uint32_t      protect;          /* PAGE_* on Windows, or the free type */
    uint32_t      flags;            /* ITTD_MAP_F_* */
    uint32_t      tid;
    uint32_t      reserved;
} ittd_mapping_change;

/* --------------------------------------------------------------- registers */

/*
 * A canonical x86-64 register set.
 *
 * The core maps this onto IDA's register array. An earlier draft had the
 * backend fill IDA's regval_t directly, which is simpler but only works
 * in-process -- a backend DLL must not see IDA types at all. Both engines have
 * something close to this already (Microsoft's CROSS_PLATFORM_CONTEXT, Sogen's
 * save_registers blob), so neither pays much to produce it.
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

/* ------------------------------------------------------- progress and stop */

/*
 * How a long query reports in and asks whether to stop. The core implements it
 * with a wait box on IDA's main thread.
 *
 * A backend may call these from any thread, but must not assume they are
 * cheap, and must not call them from inside a lock it also needs to make
 * progress. A query that answers from an index in microseconds ignores the
 * sink entirely; passing a null sink is allowed and means "no progress, never
 * cancelled".
 */
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
 * Any function pointer may be NULL, which means the same as returning
 * ITTD_E_UNSUPPORTED -- the core checks before calling, so a backend only
 * fills in what it does.
 */
typedef struct ittd_backend_api
{
    uint32_t    abi_version;        /* must equal the version asked for */
    uint32_t    reserved;

    /* ---- identity, before anything is open ---------------------------- */

    /* Short id, used in the database and in build switches: "msttd", "sogen".
     * It is written into the trace-link record, so changing one orphans
     * existing databases. */
    const char *(*id)(void);
    const char *(*display_name)(void);
    /* The File > Open filter fragment, e.g. "Microsoft TTD trace (*.run)". */
    const char *(*file_filter)(void);
    /* Non-zero if this backend handles 'path'. Asked of every loaded backend
     * in load order. Must be cheap: a signature read at most, and never a full
     * open. */
    int         (*can_open)(const char *path);

    /* ---- the session -------------------------------------------------- */

    /* NULL on failure, with the reason in ittd_last_error on the module. */
    ittd_backend *(*open)(const char *path);
    void          (*close)(ittd_backend *b);
    /* Valid for the backend handle, or for the module when b is NULL. Owned by
     * the backend and valid until the next call on the same handle. */
    const char   *(*last_error)(ittd_backend *b);
    int           (*info)(ittd_backend *b, ittd_trace_info *out);

    /* Work the backend wants done once per recording before its seeks become
     * fast: building Microsoft's memory index, filling Sogen's keyframes.
     * Offered by the core when a session starts, and declinable. Only called
     * when ITTD_CAP_PREPARE is set. */
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
     * 'known' is a byte per requested byte: non-zero where the recording can
     * account for that byte. The rest are left untouched -- the core fills them
     * from the module's on-disk image where there is one, which is the same job
     * for every backend and so is not a backend's.
     *
     * *out_known receives the number of bytes marked known.
     */
    int (*cursor_read_memory)(ittd_cursor *c, uint64_t ea, void *buf, uint8_t *known,
                              size_t size, size_t *out_known);

    /* The threads alive at this position. A count query. */
    int (*cursor_threads)(ittd_cursor *c, ittd_thread *buf, size_t cap, size_t *out_count);

    /* ---- navigation --------------------------------------------------- */

    /*
     * Stepping is a strategy, not a primitive. "Step over backwards" to a
     * replay engine is rewind, notice we landed in a callee that had just
     * returned, rewind out of it; to an indexed trace it is a read of the
     * previous execute event at this frame's depth. So the whole family is the
     * backend's, because each has a cheap route the other does not.
     *
     * Each moves 'c' and writes an ITTD_STOP_* value to *out_stop. 'forward' is
     * non-zero for forwards. Breakpoints set through nav_breakpoints are
     * honoured by all of them.
     */
    int (*nav_step)(ittd_cursor *c, int forward, int *out_stop);
    int (*nav_step_over)(ittd_cursor *c, int forward, int *out_stop);
    int (*nav_step_out)(ittd_cursor *c, int forward, int *out_stop);
    int (*nav_run)(ittd_cursor *c, int forward, int *out_stop);
    int (*nav_run_to)(ittd_cursor *c, uint64_t addr, int forward, int *out_stop);

    /* Execute breakpoints as the whole set rather than one at a time: both
     * engines key them by address, and replacing the set is cheaper and harder
     * to get wrong than reconciling adds against deletes. */
    int (*nav_breakpoints)(ittd_cursor *c, const uint64_t *addrs, size_t count);

    /* ---- enumeration -------------------------------------------------- */

    int (*modules)(ittd_backend *b, ittd_module *buf, size_t cap, size_t *out_count);
    int (*threads)(ittd_backend *b, ittd_thread *buf, size_t cap, size_t *out_count);
    int (*timeline)(ittd_backend *b, ittd_trace_event *buf, size_t cap, size_t *out_count);

    /* ---- whole-trace queries ------------------------------------------ */

    /*
     * Each of these may take minutes on one backend and microseconds on
     * another -- Microsoft answers them by replaying the recording with a
     * watchpoint armed, Sogen by reading a page index. That is the whole
     * reason this ABI asks questions instead of offering watchpoints and a
     * replay loop.
     *
     * All are count queries, all take an optional progress sink, and all set
     * *out_truncated when a cap or a cancellation means the answer is a prefix
     * of the truth.
     */
    int (*query_accesses)(ittd_backend *b, uint64_t lo, uint64_t hi, uint32_t kinds,
                          ittd_position_range when,
                          ittd_access *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress);

    /* The distinct addresses inside 'ranges' that the recording executed.
     * Separate from query_accesses because coverage wants a set of addresses,
     * not millions of individual events, and both backends have a much cheaper
     * way to produce one. */
    int (*query_executed)(ittd_backend *b, const ittd_range *ranges, size_t nranges,
                          uint64_t *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress);

    /* Every call, within 'when', to one of 'targets' (ntargets == 0 means
     * every call). */
    int (*query_calls)(ittd_backend *b, const uint64_t *targets, size_t ntargets,
                       ittd_position_range when,
                       ittd_call *buf, size_t cap, size_t *out_count,
                       int *out_truncated, const ittd_progress *progress);

    /* Where every indirect call made from inside 'ranges' actually went.
     * Separate from query_calls because the question is about call sites and
     * the answer is grouped by site, not by invocation. */
    int (*query_indirect)(ittd_backend *b, const ittd_range *ranges, size_t nranges,
                          ittd_call_target *buf, size_t cap, size_t *out_count,
                          int *out_truncated, const ittd_progress *progress);

    /* Every mapping, protection change and unmapping. A backend with
     * ITTD_CAP_MAPPING_CHANGES reads them out of the recording; one without
     * reconstructs them, which is expensive and wants the progress sink. */
    int (*query_mapping_changes)(ittd_backend *b,
                                 ittd_mapping_change *buf, size_t cap, size_t *out_count,
                                 int *out_truncated, const ittd_progress *progress);

    /* ---- symbols ------------------------------------------------------ */

    /*
     * Named addresses the recording itself knows about, and function bounds.
     *
     * Microsoft TTD records neither and parses the module's export directory
     * and .pdata out of guest memory to produce them; Sogen stores every
     * module's export directory in the trace. Either way the core gets a list
     * and applies IDA names, so only one of the two ever deals with PE parsing.
     */
    int (*module_symbols)(ittd_backend *b, uint64_t base,
                          ittd_symbol *buf, size_t cap, size_t *out_count);
    int (*module_functions)(ittd_backend *b, uint64_t base,
                            ittd_range *buf, size_t cap, size_t *out_count);
} ittd_backend_api;

/* ------------------------------------------------------------ entry point */

/*
 * The one symbol a backend module exports.
 *
 *   const ittd_backend_api *ida_ttd_backend(uint32_t abi_version);
 *
 * Returns a static table, or NULL when 'abi_version' is one the backend cannot
 * speak -- the core then reports the mismatch by name instead of calling
 * through a table it does not understand.
 */
#define ITTD_ENTRY_POINT_NAME "ida_ttd_backend"

typedef const ittd_backend_api *(*ittd_entry_point)(uint32_t abi_version);

#ifdef __cplusplus
}       /* extern "C" */
#endif

#endif  /* IDA_TTD_BACKEND_H */
