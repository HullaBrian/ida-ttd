/*
 * ittd-probe: load an ida-ttd backend DLL and exercise it against a recording,
 * with no IDA involved.
 *
 *   ittd-probe BACKEND.dll TRACE [EXPORT]
 *
 * Prints what the backend reports and checks the ABI's promises about
 * positions, where a wrong answer is silent in the UI (a register view one
 * instruction off):
 *
 *   - at an access's position, the program counter is the instruction that did
 *     it;
 *   - at a call's pos the PC is the call site, at entry_pos the target, and at
 *     ret_pos it is back in the caller just past the site;
 *   - a forward step moves the position by one.
 *
 * EXPORT (default RtlAllocateHeap) is the function whose calls are listed.
 *
 * Written in C on purpose, to check that abi/ida_ttd_backend.h is plain C.
 */

#include <abi/ida_ttd_backend.h>

#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const ittd_backend_api *api;
static ittd_backend *B;

/* Whether the table has entry 'f' and fills it, as the core checks: an entry
 * past the backend's 'size' is not there, whatever the memory beyond holds. */
#define HAS(f) (offsetof(ittd_backend_api, f) + sizeof(api->f) <= api->size && api->f != NULL)
static int failures;
/* The capacity each count-then-fill below was given (clamp_count). */
static size_t n_cap, m_cap, nn_cap, wn_cap;

static double now_ms(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER t;
    if ( freq.QuadPart == 0 )
        QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)freq.QuadPart;
}

static void check(int ok, const char *what)
{
    printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if ( !ok )
        failures++;
}

static const char *pos_text(ittd_position p)
{
    static char buf[4][64];
    static int k;
    char *b = buf[k++ & 3];
    if ( api->format_position != NULL )
        api->format_position(B, p, b, sizeof(buf[0]));
    else
        snprintf(b, sizeof(buf[0]), "%llx:%llx", (unsigned long long)p.hi, (unsigned long long)p.lo);
    return b;
}

static int is_none(ittd_position p) { return p.hi == UINT64_MAX && p.lo == UINT64_MAX; }

/* The position num/den of the way from a to b. Interpolating 'lo' alone is
   only right when both share 'hi' (Sogen: hi is 0); on a Microsoft recording
   hi is the sequence and lo the steps within it, so a position taken from
   one end's hi and an interpolated lo is not in the middle, and can wrap.
   Interpolates the sequence then, at its first step. */
static ittd_position pos_between(ittd_position a, ittd_position b, uint64_t num, uint64_t den)
{
    ittd_position p = a;
    if ( den == 0 || b.hi < a.hi || (b.hi == a.hi && b.lo <= a.lo) )
        return a;
    if ( b.hi == a.hi )
    {
        p.lo = a.lo + (b.lo - a.lo) / den * num;
        return p;
    }
    p.hi = a.hi + (uint64_t)((double)(b.hi - a.hi) * (double)num / (double)den);
    p.lo = p.hi == a.hi ? a.lo : 0;
    if ( p.hi == b.hi && p.lo > b.lo )
        p.lo = b.lo;
    return p;
}

/* About 'delta' instructions after p, through position_add when the backend
   has it; otherwise p itself. */
static ittd_position pos_plus(ittd_position p, int64_t delta)
{
    ittd_position out = p;
    if ( offsetof(ittd_backend_api, position_add) + sizeof(api->position_add) <= api->size
      && api->position_add != NULL && api->position_add(B, p, delta, &out) == ITTD_OK )
        return out;
    return p;
}

/* A count-then-fill answer must not report more entries than the buffer
   given holds (query_all clamps the same way): loops over the answer would
   read past it. Clamps, and fails a check when it had to. Always 1, so it
   can sit in a condition. */
static int clamp_count(size_t *n, size_t cap)
{
    if ( *n > cap )
    {
        check(0, "a fill reports no more entries than the buffer it was given holds");
        *n = cap;
    }
    return 1;
}

static uint64_t rip_at(ittd_cursor *c, ittd_position p)
{
    ittd_regs r;
    static int reported;
    if ( api->cursor_seek(c, p) != ITTD_OK || api->cursor_regs(c, &r) != ITTD_OK
      || (r.have & ITTD_REGS_GP) == 0 )
    {
        if ( !reported++ )
            printf("    (no registers at %s: %s)\n", pos_text(p), api->last_error(B));
        return ITTD_BADADDR;
    }
    return r.gp[ITTD_REG_RIP];
}

/* Count-then-fill into a fresh array of 'size'-byte elements. */
static void *query_all(int (*count_fill)(void *buf, size_t cap, size_t *n), size_t size, size_t *n)
{
    void *buf;
    size_t cap;
    *n = 0;
    if ( count_fill(NULL, 0, n) != ITTD_OK )
    {
        *n = 0;         /* callers loop over *n even when the result is NULL */
        return NULL;
    }
    cap = *n;
    buf = calloc(cap ? cap : 1, size);
    if ( buf == NULL || count_fill(buf, cap, n) != ITTD_OK )
    {
        free(buf);
        *n = 0;
        return NULL;
    }
    /* A count that grew between the calls filled only what fit. */
    if ( *n > cap )
        *n = cap;
    return buf;
}

static int f_modules(void *b, size_t cap, size_t *n) { return api->modules(B, (ittd_module *)b, cap, n); }
static int f_threads(void *b, size_t cap, size_t *n) { return api->threads(B, (ittd_thread *)b, cap, n); }
static int f_timeline(void *b, size_t cap, size_t *n) { return api->timeline(B, (ittd_trace_event *)b, cap, n); }

static uint64_t g_symbase;
static int f_symbols(void *b, size_t cap, size_t *n) { return api->module_symbols(B, g_symbase, (ittd_symbol *)b, cap, n); }

int main(int argc, char **argv)
{
    const char *want = argc > 3 ? argv[3] : "RtlAllocateHeap";
    HMODULE dll;
    ittd_entry_point entry;
    ittd_trace_info info;
    ittd_module *mods;
    ittd_thread *thr;
    ittd_trace_event *tl;
    ittd_cursor *c;
    size_t nmods = 0, nthr = 0, ntl = 0, i;
    uint64_t target = ITTD_BADADDR;
    double t0;

    if ( argc < 3 )
    {
        fprintf(stderr, "usage: ittd-probe BACKEND.dll TRACE [EXPORT]\n");
        return 2;
    }

    dll = LoadLibraryA(argv[1]);
    if ( dll == NULL )
    {
        fprintf(stderr, "could not load %s (error %lu)\n", argv[1], GetLastError());
        return 1;
    }
    entry = (ittd_entry_point)GetProcAddress(dll, ITTD_ENTRY_POINT_NAME);
    api = entry != NULL ? entry(ITTD_ABI_VERSION) : NULL;
    if ( api == NULL )
    {
        fprintf(stderr, "%s does not speak ABI version %u\n", argv[1], ITTD_ABI_VERSION);
        return 1;
    }
    printf("backend: %s (%s), filter \"%s\"\n", api->id(), api->display_name(), api->file_filter());
    printf("can_open: %d\n", api->can_open(argv[2]));

    t0 = now_ms();
    B = api->open(argv[2]);
    if ( B == NULL )
    {
        fprintf(stderr, "open failed: %s\n", api->last_error(NULL));
        return 1;
    }
    printf("open: %.1f ms\n", now_ms() - t0);

    api->info(B, &info);
    printf("info: %s, %s, %d-bit, positions %s..%s, fingerprint %016llx, caps 0x%x\n",
           info.backend_name, info.main_module, info.is64 ? 64 : 32,
           pos_text(info.first), pos_text(info.last),
           (unsigned long long)info.fingerprint, info.capabilities);

    /* ---- modules, threads, timeline ---------------------------------- */
    mods = (ittd_module *)query_all(f_modules, sizeof(ittd_module), &nmods);
    printf("modules: %zu\n", nmods);
    for ( i = 0; i < nmods && i < 8; i++ )
        printf("  %016llx %8llx machine %04x  %s\n", (unsigned long long)mods[i].base,
               (unsigned long long)mods[i].size, mods[i].machine, mods[i].name);

    thr = (ittd_thread *)query_all(f_threads, sizeof(ittd_thread), &nthr);
    printf("threads: %zu\n", nthr);
    for ( i = 0; i < nthr && i < 6; i++ )
        printf("  tid %u  %s..%s  teb %llx  stack %llx..%llx  %s\n", thr[i].tid,
               pos_text(thr[i].created), pos_text(thr[i].exited),
               (unsigned long long)thr[i].teb, (unsigned long long)thr[i].stack_limit,
               (unsigned long long)thr[i].stack_base, thr[i].name);

    t0 = now_ms();
    tl = (ittd_trace_event *)query_all(f_timeline, sizeof(ittd_trace_event), &ntl);
    printf("timeline: %zu event(s) in %.1f ms\n", ntl, now_ms() - t0);
    for ( i = 0; i < ntl && i < 5; i++ )
        printf("  %s  %s\n", pos_text(tl[i].pos), tl[i].text);

    /* ---- the export whose calls are listed ------------------------------ */
    /* Or an address, for a backend that records no exports (Microsoft TTD). */
    if ( want[0] == '0' && (want[1] == 'x' || want[1] == 'X') )
    {
        target = strtoull(want + 2, NULL, 16);
        printf("calls to the function at %llx\n", (unsigned long long)target);
    }
    for ( i = 0; i < nmods && target == ITTD_BADADDR; i++ )
    {
        size_t ns = 0, k;
        ittd_symbol *syms;
        g_symbase = mods[i].base;
        syms = (ittd_symbol *)query_all(f_symbols, sizeof(ittd_symbol), &ns);
        for ( k = 0; syms != NULL && k < ns; k++ )
            if ( strcmp(syms[k].name, want) == 0 )
            {
                target = syms[k].ea;
                printf("export %s!%s at %llx (%zu exports in the module)\n",
                       mods[i].name, want, (unsigned long long)target, ns);
                break;
            }
        free(syms);
    }

    c = api->cursor_open(B);
    if ( c == NULL )
    {
        fprintf(stderr, "cursor_open failed: %s\n", api->last_error(B));
        return 1;
    }

    /* ---- positions and registers ------------------------------------------ */
    printf("\npositions\n");
    {
        ittd_position mid = pos_between(info.first, info.last, 1, 2), here;
        ittd_regs r;
        uint32_t tid = 0;
        int stop = -1;
        uint8_t bytes[16], known[16];
        size_t nk = 0;

        check(api->cursor_seek(c, mid) == ITTD_OK, "seek to the middle");
        /* The middle may be a sequence's first step (Microsoft: a key frame,
           where the next instruction can be in another sequence): the checks
           below start a few instructions on, where a step is one position. */
        api->nav_step(c, 4, &stop);
        api->cursor_position(c, &mid);
        stop = -1;
        t0 = now_ms();
        check(api->cursor_seek(c, mid) == ITTD_OK, "seek to a position near the middle");
        memset(&r, 0, sizeof(r));
        if ( api->cursor_regs(c, &r) != ITTD_OK )
            printf("  registers: %s\n", api->last_error(B));
        check((r.have & ITTD_REGS_GP) != 0, "registers there");
        printf("  regs at %s: %.1f ms, rip %llx rsp %llx\n", pos_text(mid), now_ms() - t0,
               (unsigned long long)r.gp[ITTD_REG_RIP], (unsigned long long)r.gp[ITTD_REG_RSP]);
        api->cursor_thread(c, &tid);
        printf("  thread %u\n", tid);

        t0 = now_ms();
        memset(bytes, 0, sizeof(bytes));
        memset(known, 0, sizeof(known));    /* printed below even if the read fails */
        api->cursor_read_memory(c, r.gp[ITTD_REG_RIP], bytes, known, sizeof(bytes), &nk);
        printf("  16 bytes at rip, %zu known, %.1f ms:", nk, now_ms() - t0);
        for ( i = 0; i < 16; i++ )
            printf(known[i] ? " %02x" : " ??", bytes[i]);
        printf("\n");
        check(nk > 0, "the instruction at rip is readable");

        /* The access at this position must be done by the instruction at rip. */
        {
            ittd_access acc[8];
            size_t n = 0;
            int trunc = 0;
            ittd_position_range when;
            when.first = mid;
            when.last  = mid;
            /* the position just before an instruction runs, to the one after it */
            when.last.lo = mid.lo + 1;
            api->query_accesses(B, r.gp[ITTD_REG_RIP], r.gp[ITTD_REG_RIP] + 1, ITTD_ACCESS_EXEC,
                                when, acc, 8, &n, &trunc, NULL);
            check(n >= 1 && acc[0].pc == r.gp[ITTD_REG_RIP] && acc[0].pos.lo == mid.lo,
                  "the execute event of the instruction at rip is at this position");
        }

        /* The instruction stream from here starts with the instruction at rip. */
        if ( HAS(query_instructions) )
        {
            ittd_access ins[16];
            ittd_position_range w;
            size_t n = 0;
            int trunc = 0;
            uint32_t tid2 = 0;
            w.first = mid;
            w.last.hi = UINT64_MAX;
            w.last.lo = UINT64_MAX - 1;
            api->cursor_thread(c, &tid2);
            t0 = now_ms();
            api->query_instructions(B, w, tid2, ins, 16, &n, &trunc, NULL);
            printf("  16 instructions from here on thread %u: %zu, %.1f ms\n", tid2, n, now_ms() - t0);
            check(n == 16 && trunc && ins[0].pc == r.gp[ITTD_REG_RIP] && ins[0].pos.lo == mid.lo,
                  "the instruction stream starts here, with the instruction at rip");
        }

        api->nav_step(c, 1, &stop);
        api->cursor_position(c, &here);
        printf("  a step from %s", pos_text(mid));
        printf(" lands at %s (stop %d)\n", pos_text(here), stop);
        check(here.hi == mid.hi && here.lo == mid.lo + 1 && stop == ITTD_STOP_STEPPED,
              "a forward step moves one position");
        api->nav_step(c, 0, &stop);
        api->cursor_position(c, &here);
        check(here.lo == mid.lo, "and a backward step moves back");

        /* An execute breakpoint on the instruction a step starts from: the
           step still executes it. IDA sets one there itself when stepping
           from pseudocode; stopping in place read as a breakpoint hit, and
           IDA's statement stepping then ran on to the end of the recording. */
        if ( api->nav_breakpoints != NULL )
        {
            ittd_breakpoint bp;
            memset(&bp, 0, sizeof(bp));
            bp.addr  = r.gp[ITTD_REG_RIP];
            bp.size  = 1;
            bp.kinds = ITTD_ACCESS_EXEC;
            api->nav_breakpoints(c, &bp, 1);
            stop = -1;
            api->nav_step(c, 1, &stop);
            api->cursor_position(c, &here);
            api->nav_breakpoints(c, NULL, 0);
            printf("  step from an execute breakpoint on rip: stop %d at %s\n", stop, pos_text(here));
            check(here.lo == mid.lo + 1 && stop == ITTD_STOP_STEPPED,
                  "a step from an instruction with a breakpoint on it moves one position");
            api->cursor_seek(c, mid);
        }

        /* run to the instruction at rip again, from just past it */
        api->nav_step(c, 1, &stop);
        t0 = now_ms();
        api->nav_run_to(c, r.gp[ITTD_REG_RIP], 0, &stop);
        api->cursor_position(c, &here);
        printf("  run back to rip: stop %d at %s, %.1f ms\n", stop, pos_text(here), now_ms() - t0);
        check(here.lo == mid.lo && stop == ITTD_STOP_STEPPED, "running backward to rip lands on this position");

        /* What tracing a register's origin costs: single steps backward, which
           must stay on one thread. ITTD_PROBE_BACKSTEPS=N. */
        if ( getenv("ITTD_PROBE_BACKSTEPS") != NULL )
        {
            unsigned long steps = strtoul(getenv("ITTD_PROBE_BACKSTEPS"), NULL, 0), k, changed = 0;
            uint32_t tid0 = 0, tidk = 0;
            int same_thread = 1;
            ittd_regs prev = r, now_regs;
            api->cursor_thread(c, &tid0);
            t0 = now_ms();
            for ( k = 0; k < steps; k++ )
            {
                if ( api->nav_step(c, 0, &stop) != ITTD_OK || stop != ITTD_STOP_STEPPED )
                    break;
                api->cursor_thread(c, &tidk);
                same_thread &= tidk == tid0;
                api->cursor_regs(c, &now_regs);
                changed += now_regs.gp[ITTD_REG_RAX] != prev.gp[ITTD_REG_RAX];
                prev = now_regs;
            }
            printf("  %lu backward steps: %.3f ms each, rax changed %lu times\n",
                   k, k ? (now_ms() - t0) / (double)k : 0.0, changed);
            check(same_thread, "backward single steps stay on the thread");
            api->cursor_seek(c, mid);

            /* query_register_change against stepping back: the first step
               back where the register differs is the instruction that set it. */
            if ( offsetof(ittd_backend_api, query_register_change) + sizeof(api->query_register_change) <= api->size
              && api->query_register_change != NULL )
            {
                static const uint32_t regs[] = { ITTD_REG_RAX, ITTD_REG_RBX, ITTD_REG_RSI, ITTD_ORIGIN_XMM0 };
                size_t q;
                for ( q = 0; q < sizeof(regs) / sizeof(regs[0]); q++ )
                {
                    ittd_position got, first_change;
                    int found = 0, rc;
                    unsigned long s;
                    const uint32_t reg = regs[q];
                    const int xmm = reg >= ITTD_ORIGIN_XMM0;
                    t0 = now_ms();
                    rc = api->query_register_change(B, mid, tid0, reg, 1000000, &got, &found, NULL);
                    printf("  last change of register %u: rc %d, found %d at %s, %.1f ms\n",
                           reg, rc, found, found ? pos_text(got) : "-", now_ms() - t0);
                    first_change.hi = first_change.lo = UINT64_MAX;
                    api->cursor_seek(c, mid);
                    for ( s = 0; s < steps; s++ )
                    {
                        if ( api->nav_step(c, 0, &stop) != ITTD_OK || stop != ITTD_STOP_STEPPED )
                            break;
                        api->cursor_regs(c, &now_regs);
                        if ( xmm ? memcmp(now_regs.xmm[0], r.xmm[0], 16) != 0
                                 : now_regs.gp[reg] != r.gp[reg] )
                        {
                            api->cursor_position(c, &first_change);
                            break;
                        }
                    }
                    api->cursor_seek(c, mid);
                    if ( first_change.hi != UINT64_MAX )
                        check(rc == ITTD_OK && found && got.hi == first_change.hi && got.lo == first_change.lo,
                              "  the register's last change is the one stepping back finds");
                    else
                        printf("  (no change within %lu steps back to compare)\n", steps);
                }
            }
        }
    }

    /* ---- calls -------------------------------------------------------------- */
    if ( target != ITTD_BADADDR )
    {
        ittd_position_range all;
        ittd_call *calls;
        size_t n = 0, with_ret = 0, k;
        int trunc = 0;
        all.first.hi = 0; all.first.lo = 0;
        all.last.hi = UINT64_MAX; all.last.lo = UINT64_MAX - 1;

        printf("\ncalls to %s\n", want);
        t0 = now_ms();
        api->query_calls(B, &target, 1, all, NULL, 0, &n, &trunc, NULL);
        n_cap = n;
        calls = (ittd_call *)calloc(n ? n : 1, sizeof(ittd_call));
        api->query_calls(B, &target, 1, all, calls, n, &n, &trunc, NULL);
        clamp_count(&n, n_cap);
        for ( k = 0; k < n; k++ )
            if ( !is_none(calls[k].ret_pos) )
                with_ret++;
        printf("  %zu call(s), %zu with a return, %.1f ms\n", n, with_ret, now_ms() - t0);

        for ( k = 0; k < n && k < 3; k++ )
        {
            ittd_call *e = &calls[k];
            uint64_t at_pos = is_none(e->pos) ? ITTD_BADADDR : rip_at(c, e->pos);
            uint64_t at_entry = rip_at(c, e->entry_pos);
            uint64_t at_ret = is_none(e->ret_pos) ? ITTD_BADADDR : rip_at(c, e->ret_pos);
            ittd_regs r;
            printf("  #%zu tid %u site %llx pos %s entry %s ret %s%s\n", k, e->tid,
                   (unsigned long long)e->site, pos_text(e->pos), pos_text(e->entry_pos),
                   pos_text(e->ret_pos), (e->flags & ITTD_CALL_F_NOT_CALL) ? " (jump)" : "");
            int is_call = (e->flags & ITTD_CALL_F_NOT_CALL) == 0;
            if ( !is_none(e->pos) )
                check(at_pos == e->site, "  rip at pos is the call site");
            check(at_entry == e->target, "  rip at entry_pos is the target");
            /* At the callee's first instruction, the frame was entered by this
               very call. */
            if ( k == 0 && !is_none(e->pos) && is_call && HAS(query_frame_entry) )
            {
                ittd_position fc;
                uint64_t fe = 0;
                int rc = api->query_frame_entry(B, e->entry_pos, e->tid, 0x10000, &fc, &fe);
                printf("    frame entry from entry_pos: rc %d, call at %s, entry %llx\n",
                       rc, pos_text(fc), (unsigned long long)fe);
                check(rc == ITTD_OK && fc.lo == e->pos.lo && fe == e->target,
                      "  the frame at entry_pos was entered by this call");
            }
            /* A write breakpoint on the slot the call pushes its return address
               into stops at the call, run forward from just before it. */
            if ( k == 0 && !is_none(e->pos) && is_call && e->pos.lo > 0 && api->nav_breakpoints != NULL )
            {
                ittd_regs rr;
                ittd_breakpoint bp;
                ittd_position before = e->pos, landed;
                int stop = -1;
                memset(&bp, 0, sizeof(bp));
                api->cursor_seek(c, e->pos);
                if ( api->cursor_regs(c, &rr) == ITTD_OK )
                {
                    bp.addr  = rr.gp[ITTD_REG_RSP] - 8;
                    bp.size  = 8;
                    bp.kinds = ITTD_ACCESS_WRITE;
                    before.lo = e->pos.lo - 1;
                    api->cursor_seek(c, before);
                    api->nav_breakpoints(c, &bp, 1);
                    api->nav_run(c, 1, &stop);
                    api->cursor_position(c, &landed);
                    api->nav_breakpoints(c, NULL, 0);
                    printf("    write breakpoint on [rsp-8, rsp): stop %d at %s\n", stop, pos_text(landed));
                    check(stop == ITTD_STOP_BREAKPOINT && landed.lo == e->pos.lo,
                          "  a write breakpoint on the return-address slot stops at the call");

                    /* And run backward into it from the callee's entry, just
                       after the write: the same stop. */
                    api->cursor_seek(c, e->entry_pos);
                    api->nav_breakpoints(c, &bp, 1);
                    stop = -1;
                    api->nav_run(c, 0, &stop);
                    api->cursor_position(c, &landed);
                    api->nav_breakpoints(c, NULL, 0);
                    printf("    ... run backward into it: stop %d at %s\n", stop, pos_text(landed));
                    check(stop == ITTD_STOP_BREAKPOINT && landed.lo == e->pos.lo && landed.hi == e->pos.hi,
                          "  running backward into the write stops at the call too");

                    /* Stopped on the write by the breakpoint, movement goes on:
                       a step completes and a run does not stop on the same
                       instruction again. */
                    {
                        ittd_position on = e->pos;
                        api->cursor_seek(c, on);
                        api->nav_breakpoints(c, &bp, 1);
                        stop = -1;
                        api->nav_step(c, 1, &stop);
                        api->cursor_position(c, &landed);
                        check(!(landed.hi == on.hi && landed.lo == on.lo),
                              "  a step from the writing instruction moves on");
                        api->cursor_seek(c, on);
                        stop = -1;
                        api->nav_run(c, 1, &stop);
                        api->cursor_position(c, &landed);
                        api->nav_breakpoints(c, NULL, 0);
                        check(!(landed.hi == on.hi && landed.lo == on.lo),
                              "  and so does a run");
                    }

                    /* From a few instructions further on, where the write is
                       not the instruction right before the start. */
                    {
                        int k2;
                        api->cursor_seek(c, e->entry_pos);
                        for ( k2 = 0; k2 < 3; k2++ )
                            api->nav_step(c, 1, &stop);
                        api->nav_breakpoints(c, &bp, 1);
                        stop = -1;
                        api->nav_run(c, 0, &stop);
                        api->cursor_position(c, &landed);
                        api->nav_breakpoints(c, NULL, 0);
                        printf("    ... from three instructions on: stop %d at %s\n", stop, pos_text(landed));
                        check(stop == ITTD_STOP_BREAKPOINT && landed.lo == e->pos.lo && landed.hi == e->pos.hi,
                              "  and from further on");
                    }
                }
            }
            if ( !is_none(e->pos) && !is_none(e->ret_pos) && is_call && HAS(nav_step_over) )
            {
                ittd_position landed;
                int stop = -1;
                api->cursor_seek(c, e->pos);
                t0 = now_ms();
                if ( api->nav_step_over(c, 1, &stop) == ITTD_OK )
                {
                    api->cursor_position(c, &landed);
                    printf("    step over the call: stop %d at %s, %.1f ms\n", stop, pos_text(landed),
                           now_ms() - t0);
                    check(landed.lo == e->ret_pos.lo, "  stepping over the call lands on ret_pos");
                }
                if ( api->nav_step_over(c, 0, &stop) == ITTD_OK )
                {
                    api->cursor_position(c, &landed);
                    printf("    step back over it: stop %d at %s\n", stop, pos_text(landed));
                    check(landed.lo == e->pos.lo, "  stepping back over the call lands on pos");
                }
            }
            if ( !is_none(e->pos) && !is_none(e->ret_pos) && !(e->flags & ITTD_CALL_F_NOT_CALL)
              && api->nav_step_out != NULL )
            {
                ittd_position landed;
                int stop = -1;
                api->cursor_seek(c, e->entry_pos);
                t0 = now_ms();
                if ( api->nav_step_out(c, 1, &stop) == ITTD_OK )
                {
                    api->cursor_position(c, &landed);
                    printf("    step out from entry_pos: stop %d at %s, %.1f ms\n", stop, pos_text(landed),
                           now_ms() - t0);
                    check(landed.lo == e->ret_pos.lo, "  stepping out of the callee lands on ret_pos");
                }
                api->cursor_seek(c, e->entry_pos);
                if ( api->nav_step_out(c, 0, &stop) == ITTD_OK )
                {
                    api->cursor_position(c, &landed);
                    printf("    step out backwards: stop %d at %s\n", stop, pos_text(landed));
                    check(landed.lo == e->pos.lo, "  stepping out backwards lands on pos");
                }
                /* IDA's own backward step over: an execute breakpoint on the
                   return address minus one (the call's last byte, not its
                   first) and a run backward from just after the return. */
                {
                    uint64_t ret_ip = rip_at(c, e->ret_pos);
                    ittd_breakpoint bp;
                    memset(&bp, 0, sizeof(bp));
                    bp.addr  = ret_ip - 1;
                    bp.size  = 1;
                    bp.kinds = ITTD_ACCESS_EXEC;
                    api->cursor_seek(c, e->ret_pos);
                    api->nav_breakpoints(c, &bp, 1);
                    stop = -1;
                    api->nav_run(c, 0, &stop);
                    api->cursor_position(c, &landed);
                    api->nav_breakpoints(c, NULL, 0);
                    printf("    run back to the call's last byte: stop %d at %s\n", stop, pos_text(landed));
                    check(stop == ITTD_STOP_BREAKPOINT && landed.lo == e->pos.lo,
                          "  an execute breakpoint inside the call stops at the call");
                }
            }
            if ( !is_none(e->ret_pos) )
            {
                at_ret = rip_at(c, e->ret_pos);
                if ( is_call )
                    check(at_ret > e->site && at_ret <= e->site + 15, "  rip at ret_pos is just past the site");
                if ( at_ret != ITTD_BADADDR && api->cursor_regs(c, &r) == ITTD_OK )
                    printf("    returned rax %llx\n", (unsigned long long)r.gp[ITTD_REG_RAX]);
            }
        }

        /* the batch form, against the cursor's answers */
        if ( HAS(regs_at) && n > 0 )
        {
            size_t m = n < 200 ? n : 200, ok = 0;
            ittd_position *ps = (ittd_position *)calloc(m, sizeof(ittd_position));
            ittd_regs *rs = (ittd_regs *)calloc(m, sizeof(ittd_regs));
            for ( k = 0; k < m; k++ )
                ps[m - 1 - k] = calls[k].entry_pos;      /* reversed on purpose */
            t0 = now_ms();
            api->regs_at(B, ps, m, rs, NULL);
            printf("  regs_at for %zu entries: %.1f ms (%.2f ms each)\n", m, now_ms() - t0,
                   (now_ms() - t0) / (double)m);
            for ( k = 0; k < m; k++ )
                if ( (rs[k].have & ITTD_REGS_GP) != 0 && rs[k].gp[ITTD_REG_RIP] == target )
                    ok++;
            check(ok == m, "  every batched entry shows rip at the target");
            free(ps);
            free(rs);
        }

        /* Every call in a window (no targets: what a call tree asks for)
           agrees with the listing by target: a call that returned is found
           in the window from its own position to its return, with the same
           entry and return. */
        for ( k = 0; k < n; k++ )
        {
            ittd_call *e = &calls[k];
            ittd_position_range win;
            ittd_call *ev;
            size_t m = 0, j;
            int found = 0;
            double t1;
            if ( is_none(e->pos) || is_none(e->ret_pos) || (e->flags & ITTD_CALL_F_NOT_CALL) != 0 )
                continue;
            /* One past the return: the ret is recognised where it lands. */
            win.first = e->pos;
            win.last  = e->ret_pos;
            if ( api->position_add != NULL )
                api->position_add(B, e->ret_pos, 1, &win.last);
            t1 = now_ms();
            if ( api->query_calls(B, NULL, 0, win, NULL, 0, &m, &trunc, NULL) != ITTD_OK )
            {
                printf("  every call in a window: %s\n", api->last_error(B));
                check(0, "  every call in a window can be listed");
                break;
            }
            m_cap = m;
            ev = (ittd_call *)calloc(m ? m : 1, sizeof(ittd_call));
            api->query_calls(B, NULL, 0, win, ev, m, &m, &trunc, NULL);
            clamp_count(&m, m_cap);
            for ( j = 0; j < m; j++ )
                if ( ev[j].pos.lo == e->pos.lo && ev[j].entry_pos.lo == e->entry_pos.lo
                  && ev[j].ret_pos.lo == e->ret_pos.lo && ev[j].target == e->target )
                    found = 1;
            printf("  every call from %s to %s: %zu, %.1f ms\n", pos_text(win.first), pos_text(win.last),
                   m, now_ms() - t1);
            if ( !found )
            {
                printf("    wanted pos %s entry %s ret %s target %llx\n", pos_text(e->pos), pos_text(e->entry_pos),
                       pos_text(e->ret_pos), (unsigned long long)e->target);
                for ( j = 0; j < m && j < 4; j++ )
                    printf("    got    pos %s entry %s ret %s target %llx site %llx\n", pos_text(ev[j].pos),
                           pos_text(ev[j].entry_pos), pos_text(ev[j].ret_pos), (unsigned long long)ev[j].target,
                           (unsigned long long)ev[j].site);
            }
            check(found, "  the window's listing has the call, with its entry and return");
            free(ev);
            break;
        }
        free(calls);
    }

    /* ---- indirect branches in the main module ------------------------------- */
    if ( nmods > 0 )
    {
        ittd_range r;
        ittd_call_target *tg;
        size_t n = 0, k, m = 0;
        int trunc = 0;
        for ( k = 0; k < nmods; k++ )
            if ( _stricmp(mods[k].name, info.main_module) == 0 )
                m = k;
        r.start = mods[m].base;
        r.end   = mods[m].base + mods[m].size;
        printf("\nindirect calls in %s\n", mods[m].name);
        t0 = now_ms();
        api->query_indirect(B, &r, 1, 0, NULL, 0, &n, &trunc, NULL);
        n_cap = n;
        tg = (ittd_call_target *)calloc(n ? n : 1, sizeof(ittd_call_target));
        api->query_indirect(B, &r, 1, 0, tg, n, &n, &trunc, NULL);
        clamp_count(&n, n_cap);
        printf("  %zu edge(s), %.1f ms\n", n, now_ms() - t0);
        for ( k = 0; k < n && k < 5; k++ )
        {
            printf("  %llx -> %llx  x%llu  first %s\n", (unsigned long long)tg[k].site,
                   (unsigned long long)tg[k].target, (unsigned long long)tg[k].hits,
                   pos_text(tg[k].first_pos));
            if ( k == 0 && !is_none(tg[k].first_pos) )
                check(rip_at(c, tg[k].first_pos) == tg[k].site, "  rip at first_pos is the site");
        }
        free(tg);
    }

    /* ---- the memory map -------------------------------------------------------- */
    if ( api->query_mapping_changes != NULL )
    {
        ittd_mapping_change *mc;
        ittd_name *names = NULL;
        size_t n = 0, nn = 0, k, at_start = 0, rwx = 0;
        int ordered = 1, files_ok = 1;
        int trunc = 0;
        printf("\nmemory map\n");
        t0 = now_ms();
        api->query_mapping_changes(B, NULL, 0, &n, &trunc, NULL);
        n_cap = n;
        mc = (ittd_mapping_change *)calloc(n ? n : 1, sizeof(ittd_mapping_change));
        api->query_mapping_changes(B, mc, n, &n, &trunc, NULL);
        clamp_count(&n, n_cap);
        printf("  %zu entr%s, %.1f ms\n", n, n == 1 ? "y" : "ies", now_ms() - t0);
        if ( api->query_mapping_files != NULL )
        {
            api->query_mapping_files(B, NULL, 0, &nn);
            nn_cap = nn;
            names = (ittd_name *)calloc(nn ? nn : 1, sizeof(ittd_name));
            api->query_mapping_files(B, names, nn, &nn);
            clamp_count(&nn, nn_cap);
        }
        for ( k = 0; k < n; k++ )
        {
            if ( mc[k].flags & ITTD_MAP_F_AT_START )
                at_start++;
            if ( k > 0 && (mc[k].pos.hi < mc[k - 1].pos.hi
                        || (mc[k].pos.hi == mc[k - 1].pos.hi && mc[k].pos.lo < mc[k - 1].pos.lo)) )
                ordered = 0;
            if ( mc[k].file > nn )
                files_ok = 0;
            if ( getenv("ITTD_PROBE_MAP_DUMP") != NULL )
            {
                uint32_t q;
                printf("  %s (asked %s) kind %u %016llx +%llx prot %#x flags %#x tid %u api %llx chain",
                       pos_text(mc[k].pos), pos_text(mc[k].call_pos), mc[k].kind,
                       (unsigned long long)mc[k].base, (unsigned long long)mc[k].size, mc[k].protect,
                       mc[k].flags, mc[k].tid, (unsigned long long)mc[k].api);
                for ( q = 0; q < mc[k].chain_n; q++ )
                    printf(" %llx", (unsigned long long)mc[k].chain[q]);
                printf("\n");
            }
            /* MEM_COMMIT, PAGE_EXECUTE_READWRITE, not an image */
            if ( mc[k].state == 0x1000 && (mc[k].protect & 0xFF) == 0x40 && mc[k].region_type != ITTD_REGION_IMAGE )
            {
                if ( rwx++ < 5 )
                {
                    uint32_t q;
                    printf("  RWX %016llx +%llx at %s (asked for at %s), type %u, api %llx, chain",
                           (unsigned long long)mc[k].base, (unsigned long long)mc[k].size,
                           pos_text(mc[k].pos), pos_text(mc[k].call_pos), mc[k].region_type,
                           (unsigned long long)mc[k].api);
                    for ( q = 0; q < mc[k].chain_n; q++ )
                        printf(" %llx", (unsigned long long)mc[k].chain[q]);
                    printf("\n");
                }
            }
        }
        printf("  %zu at the start, %zu changes, %zu file name(s), %zu RWX committed\n",
               at_start, n - at_start, nn, rwx);
        for ( k = 0; k < nn && k < 3; k++ )
            printf("  file %zu: %s\n", k + 1, names[k].name);
        if ( info.capabilities & ITTD_CAP_MAPPING_CHANGES )   /* a recorded map, not a reconstruction */
            check(at_start > 0, "  the map at the start is there");
        check(ordered, "  entries are in position order");
        check(files_ok, "  every file index names a file");
        free(mc);
        free(names);
    }

    /* ---- bytes no access shows (filled from checkpoints) ----------------------- */
    {
        ittd_position mid = info.first;
        ittd_regs r;
        uint8_t page[4096], known[4096];
        size_t nk = 0;
        mid = pos_between(info.first, info.last, 1, 2);
        api->cursor_seek(c, mid);
        if ( api->cursor_regs(c, &r) == ITTD_OK )
        {
            uint64_t sp_page = (r.gp[ITTD_REG_RSP] & ~0xFFFull) + 0x1000;
            t0 = now_ms();
            api->cursor_read_memory(c, sp_page, page, known, sizeof(page), &nk);
            printf("\nthe stack page above rsp at %s: %zu of 4096 bytes known, %.1f ms\n",
                   pos_text(mid), nk, now_ms() - t0);
        }

        /* What jumping around costs, in time and memory: a page at ten
           positions spread over the recording. */
        {
            int j;
            PROCESS_MEMORY_COUNTERS pmc;
            for ( j = 0; j < 10; j++ )
            {
                ittd_position at = info.first;
                double t1;
                at = pos_between(info.first, info.last, (uint64_t)j, 10);
                api->cursor_seek(c, at);
                if ( api->cursor_regs(c, &r) != ITTD_OK )
                    continue;
                t1 = now_ms();
                /* the stack: written all the time, so never served from a cache */
                api->cursor_read_memory(c, r.gp[ITTD_REG_RSP] & ~0xFFFull, page, known, sizeof(page), &nk);
                t1 = now_ms() - t1;
                memset(&pmc, 0, sizeof(pmc));
                GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
                printf("a page at %s: %.1f ms, working set %zu MiB\n", pos_text(at), t1,
                       (size_t)(pmc.WorkingSetSize >> 20));
            }
        }

        /* Registers then memory, at nearby positions: what reading a call's
           arguments does, call after call. */
        {
            int j;
            ittd_position at = info.first;
            for ( j = 0; j < 5; j++ )
            {
                double t1, t2;
                at = pos_plus(pos_between(info.first, info.last, 1, 2), (int64_t)j * 1000);
                api->cursor_seek(c, at);
                t1 = now_ms();
                api->cursor_regs(c, &r);
                t1 = now_ms() - t1;
                t2 = now_ms();
                api->cursor_read_memory(c, (r.gp[ITTD_REG_RSP] & ~0xFFFull) - 0x2000, page, known,
                                        sizeof(page), &nk);
                t2 = now_ms() - t2;
                printf("regs then a stack page at %s: %.1f ms, %.1f ms\n", pos_text(at), t1, t2);
            }
        }

        /* What a cursor costs in memory: ten more, each reading one page. */
        {
            int j;
            ittd_cursor *extra[10];
            PROCESS_MEMORY_COUNTERS pmc;
            for ( j = 0; j < 10; j++ )
            {
                extra[j] = api->cursor_open(B);
                if ( extra[j] != NULL && nmods > 0 )   /* mods is NULL when the list failed */
                {
                    api->cursor_seek(extra[j], info.last);
                    api->cursor_read_memory(extra[j], mods[0].base, page, known, sizeof(page), &nk);
                }
            }
            memset(&pmc, 0, sizeof(pmc));
            GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
            printf("with ten more cursors: working set %zu MiB\n", (size_t)(pmc.WorkingSetSize >> 20));
            for ( j = 0; j < 10; j++ )
                if ( extra[j] != NULL )
                    api->cursor_close(extra[j]);
        }

        /* What naming a module costs: the core reads each one's headers where
           it was mapped. The first page of every module, at its load. */
        {
            double all = 0, worst = 0;
            const char *worst_name = "";
            for ( i = 0; i < nmods; i++ )
            {
                ittd_position at = mods[i].loaded;
                double t1;
                if ( is_none(at) )
                    at = info.first;
                api->cursor_seek(c, at);
                t1 = now_ms();
                api->cursor_read_memory(c, mods[i].base, page, known, sizeof(page), &nk);
                t1 = now_ms() - t1;
                all += t1;
                if ( t1 > worst )
                {
                    worst = t1;
                    worst_name = mods[i].name;
                }
            }
            printf("module headers at load: %zu modules, %.1f ms in all, worst %.1f ms (%s)\n",
                   nmods, all, worst, worst_name);
        }

        /* What IDA's analysis costs: it reads a module's code page by page,
           and again after every stop. ntdll's first 64 KiB, twice. */
        for ( i = 0; i < nmods; i++ )
            if ( _stricmp(mods[i].name, "ntdll.dll") == 0 )
            {
                int pass;
                for ( pass = 0; pass < 3; pass++ )
                {
                    /* the third pass from elsewhere in the recording, as after a stop */
                    if ( pass == 2 )
                        api->cursor_seek(c, info.first);
                    size_t total = 0, pg;
                    t0 = now_ms();
                    for ( pg = 0; pg < 16; pg++ )
                    {
                        api->cursor_read_memory(c, mods[i].base + pg * 4096, page, known, sizeof(page), &nk);
                        total += nk;
                    }
                    printf("ntdll's first 64 KiB, pass %d: %zu bytes known, %.1f ms (%.2f ms a page)\n",
                           pass + 1, total, now_ms() - t0, (now_ms() - t0) / 16);
                }
                break;
            }
    }

    /* ---- exceptions ---------------------------------------------------------- */
    if ( api->query_exceptions != NULL )
    {
        ittd_exception ex[8];
        size_t n = 0, k;
        int trunc = 0;
        t0 = now_ms();
        api->query_exceptions(B, ex, 8, &n, &trunc, NULL);
        printf("\nexceptions: %zu, %.1f ms\n", n, now_ms() - t0);
        for ( k = 0; k < n && k < 8; k++ )
            printf("  %s  tid %u  code %08x at %llx  raised at %s\n", pos_text(ex[k].pos), ex[k].tid,
                   ex[k].code, (unsigned long long)ex[k].address, pos_text(ex[k].raise_pos));
    }

    /* ---- syscalls ------------------------------------------------------------ */
    if ( (info.capabilities & ITTD_CAP_SYSCALLS) != 0
      && offsetof(ittd_backend_api, query_syscalls) + sizeof(api->query_syscalls) <= api->size
      && api->query_syscalls != NULL )
    {
        ittd_syscall *sc;
        size_t n = 0, k, named = 0, at_syscall = 0, sampled = 0, ordered = 1;
        int trunc = 0;
        t0 = now_ms();
        api->query_syscalls(B, NULL, 0, &n, &trunc, NULL);
        n_cap = n;
        sc = (ittd_syscall *)calloc(n ? n : 1, sizeof(*sc));
        api->query_syscalls(B, sc, n, &n, &trunc, NULL);
        clamp_count(&n, n_cap);
        printf("\nsyscalls: %zu, %.1f ms\n", n, now_ms() - t0);
        for ( k = 0; k < n; k++ )
        {
            if ( sc[k].name[0] != '\0' )
                named++;
            if ( k > 0 && (sc[k].pos.hi < sc[k - 1].pos.hi
                        || (sc[k].pos.hi == sc[k - 1].pos.hi && sc[k].pos.lo < sc[k - 1].pos.lo)) )
                ordered = 0;
        }
        for ( k = 0; k < n && k < 5; k++ )
            printf("  %s  tid %u  %#x %s -> %#llx\n", pos_text(sc[k].pos), sc[k].tid, sc[k].number,
                   sc[k].name, (unsigned long long)sc[k].result);
        /* At a syscall's position the next instruction is the syscall itself.
           Sampled across the list, as each one is a seek. */
        for ( k = 0; k < n; k += n / 64 + 1 )
        {
            uint8_t code[2] = { 0, 0 }, kn[2] = { 0, 0 };
            size_t got = 0;
            uint64_t rip = rip_at(c, sc[k].pos);
            sampled++;
            if ( rip != ITTD_BADADDR
              && api->cursor_read_memory(c, rip, code, kn, 2, &got) == ITTD_OK
              && got == 2 && code[0] == 0x0F && code[1] == 0x05 )
                at_syscall++;
        }
        printf("  %zu named, %zu of %zu sampled at a syscall instruction\n", named, at_syscall, sampled);
        {
            /* One step on from a syscall the kernel has returned: rax there is its result.
               (Not for the few that never come back, like NtContinue.) */
            size_t came_back = 0, agree = 0;
            for ( k = 0; k < n; k += n / 64 + 1 )
            {
                ittd_regs r0, r1;
                int stop = 0;
                if ( api->cursor_seek(c, sc[k].pos) != ITTD_OK || api->cursor_regs(c, &r0) != ITTD_OK )
                    continue;
                api->nav_step(c, 1, &stop);
                if ( api->cursor_regs(c, &r1) != ITTD_OK || r1.gp[ITTD_REG_RIP] != r0.gp[ITTD_REG_RIP] + 2 )
                    continue;
                came_back++;
                if ( r1.gp[ITTD_REG_RAX] == sc[k].result )
                    agree++;
                else
                    printf("  %s %s: result %#llx, rax after %#llx\n", pos_text(sc[k].pos), sc[k].name,
                           (unsigned long long)sc[k].result, (unsigned long long)r1.gp[ITTD_REG_RAX]);
            }
            printf("  %zu of %zu sampled returned to the next instruction\n", came_back, sampled);
            if ( HAS(regs_at) )
            {
                /* A backend may answer regs_at for syscall positions from what it
                   saw listing them; it must agree with a seek. */
                size_t same = 0, asked = 0;
                for ( k = 0; k < n; k += n / 64 + 1 )
                {
                    ittd_regs a, b;
                    asked++;
                    if ( api->regs_at(B, &sc[k].pos, 1, &a, NULL) == ITTD_OK
                      && api->cursor_seek(c, sc[k].pos) == ITTD_OK && api->cursor_regs(c, &b) == ITTD_OK
                      && memcmp(a.gp, b.gp, sizeof(a.gp)) == 0 )
                        same++;
                }
                check(same == asked, "  registers at a syscall agree between regs_at and a seek");

                /* And one batch of positions no syscall list has (just past
                   each sampled syscall), in reverse order: what a backend
                   reads itself rather than remembers. */
                {
                    size_t m = 0, j, agree_b = 0;
                    ittd_position ps[64];
                    ittd_regs rs[64];
                    for ( k = 0; k < n && m < 64; k += n / 64 + 1 )
                        ps[m++] = pos_plus(sc[k].pos, 3);
                    for ( j = 0; j < m / 2; j++ )
                    {
                        ittd_position t = ps[j];
                        ps[j] = ps[m - 1 - j];
                        ps[m - 1 - j] = t;
                    }
                    t0 = now_ms();
                    if ( api->regs_at(B, ps, m, rs, NULL) == ITTD_OK )
                    {
                        printf("  regs_at for %zu positions past syscalls: %.1f ms\n", m, now_ms() - t0);
                        for ( j = 0; j < m; j++ )
                        {
                            ittd_regs b;
                            if ( (rs[j].have & ITTD_REGS_GP) != 0 && api->cursor_seek(c, ps[j]) == ITTD_OK
                              && api->cursor_regs(c, &b) == ITTD_OK && memcmp(rs[j].gp, b.gp, sizeof(b.gp)) == 0 )
                                agree_b++;
                        }
                    }
                    check(m > 0 && agree_b == m, "  a regs_at batch of other positions agrees with seeks");
                }

                /* ITTD_PROBE_BENCH_READS=1: what reading memory at every
                   syscall costs, as the syscall decoder does it: registers in
                   one batch, then one 256-byte block of stack each in one
                   read_memory_at; and, for comparison, a cursor seeked to
                   each of the first hundred and read there. */
                if ( getenv("ITTD_PROBE_BENCH_READS") != NULL && HAS(read_memory_at) )
                {
                    ittd_position *bp = (ittd_position *)calloc(n ? n : 1, sizeof(*bp));
                    ittd_regs *br = (ittd_regs *)calloc(n ? n : 1, sizeof(*br));
                    ittd_mem_read *rd = (ittd_mem_read *)calloc(n ? n : 1, sizeof(*rd));
                    uint8_t *buf = (uint8_t *)calloc(n ? n * 256 : 1, 1), *kn = (uint8_t *)calloc(n ? n * 256 : 1, 1);
                    size_t j, nr = 0, serial = n < 100 ? n : 100, known_bytes = 0;
                    double t1;
                    for ( j = 0; j < n; j++ )
                        bp[j] = sc[j].pos;
                    t1 = now_ms();
                    api->regs_at(B, bp, n, br, NULL);
                    printf("  bench: regs_at for %zu syscalls: %.1f ms\n", n, now_ms() - t1);
                    for ( j = 0; j < n; j++ )
                    {
                        if ( (br[j].have & ITTD_REGS_GP) == 0 )
                            continue;
                        rd[nr].pos = sc[j].pos;
                        rd[nr].addr = br[j].gp[ITTD_REG_RSP] & ~0xFFull;
                        rd[nr].offset = nr * 256;
                        rd[nr].size = 256;
                        nr++;
                    }
                    t1 = now_ms();
                    api->read_memory_at(B, rd, nr, buf, kn, NULL);
                    t1 = now_ms() - t1;
                    for ( j = 0; j < nr * 256; j++ )
                        known_bytes += kn[j] != ITTD_KNOWN_NO;
                    printf("  bench: read_memory_at, %zu positions x 256 bytes: %.1f ms (%.2f ms a position), %zu bytes known\n",
                           nr, t1, nr ? t1 / (double)nr : 0.0, known_bytes);
                    /* The cursor's answer at each of the first 'serial'
                       positions (ITTD_PROBE_BENCH_READS=N, default 100), timed
                       and compared byte for byte with the batch's. */
                    if ( atoi(getenv("ITTD_PROBE_BENCH_READS")) > 1 )
                        serial = (size_t)atoi(getenv("ITTD_PROBE_BENCH_READS"));
                    {
                        uint8_t one[256], onek[256];
                        size_t differ = 0, compared = 0;
                        t1 = now_ms();
                        for ( j = 0; j < serial && j < nr; j++ )
                        {
                            size_t got = 0, b2;
                            api->cursor_seek(c, rd[j].pos);
                            api->cursor_read_memory(c, rd[j].addr, one, onek, 256, &got);
                            compared++;
                            for ( b2 = 0; b2 < 256; b2++ )
                                if ( (onek[b2] != 0) != (kn[j * 256 + b2] != ITTD_KNOWN_NO)
                                  || (onek[b2] != 0 && one[b2] != buf[j * 256 + b2]) )
                                {
                                    differ++;
                                    break;
                                }
                        }
                        t1 = now_ms() - t1;
                        printf("  bench: one cursor, seek and read, %zu positions: %.1f ms (%.2f ms a position)\n",
                               compared, t1, compared ? t1 / (double)compared : 0.0);
                        check(differ == 0, "  read_memory_at gives what a cursor reads at each position");
                        if ( differ != 0 )
                            printf("  %zu of %zu blocks differ\n", differ, compared);
                    }
                    /* A second position near the first: a syscall, then just
                       after it, as the decoder reads arguments then results. */
                    {
                        uint8_t one[256], onek[256];
                        double t_next = 0, t_at = 0;
                        size_t m = nr < 100 ? nr : 100;
                        for ( j = 0; j < m; j++ )
                        {
                            size_t got = 0;
                            double t2 = now_ms();
                            api->cursor_seek(c, rd[j].pos);
                            api->cursor_read_memory(c, rd[j].addr, one, onek, 256, &got);
                            t_at += now_ms() - t2;
                            t2 = now_ms();
                            api->cursor_seek(c, pos_plus(rd[j].pos, 1));
                            api->cursor_read_memory(c, rd[j].addr, one, onek, 256, &got);
                            t_next += now_ms() - t2;
                        }
                        printf("  bench: %zu syscalls, seek and read there %.2f ms, then one position on %.2f ms (each)\n",
                               m, m ? t_at / m : 0.0, m ? t_next / m : 0.0);
                    }
                    free(bp); free(br); free(rd); free(buf); free(kn);
                }
            }
            check(came_back > 0 && agree == came_back, "  a syscall's result is rax once it returns");
        }
        {
            /* The numbers no stub was found for, so a gap in the name table shows. */
            uint32_t seen[16];
            size_t ns = 0, j;
            for ( k = 0; k < n && ns < 16; k++ )
            {
                if ( sc[k].name[0] != '\0' )
                    continue;
                for ( j = 0; j < ns && seen[j] != sc[k].number; j++ )
                    ;
                if ( j == ns )
                {
                    seen[ns++] = sc[k].number;
                    printf("  unnamed: %#x, first at %s\n", sc[k].number, pos_text(sc[k].pos));
                }
            }
        }
        check((int)ordered, "  syscalls are in position order");
        check(n == 0 || named > 0, "  syscalls have names");
        check(at_syscall == sampled, "  rip at a syscall's position is a syscall instruction");

        /* The handles NtOpen* / NtCreate* wrote back (their first argument,
           r10), as query_out_values recovers them: a handle is a small
           multiple of four. */
        if ( info.is64 && offsetof(ittd_backend_api, query_out_values) + sizeof(api->query_out_values) <= api->size
          && api->query_out_values != NULL )
        {
            ittd_out_slot slots[64];
            uint64_t values[64];
            uint8_t known[64];
            size_t m = 0, found = 0, handle_like = 0;
            for ( k = 0; k < n && m < 64; k++ )
            {
                ittd_regs rr;
                if ( (strncmp(sc[k].name, "NtOpen", 6) != 0 && strncmp(sc[k].name, "NtCreate", 8) != 0)
                  || (int32_t)(uint32_t)sc[k].result < 0
                  || api->cursor_seek(c, sc[k].pos) != ITTD_OK || api->cursor_regs(c, &rr) != ITTD_OK )
                    continue;
                memset(&slots[m], 0, sizeof(slots[m]));
                slots[m].call  = sc[k].pos;
                slots[m].addr  = rr.gp[10];
                slots[m].tid   = sc[k].tid;
                slots[m].width = 8;
                m++;
            }
            t0 = now_ms();
            if ( m > 0 && api->query_out_values(B, slots, m, values, known, NULL) == ITTD_OK )
            {
                for ( k = 0; k < m; k++ )
                {
                    found += known[k] != 0;
                    handle_like += known[k] != 0 && values[k] != 0 && values[k] < 0x100000 && (values[k] & 3) == 0;
                }
                printf("  out parameters of %zu NtOpen*/NtCreate* calls: %zu found, %zu handle-like, %.1f ms\n",
                       m, found, handle_like, now_ms() - t0);
                check(found == handle_like && found * 10 >= m * 9, "  their handles are recovered");
            }
        }
        free(sc);
    }

    /* ---- self-modifying code --------------------------------------------------- */
    if ( (info.capabilities & ITTD_CAP_SELF_MODIFYING) != 0
      && offsetof(ittd_backend_api, query_self_modifying) + sizeof(api->query_self_modifying) <= api->size
      && api->query_self_modifying != NULL )
    {
        ittd_selfmod *sm;
        size_t n = 0, k, writer_ok = 0, run_ok = 0, sampled = 0;
        int trunc = 0, rc;
        t0 = now_ms();
        rc = api->query_self_modifying(B, NULL, 0, &n, &trunc, NULL);
        n_cap = n;
        sm = (ittd_selfmod *)calloc(n ? n : 1, sizeof(*sm));
        if ( rc == ITTD_OK )
            rc = api->query_self_modifying(B, sm, n, &n, &trunc, NULL);
        clamp_count(&n, n_cap);
        printf("\nself-modifying code: %zu instruction(s), %.1f ms%s%s\n", rc == ITTD_OK ? n : 0,
               now_ms() - t0, rc == ITTD_OK ? "" : ", failed: ", rc == ITTD_OK ? "" : api->last_error(B));
        if ( rc == ITTD_OK )
        {
            for ( k = 0; k < n && k < 5; k++ )
                printf("  %llx +%llu  written at %s by %llx, first run at %s, %llu run(s)\n",
                       (unsigned long long)sm[k].address, (unsigned long long)sm[k].size,
                       pos_text(sm[k].write_pos), (unsigned long long)sm[k].write_ip,
                       pos_text(sm[k].execute_pos), (unsigned long long)sm[k].executions);
            if ( getenv("ITTD_PROBE_SCAN_DUMP") != NULL )
            {
                char path[1024];
                FILE *f;
                snprintf(path, sizeof(path), "%s.selfmod.tsv", getenv("ITTD_PROBE_SCAN_DUMP"));
                f = fopen(path, "w");
                for ( k = 0; f != NULL && k < n; k++ )
                {
                    fprintf(f, "%llx\t%llu\t%s\t%llx\t", (unsigned long long)sm[k].address,
                            (unsigned long long)sm[k].size, pos_text(sm[k].write_pos),
                            (unsigned long long)sm[k].write_ip);
                    fprintf(f, "%s\t%llu\n", pos_text(sm[k].execute_pos), (unsigned long long)sm[k].executions);
                }
                if ( f != NULL )
                    fclose(f);
            }
            /* The positions mean what the ABI says: at the write, RIP is the
               writer; at the first run, RIP is the instruction. */
            for ( k = 0; k < n; k += n / 32 + 1 )
            {
                sampled++;
                if ( rip_at(c, sm[k].write_pos) == sm[k].write_ip )
                    writer_ok++;
                if ( rip_at(c, sm[k].execute_pos) == sm[k].address )
                    run_ok++;
            }
            check(writer_ok == sampled, "  rip at write_pos is the writer");
            check(run_ok == sampled, "  rip at execute_pos is the written instruction");
        }
        free(sm);
    }

    /* ---- the replay environment -------------------------------------------------
       What a replay needs, and whether ITTD_PROBE_FORK_REGISTRY holds the
       recording's hives. ITTD_PROBE_OTHER_REGISTRY names other hives, which
       must be told apart and refused by a replay. A recording that carries its
       hives, or was made in an emulation root, takes no hive folder. */
    int hive_folder_used = 1;
    if ( offsetof(ittd_backend_api, check_registry) + sizeof(api->check_registry) <= api->size
      && api->replay_env != NULL && api->check_registry != NULL )
    {
        ittd_replay_env env;
        int rc;
        memset(&env, 0, sizeof(env));
        env.size = sizeof(env);
        rc = api->replay_env(B, &env);
        printf("\nreplay environment: %s, registry %s%s, root \"%s\", hint \"%s\", Windows \"%s\", system DLLs %s\n",
               env.host ? "host" : "emulation root", env.registry_known ? "named" : "not named",
               env.registry_carried ? " and carried" : "",
               env.emulation_root, env.registry_hint, env.windows_version,
               env.system_dlls == ITTD_DLLS_SAME ? "same" : env.system_dlls == ITTD_DLLS_DIFFER ? "differ" : "unknown");
        check(rc == ITTD_OK, "  replay_env answers");
        hive_folder_used = env.host && !env.registry_carried;
        rc = api->check_registry(B, "C:\\");
        check(rc == ITTD_E_NO_REGISTRY, "  check_registry: a folder without hives is ITTD_E_NO_REGISTRY");
        if ( getenv("ITTD_PROBE_FORK_REGISTRY") != NULL )
        {
            double t1 = now_ms();
            rc = api->check_registry(B, getenv("ITTD_PROBE_FORK_REGISTRY"));
            printf("check_registry(%s): %d %s, %.1f ms\n", getenv("ITTD_PROBE_FORK_REGISTRY"), rc,
                   rc < 0 ? api->last_error(B) : "", now_ms() - t1);
            /* A recording carrying its hives replays without them, so the folder
               may as well be empty. */
            check(rc == (env.registry_known ? ITTD_OK : ITTD_REGISTRY_UNVERIFIED)
                  || (env.registry_carried && rc == ITTD_E_NO_REGISTRY),
                  "  check_registry: the recording's own hives");
            t1 = now_ms();
            rc = api->check_registry(B, getenv("ITTD_PROBE_FORK_REGISTRY"));
            printf("again: %.1f ms\n", now_ms() - t1);
        }
        if ( getenv("ITTD_PROBE_OTHER_REGISTRY") != NULL && env.registry_known && hive_folder_used )
        {
            ittd_fork_settings fs;
            ittd_fork *fk = NULL;
            ittd_position mid = info.first;
            rc = api->check_registry(B, getenv("ITTD_PROBE_OTHER_REGISTRY"));
            printf("check_registry(%s): %d %s\n", getenv("ITTD_PROBE_OTHER_REGISTRY"), rc, rc < 0 ? api->last_error(B) : "");
            check(rc == ITTD_E_REGISTRY_MISMATCH, "  check_registry: other hives are ITTD_E_REGISTRY_MISMATCH");
            memset(&fs, 0, sizeof(fs));
            fs.size = sizeof(fs);
            fs.flags = ITTD_FORK_ALLOW_HOST;
            fs.registry_dir = getenv("ITTD_PROBE_OTHER_REGISTRY");
            mid = pos_between(info.first, info.last, 1, 2);
            rc = api->fork_open(B, mid, &fs, NULL, &fk);
            if ( rc == ITTD_OK )
                api->fork_close(fk);
            check(rc == ITTD_E_REGISTRY_MISMATCH, "  a replay with other hives is refused");
        }
    }

    /* ---- a fork ------------------------------------------------------------------
       Runs only when ITTD_PROBE_FORK_REGISTRY names the recording's hives.
       Replays to the middle, changes r11, records a few thousand instructions
       into ITTD_PROBE_FORK_OUT (default fork.sogttd) and opens that: it must
       start at the fork's position with the parent's RIP and the new r11. */
    if ( (info.capabilities & ITTD_CAP_FORK) != 0 && getenv("ITTD_PROBE_FORK_REGISTRY") != NULL
      && offsetof(ittd_backend_api, fork_close) + sizeof(api->fork_close) <= api->size
      && api->fork_open != NULL )
    {
        const char *out_path = getenv("ITTD_PROBE_FORK_OUT") != NULL ? getenv("ITTD_PROBE_FORK_OUT") : "fork.sogttd";
        const uint64_t patched = 0x1122334455667788ull;
        ittd_fork_settings fs;
        ittd_fork *fk = NULL;
        ittd_position mid = info.first;
        ittd_regs fr;
        uint64_t parent_rip, ran = 0;
        int rc;
        memset(&fs, 0, sizeof(fs));
        fs.size = sizeof(fs);
        fs.flags = ITTD_FORK_ALLOW_HOST;   /* the reference traces were recorded against the host */
        fs.registry_dir = getenv("ITTD_PROBE_FORK_REGISTRY");
        mid = pos_between(info.first, info.last, 1, 2);
        parent_rip = rip_at(c, mid);

        /* Without consent, a recording made against the host is not replayed
           (the reference traces all are). */
        fs.flags = 0;
        rc = api->fork_open(B, mid, &fs, NULL, &fk);
        printf("\nwithout ITTD_FORK_ALLOW_HOST: %s\n", rc == ITTD_OK ? "opened" : api->last_error(B));
        if ( rc == ITTD_OK )
            api->fork_close(fk);
        check(rc == ITTD_E_HOST_REPLAY && strstr(api->last_error(B), "against the host") != NULL,
              "  a host recording is not replayed without consent (ITTD_E_HOST_REPLAY)");
        fs.flags = ITTD_FORK_ALLOW_HOST;
        fk = NULL;

        /* A folder with no hives in it is named as such. */
        if ( hive_folder_used )
        {
            const char *real = fs.registry_dir;
            fs.registry_dir = "C:\\";
            rc = api->fork_open(B, mid, &fs, NULL, &fk);
            if ( rc == ITTD_OK )
                api->fork_close(fk);
            check(rc == ITTD_E_NO_REGISTRY, "  a folder without hives is ITTD_E_NO_REGISTRY");
            fs.registry_dir = real;
            fk = NULL;
        }

        t0 = now_ms();
        rc = api->fork_open(B, mid, &fs, NULL, &fk);
        printf("\nfork at %s: %s, %.1f ms\n", pos_text(mid), rc == ITTD_OK ? "open" : api->last_error(B), now_ms() - t0);
        check(rc == ITTD_OK, "  fork_open replays to the position");
        if ( rc == ITTD_OK )
        {
            check(api->fork_regs(fk, &fr) == ITTD_OK && fr.gp[ITTD_REG_RIP] == parent_rip,
                  "  the fork's rip is the recording's at that position");
            fr.gp[11] = patched;
            check(api->fork_set_regs(fk, &fr) == ITTD_OK, "  registers can be changed");
            t0 = now_ms();
            rc = api->fork_record(fk, out_path, 20000, "probe: r11", NULL, &ran);
            printf("  recorded %llu instruction(s) into %s, %.1f ms%s%s\n", (unsigned long long)ran, out_path,
                   now_ms() - t0, rc == ITTD_OK ? "" : ": ", rc == ITTD_OK ? "" : api->last_error(B));
            check(rc == ITTD_OK && ran > 0, "  the fork records");
            api->fork_close(fk);
        }
        if ( rc == ITTD_OK )
        {
            ittd_backend *child = api->open(out_path);
            check(child != NULL, "  the fork opens as a recording of its own");
            if ( child != NULL )
            {
                ittd_trace_info ci;
                ittd_cursor *cc = api->cursor_open(child);
                ittd_regs cr;
                api->info(child, &ci);
                printf("  fork: positions %s..%s\n", pos_text(ci.first), pos_text(ci.last));
                check(ci.first.lo == mid.lo, "  it starts at the fork's position");
                check(cc != NULL && api->cursor_seek(cc, ci.first) == ITTD_OK && api->cursor_regs(cc, &cr) == ITTD_OK
                      && cr.gp[ITTD_REG_RIP] == parent_rip && cr.gp[11] == patched,
                      "  with the parent's rip and the changed register");
                if ( cc != NULL )
                    api->cursor_close(cc);
                api->close(child);
            }
        }
    }

    /* ---- replay scans: strings and buffers --------------------------------------
       A full replay each, so also gated on ITTD_PROBE_FORK_REGISTRY. A string
       recovered after the start must be in memory just after its reported
       position (the write that completed it). */
    if ( (info.capabilities & ITTD_CAP_REPLAY_SCANS) != 0 && getenv("ITTD_PROBE_FORK_REGISTRY") != NULL
      && offsetof(ittd_backend_api, query_buffers) + sizeof(api->query_buffers) <= api->size
      && api->query_strings != NULL )
    {
        ittd_fork_settings fs;
        ittd_string_hit *sh;
        ittd_buffer_hit *bh;
        size_t n = 0, k, sampled = 0, there = 0;
        int trunc = 0, rc;
        memset(&fs, 0, sizeof(fs));
        fs.size = sizeof(fs);
        fs.flags = ITTD_FORK_ALLOW_HOST;
        fs.registry_dir = getenv("ITTD_PROBE_FORK_REGISTRY");

        t0 = now_ms();
        rc = api->query_strings(B, &fs, 8, NULL, 0, &n, &trunc, NULL);
        printf("\nstrings (8+): %zu, %.1f ms%s%s\n", n, now_ms() - t0,
               rc == ITTD_OK ? "" : ", failed: ", rc == ITTD_OK ? "" : api->last_error(B));
        check(rc == ITTD_OK, "  the string scan replays the recording");
        n_cap = n;
        sh = (ittd_string_hit *)calloc(n ? n : 1, sizeof(*sh));
        t0 = now_ms();
        if ( rc == ITTD_OK && api->query_strings(B, &fs, 8, sh, n, &n, &trunc, NULL) == ITTD_OK && clamp_count(&n, n_cap) )
        {
            printf("  again: %.1f ms (kept)\n", now_ms() - t0);
            for ( k = 0; k < n && k < 5; k++ )
                printf("  %s  %llx  %s\"%.60s\"\n", pos_text(sh[k].pos), (unsigned long long)sh[k].address,
                       sh[k].wide ? "L" : "", sh[k].text);
            for ( k = 0; k < n; k += n / 32 + 1 )
            {
                uint8_t mem[8], kn[8];
                size_t got = 0;
                ittd_position after = sh[k].pos;
                if ( sh[k].wide || (sh[k].pos.hi == info.first.hi && sh[k].pos.lo == info.first.lo) )
                    continue;
                after.lo++;
                sampled++;
                if ( api->cursor_seek(c, after) == ITTD_OK
                  && api->cursor_read_memory(c, sh[k].address, mem, kn, 4, &got) == ITTD_OK
                  && got == 4 && memcmp(mem, sh[k].text, 4) == 0 )
                    there++;
                else
                    printf("  not there: %s  %llx  \"%.40s\" (read %zu: %02x %02x %02x %02x)\n", pos_text(after),
                           (unsigned long long)sh[k].address, sh[k].text, got, mem[0], mem[1], mem[2], mem[3]);
            }
            printf("  %zu of %zu sampled ASCII strings in memory just after their position\n", there, sampled);
            if ( getenv("ITTD_PROBE_FIND") != NULL )
                for ( k = 0; k < n; k++ )
                    if ( strstr(sh[k].text, getenv("ITTD_PROBE_FIND")) != NULL )
                        printf("  found at %llx, %s: %s\"%.80s\"\n", (unsigned long long)sh[k].address,
                               pos_text(sh[k].pos), sh[k].wide ? "L" : "", sh[k].text);
            check(there == sampled, "  a string is in memory after the write that completed it");
            if ( getenv("ITTD_PROBE_SCAN_DUMP") != NULL )
            {
                char path[1024];
                FILE *f;
                snprintf(path, sizeof(path), "%s.strings.tsv", getenv("ITTD_PROBE_SCAN_DUMP"));
                f = fopen(path, "w");
                for ( k = 0; f != NULL && k < n; k++ )
                    fprintf(f, "%llx\t%s\t%s\t%s\n", (unsigned long long)sh[k].address,
                            pos_text(sh[k].pos), sh[k].wide ? "L" : "A", sh[k].text);
                if ( f != NULL )
                    fclose(f);
            }
        }
        free(sh);

        t0 = now_ms();
        rc = api->query_buffers(B, &fs, NULL, 0, &n, &trunc, NULL);
        printf("buffers: %zu, %.1f ms%s%s\n", n, now_ms() - t0,
               rc == ITTD_OK ? "" : ", failed: ", rc == ITTD_OK ? "" : api->last_error(B));
        check(rc == ITTD_OK, "  the buffer scan replays the recording");
        n_cap = n;
        bh = (ittd_buffer_hit *)calloc(n ? n : 1, sizeof(*bh));
        if ( rc == ITTD_OK && api->query_buffers(B, &fs, bh, n, &n, &trunc, NULL) == ITTD_OK && clamp_count(&n, n_cap) )
            for ( k = 0; k < n && k < 5; k++ )
                printf("  %llx +%llx  %s  written %s..%s by %llx (%llu)  %.50s\n",
                       (unsigned long long)bh[k].address, (unsigned long long)bh[k].size, bh[k].kind,
                       pos_text(bh[k].first_pos), pos_text(bh[k].last_pos),
                       (unsigned long long)bh[k].writer_ip, (unsigned long long)bh[k].writes, bh[k].preview);
        if ( rc == ITTD_OK && getenv("ITTD_PROBE_SCAN_DUMP") != NULL )
        {
            char path[1024];
            FILE *f;
            snprintf(path, sizeof(path), "%s.buffers.tsv", getenv("ITTD_PROBE_SCAN_DUMP"));
            f = fopen(path, "w");
            for ( k = 0; f != NULL && k < n; k++ )
            {
                fprintf(f, "%llx\t%llx\t%s\t%s\t", (unsigned long long)bh[k].address,
                        (unsigned long long)bh[k].size, bh[k].kind, pos_text(bh[k].first_pos));
                fprintf(f, "%s\t%llx\t%llu\t%s\n", pos_text(bh[k].last_pos),
                        (unsigned long long)bh[k].writer_ip, (unsigned long long)bh[k].writes, bh[k].preview);
            }
            if ( f != NULL )
                fclose(f);
        }
        free(bh);
    }

    /* ---- the memory heatmap (ITTD_PROBE_HEAT=1: a whole-recording pass) -------- */
    if ( getenv("ITTD_PROBE_HEAT") != NULL
      && offsetof(ittd_backend_api, heat_slice_position) + sizeof(api->heat_slice_position) <= api->size
      && api->query_access_heat != NULL )
    {
        size_t n = 0, k, pages = 0;
        int trunc = 0, rc;
        uint64_t reads = 0, writes = 0, execs = 0, last_page = ~0ull;
        ittd_heat_cell *cells;
        ittd_position p0, p1;
        t0 = now_ms();
        rc = api->query_access_heat(B, 12, 256, NULL, 0, &n, &trunc, NULL);
        printf("\nheatmap: %zu cell(s), %.1f ms%s\n", n, now_ms() - t0, rc == ITTD_OK ? "" : " (failed)");
        n_cap = n;
        cells = (ittd_heat_cell *)calloc(n ? n : 1, sizeof(*cells));
        if ( rc == ITTD_OK && api->query_access_heat(B, 12, 256, cells, n, &n, &trunc, NULL) == ITTD_OK && clamp_count(&n, n_cap) )
        {
            for ( k = 0; k < n; k++ )
            {
                reads += cells[k].reads;
                writes += cells[k].writes;
                execs += cells[k].executes;
                pages += cells[k].page != last_page;
                last_page = cells[k].page;
            }
            printf("  %zu page(s): %llu reads, %llu writes, %llu executes\n", pages,
                   (unsigned long long)reads, (unsigned long long)writes, (unsigned long long)execs);
            check(execs > 0 && writes > 0 && reads > 0, "  the heatmap counts reads, writes and executes");
        }
        api->heat_slice_position(B, 256, 0, &p0);
        api->heat_slice_position(B, 256, 128, &p1);
        printf("  slice 0 at %s, slice 128 at %s\n", pos_text(p0), pos_text(p1));

        /* Zoomed in: slices 64..128 of the whole count, counted again as a
           window of 64 slices of its own. Its accesses are those of whole
           slices 64..127, plus at most the first instant of slice 128 (a
           window includes its last position). */
        if ( offsetof(ittd_backend_api, heat_window_slice_position) + sizeof(api->heat_window_slice_position) <= api->size
          && api->query_access_heat_window != NULL && api->heat_window_slice_position != NULL && rc == ITTD_OK )
        {
            ittd_position_range w;
            ittd_position wp0;
            ittd_heat_cell *wc;
            size_t wn = 0;
            uint64_t lo = 0, hi = 0, got = 0;
            for ( k = 0; k < n; k++ )
            {
                uint64_t all = (uint64_t)cells[k].reads + cells[k].writes + cells[k].executes;
                if ( cells[k].slice >= 64 && cells[k].slice < 128 )
                    lo += all;
                if ( cells[k].slice >= 64 && cells[k].slice <= 128 )
                    hi += all;
            }
            api->heat_slice_position(B, 256, 64, &w.first);
            w.last = p1;
            t0 = now_ms();
            rc = api->query_access_heat_window(B, 12, 64, w, NULL, 0, &wn, &trunc, NULL);
            wn_cap = wn;
            wc = (ittd_heat_cell *)calloc(wn ? wn : 1, sizeof(*wc));
            if ( rc == ITTD_OK )
                rc = api->query_access_heat_window(B, 12, 64, w, wc, wn, &wn, &trunc, NULL);
            clamp_count(&wn, wn_cap);
            for ( k = 0; rc == ITTD_OK && k < wn; k++ )
                got += (uint64_t)wc[k].reads + wc[k].writes + wc[k].executes;
            printf("  window %s..%s: %zu cell(s), %llu accesses (whole count: %llu..%llu), %.1f ms\n",
                   pos_text(w.first), pos_text(w.last), wn, (unsigned long long)got,
                   (unsigned long long)lo, (unsigned long long)hi, now_ms() - t0);
            check(rc == ITTD_OK && got >= lo && got <= hi,
                  "  a heatmap window counts what the whole count has in that stretch");
            check(rc == ITTD_OK && (wn == 0 || wc[wn - 1].slice < 64), "  a window's slices stay within it");
            free(wc);
            api->heat_window_slice_position(B, 64, 0, w, &wp0);
            check(wp0.hi == w.first.hi && wp0.lo == w.first.lo, "  a window's first slice starts where it does");
        }
        free(cells);
    }

    api->cursor_close(c);
    api->close(B);
    free(mods);
    free(thr);
    free(tl);
    printf("\n%d check(s) failed\n", failures);
    return failures == 0 ? 0 : 3;
}
