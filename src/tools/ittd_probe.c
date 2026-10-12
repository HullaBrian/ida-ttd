/*
 * ittd-probe: load an ida-ttd backend DLL and exercise it against a recording,
 * with no IDA involved.
 *
 *   ittd-probe BACKEND.dll TRACE [EXPORT]
 *
 * Prints what the backend reports, and checks the promises the ABI makes about
 * positions -- the part a wrong answer to is silent in the UI (a register view
 * one instruction off):
 *
 *   - at an access's position, the program counter is the instruction that did
 *     it;
 *   - at a call's pos the PC is the call site, at entry_pos the target, and at
 *     ret_pos it is back in the caller just past the site;
 *   - a forward step moves the position by one.
 *
 * EXPORT (default RtlAllocateHeap) is the function whose calls are listed.
 *
 * Written in C on purpose: it is also the check that abi/ida_ttd_backend.h is
 * the plain C it says it is.
 */

#include <abi/ida_ttd_backend.h>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const ittd_backend_api *api;
static ittd_backend *B;
static int failures;

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
    *n = 0;
    if ( count_fill(NULL, 0, n) != ITTD_OK )
        return NULL;
    buf = calloc(*n ? *n : 1, size);
    if ( buf != NULL && count_fill(buf, *n, n) != ITTD_OK )
    {
        free(buf);
        return NULL;
    }
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

    /* ---- the export whose calls we list --------------------------------- */
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
        ittd_position mid = info.last, here;
        ittd_regs r;
        uint32_t tid = 0;
        int stop = -1;
        uint8_t bytes[16], known[16];
        size_t nk = 0;

        mid.lo = info.first.lo + (info.last.lo - info.first.lo) / 2;
        t0 = now_ms();
        check(api->cursor_seek(c, mid) == ITTD_OK, "seek to the middle");
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
        if ( api->query_instructions != NULL )
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
        check(here.lo == mid.lo + 1 && stop == ITTD_STOP_STEPPED, "a forward step moves one position");
        api->nav_step(c, 0, &stop);
        api->cursor_position(c, &here);
        check(here.lo == mid.lo, "and a backward step moves back");

        /* run to the instruction at rip again, from just past it */
        api->nav_step(c, 1, &stop);
        t0 = now_ms();
        api->nav_run_to(c, r.gp[ITTD_REG_RIP], 0, &stop);
        api->cursor_position(c, &here);
        printf("  run back to rip: stop %d at %s, %.1f ms\n", stop, pos_text(here), now_ms() - t0);
        check(here.lo == mid.lo && stop == ITTD_STOP_STEPPED, "running backward to rip lands on this position");
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
        calls = (ittd_call *)calloc(n ? n : 1, sizeof(ittd_call));
        api->query_calls(B, &target, 1, all, calls, n, &n, &trunc, NULL);
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
            if ( !is_none(e->pos) )
                check(at_pos == e->site, "  rip at pos is the call site");
            check(at_entry == e->target, "  rip at entry_pos is the target");
            /* At the callee's first instruction, the frame was entered by this
               very call. */
            if ( k == 0 && !is_none(e->pos) && api->query_frame_entry != NULL )
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
            if ( k == 0 && !is_none(e->pos) && e->pos.lo > 0 && api->nav_breakpoints != NULL )
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
                }
            }
            if ( !is_none(e->pos) && !is_none(e->ret_pos) && api->nav_step_over != NULL )
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
            }
            if ( !is_none(e->ret_pos) )
            {
                at_ret = rip_at(c, e->ret_pos);
                check(at_ret > e->site && at_ret <= e->site + 15, "  rip at ret_pos is just past the site");
                if ( at_ret != ITTD_BADADDR && api->cursor_regs(c, &r) == ITTD_OK )
                    printf("    returned rax %llx\n", (unsigned long long)r.gp[ITTD_REG_RAX]);
            }
        }

        /* the batch form, against the cursor's answers */
        if ( api->regs_at != NULL && n > 0 )
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
        tg = (ittd_call_target *)calloc(n ? n : 1, sizeof(ittd_call_target));
        api->query_indirect(B, &r, 1, 0, tg, n, &n, &trunc, NULL);
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
    if ( (info.capabilities & ITTD_CAP_MAPPING_CHANGES) != 0 && api->query_mapping_changes != NULL )
    {
        ittd_mapping_change *mc;
        ittd_name *names = NULL;
        size_t n = 0, nn = 0, k, at_start = 0, rwx = 0;
        int ordered = 1, files_ok = 1;
        int trunc = 0;
        printf("\nmemory map\n");
        t0 = now_ms();
        api->query_mapping_changes(B, NULL, 0, &n, &trunc, NULL);
        mc = (ittd_mapping_change *)calloc(n ? n : 1, sizeof(ittd_mapping_change));
        api->query_mapping_changes(B, mc, n, &n, &trunc, NULL);
        printf("  %zu entr%s, %.1f ms\n", n, n == 1 ? "y" : "ies", now_ms() - t0);
        if ( api->query_mapping_files != NULL )
        {
            api->query_mapping_files(B, NULL, 0, &nn);
            names = (ittd_name *)calloc(nn ? nn : 1, sizeof(ittd_name));
            api->query_mapping_files(B, names, nn, &nn);
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
            /* MEM_COMMIT, PAGE_EXECUTE_READWRITE, not an image */
            if ( mc[k].state == 0x1000 && (mc[k].protect & 0xFF) == 0x40 && mc[k].region_type != ITTD_REGION_IMAGE )
            {
                if ( rwx++ < 5 )
                    printf("  RWX %016llx +%llx at %s (asked for at %s), type %u\n",
                           (unsigned long long)mc[k].base, (unsigned long long)mc[k].size,
                           pos_text(mc[k].pos), pos_text(mc[k].call_pos), mc[k].region_type);
            }
        }
        printf("  %zu at the start, %zu changes, %zu file name(s), %zu RWX committed\n",
               at_start, n - at_start, nn, rwx);
        for ( k = 0; k < nn && k < 3; k++ )
            printf("  file %zu: %s\n", k + 1, names[k].name);
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
        mid.lo = info.first.lo + (info.last.lo - info.first.lo) / 2;
        api->cursor_seek(c, mid);
        if ( api->cursor_regs(c, &r) == ITTD_OK )
        {
            uint64_t sp_page = (r.gp[ITTD_REG_RSP] & ~0xFFFull) + 0x1000;
            t0 = now_ms();
            api->cursor_read_memory(c, sp_page, page, known, sizeof(page), &nk);
            printf("\nthe stack page above rsp at %s: %zu of 4096 bytes known, %.1f ms\n",
                   pos_text(mid), nk, now_ms() - t0);
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

    api->cursor_close(c);
    api->close(B);
    free(mods);
    free(thr);
    free(tl);
    printf("\n%d check(s) failed\n", failures);
    return failures == 0 ? 0 : 3;
}
