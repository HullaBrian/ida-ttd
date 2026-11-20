// The an.* script commands that run the whole-recording analyses (the
// forks and recordings are script_fork.cpp's).
#include "plugin/script_internal.h"
#include "analysis/memsearch.h"
#include "analysis/coverage.h"
#include "analysis/callsites.h"
#include "analysis/tracer.h"
#include "analysis/memmap.h"
#include "analysis/syscalls.h"
#include "analysis/replay_scans.h"
#include "analysis/calltree.h"
#include "analysis/origin.h"
#include "analysis/handles.h"

namespace idattd
{
    // ------------------------------------------------------------------ an.*
    //
    // The analyses, run exactly as their UI actions run them (same functions,
    // wait boxes and database writes), with the scope given here instead of
    // in a dialog.

    static uint8_t access_mask(const Args &a, size_t i)
    {
        return rwx_mask(a.count() > i ? a.at(i) : qstring("rwx"), ACC_READ, ACC_WRITE, ACC_EXEC);
    }

    static void cmd_an_search(const Args &a, JObj &out)
    {
        need_session();
        ea_t lo = (ea_t)a.u64(0), hi = (ea_t)a.u64(1);
        uint64_t max = a.u64_or(3, 200);
        std::vector<MemAccess> v;
        bool truncated = false, cancelled = false;
        qstring err;
        if ( !search_memory(&mgr(), lo, hi, access_mask(a, 2), &v, &truncated, &cancelled, &err) )
            fail("the search did not run: %s", err.c_str());
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", format_position(v[i].pos)).hex("pc", v[i].pc).hex("addr", v[i].addr)
             .num("size", v[i].size).num("tid", v[i].tid).str("kind", access_name(v[i].kind));
            arr.add(o.done());
        }
        out.boolean("truncated", truncated).boolean("cancelled", cancelled)
           .num("count", (int64_t)v.size()).raw("accesses", arr.done());
    }

    // an.decode [MAX]: list and decode every syscall's arguments as the
    // Syscalls window does when nothing is saved (without saving), and say
    // where the time went (DecodeStats); MAX decoded rows are returned.
    static void cmd_an_decode(const Args &a, JObj &out)
    {
        need_session();
        // an.decode [MAX] [file=PATH] [saved]: file= writes every decoded row
        // ("pos<TAB>name<TAB>args") to PATH, for comparing two builds;
        // saved writes what the database holds instead of decoding.
        uint64_t max = 5;
        qstring file;
        bool saved = false;
        for ( size_t i = 0; i < a.count(); i++ )
        {
            if ( a.at(i).starts_with("file=") )
                file = a.at(i).substr(5);
            else if ( a.at(i) == "saved" )
                saved = true;
            else
                max = a.u64(i);
        }
        std::vector<SyscallEvent> v;
        std::vector<qstring> decoded;
        bool cancelled = false;
        auto dump = [&]()
        {
            if ( file.empty() )
                return;
            FILE *f = qfopen(file.c_str(), "w");
            if ( f == nullptr )
                fail("cannot write %s", file.c_str());
            for ( size_t i = 0; i < v.size(); i++ )
                qfprintf(f, "%s\t%s\t%s\n", format_position(v[i].pos).c_str(), v[i].name.c_str(),
                         i < decoded.size() ? decoded[i].c_str() : "");
            qfclose(f);
        };
        if ( saved )
        {
            if ( !load_syscalls(&v, &decoded) )
                fail("this database has no saved syscalls");
            dump();
            out.num("count", (int64_t)v.size());
            return;
        }
        const auto t0 = std::chrono::steady_clock::now();
        if ( !list_syscalls(&mgr(), &v, &cancelled) || cancelled )
            fail("this recording's syscalls were not listed");
        const double t_list = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        const bool ran = decode_syscalls(&mgr(), v, &decoded, &cancelled);
        need_session();
        dump();
        const DecodeStats &st = last_decode_stats();
        JObj s;
        s.num("calls", (int64_t)st.calls).num("with_signature", (int64_t)st.with_sig)
         .num("with_registers", (int64_t)st.with_regs).num("out_slots", (int64_t)st.out_slots)
         .num("needs_after", (int64_t)st.needs_after)
         .num("rounds_args", st.rounds_args).num("rounds_after", st.rounds_after)
         .num("fetches", (int64_t)st.fetches).num("blocks", (int64_t)st.blocks)
         .num("positions", (int64_t)st.positions);
        auto secs = [](double x) { qstring t; t.sprnt("%.2f", x); return t; };
        s.str("t_list", secs(t_list)).str("t_regs", secs(st.t_regs)).str("t_args", secs(st.t_args))
         .str("t_search", secs(st.t_search)).str("t_after", secs(st.t_after))
         .str("t_fetch", secs(st.t_fetch)).str("t_total", secs(st.t_total));
        size_t nonempty = 0;
        for ( const qstring &d : decoded )
            nonempty += !d.empty();
        JArr rows;
        for ( size_t i = 0, shown = 0; i < v.size() && shown < max; i++ )
        {
            if ( decoded[i].empty() )
                continue;
            JObj o;
            o.str("pos", format_position(v[i].pos)).str("name", v[i].name).str("args", decoded[i]);
            rows.add(o.done());
            shown++;
        }
        out.boolean("ran", ran).boolean("cancelled", cancelled).num("decoded", (int64_t)nonempty)
           .raw("stats", s.done()).raw("rows", rows.done());
    }

    static void cmd_an_syscalls(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 50);
        std::vector<SyscallEvent> v;
        bool cancelled = false;
        if ( !list_syscalls(&mgr(), &v, &cancelled) )
            fail("this recording does not list its syscalls");
        std::vector<std::optional<SyscallArgs>> args;
        syscall_arguments(mgr().backend(), v, 0, (size_t)max, &args);
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", format_position(v[i].pos)).num("tid", v[i].tid)
             .hex("number", v[i].number).str("name", v[i].name).hex("result", v[i].result);
            if ( i < args.size() && args[i].has_value() )
                o.hex_list("args", args[i]->data(), args[i]->size());
            arr.add(o.done());
        }
        out.boolean("cancelled", cancelled).num("count", (int64_t)v.size()).raw("syscalls", arr.done());
    }

    static void cmd_an_selfmod(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 50);
        std::vector<SelfModHit> v;
        bool cancelled = false;
        if ( !find_self_modifying(&mgr(), &v, &cancelled) )
            fail("this recording's backend cannot look for self-modifying code");
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.hex("address", v[i].address).num("size", (int64_t)v[i].size)
             .str("written", format_position(v[i].write_pos)).hex("writer", v[i].write_ip)
             .str("first_run", format_position(v[i].execute_pos))
             .num("runs", (int64_t)v[i].executions);
            arr.add(o.done());
        }
        out.boolean("cancelled", cancelled).num("count", (int64_t)v.size()).raw("hits", arr.done());
    }

    static void cmd_an_strings(const Args &a, JObj &out)
    {
        need_session();
        size_t np = plain_args(a, 2);
        uint32_t min_len = np > 0 ? (uint32_t)a.u64(0) : 6;
        uint64_t max = np > 1 ? a.u64(1) : 50;
        std::vector<StringHit> v;
        bool cancelled = false;
        qstring err;
        if ( !recover_strings(&mgr(), replay_args(a, np), min_len, &v, &cancelled, &err) )
            fail("the replay did not run: %s", err.c_str());
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.str("pos", format_position(v[i].pos)).hex("address", v[i].address)
             .boolean("wide", v[i].wide).str("text", v[i].text);
            arr.add(o.done());
        }
        need_session();         // the session may have ended during the replay
        out.boolean("cancelled", cancelled).num("count", (int64_t)v.size()).raw("strings", arr.done())
           .str("notice", mgr().backend()->scan_notice());
    }

    static void cmd_an_buffers(const Args &a, JObj &out)
    {
        need_session();
        size_t np = plain_args(a, 1);
        uint64_t max = np > 0 ? a.u64(0) : 50;
        std::vector<BufferHit> v;
        bool cancelled = false;
        qstring err;
        if ( !recover_buffers(&mgr(), replay_args(a, np), &v, &cancelled, &err) )
            fail("the replay did not run: %s", err.c_str());
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.hex("address", v[i].address).hex("size", v[i].size).str("kind", v[i].kind)
             .str("first", format_position(v[i].first_pos)).str("last", format_position(v[i].last_pos))
             .hex("writer", v[i].writer_ip).num("writes", (int64_t)v[i].writes).str("preview", v[i].preview);
            arr.add(o.done());
        }
        need_session();         // the session may have ended during the replay
        out.boolean("cancelled", cancelled).num("count", (int64_t)v.size()).raw("buffers", arr.done())
           .str("notice", mgr().backend()->scan_notice());
    }

    static void cmd_an_calltree(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 50);
        CallTree t;
        qstring err;
        if ( !build_call_tree(&mgr(), &t, &err) )
            fail("the call tree did not build: %s", err.c_str());
        JArr arr;
        for ( size_t i = 0; i < t.rows.size() && i < max; i++ )
        {
            const CallTreeRow &r = t.rows[i];
            JObj o;
            o.str("pos", format_position(r.pos)).num("depth", r.depth).hex("site", r.site)
             .hex("target", r.target).str("ret", format_position(r.ret_pos)).boolean("call", r.is_call);
            arr.add(o.done());
        }
        out.hex("root", t.root).str("from", format_position(t.from)).str("to", format_position(t.to))
           .boolean("from_cursor", t.from_cursor).boolean("truncated", t.truncated)
           .boolean("cancelled", t.cancelled).num("count", (int64_t)t.rows.size()).raw("calls", arr.done());
    }

    // Build the heatmap's counts, as the menu does; their size.
    static void cmd_an_heat(const Args &, JObj &out)
    {
        need_session();
        qstring err;
        if ( !build_heatmap(&mgr(), &err) )
            fail("%s", err.c_str());
        out.num("json_bytes", (int64_t)heatmap_json().length());
    }

    static void cmd_an_coverage(const Args &a, JObj &out)
    {
        need_session();
        CoverageResult r;
        bgcolor_t color = (bgcolor_t)a.u64_or(2, COVERAGE_DEFAULT_COLOR);
        if ( !run_coverage(&mgr(), { { (ea_t)a.u64(0), (ea_t)a.u64(1) } }, color, &r) )
            fail("coverage did not run: %s", r.error.c_str());
        out.num("executed", (int64_t)r.executed).num("colored", (int64_t)r.colored)
           .num("both", (int64_t)r.both).num("undefined", (int64_t)r.undefined).boolean("cancelled", r.cancelled);
    }

    static void cmd_an_callsites(const Args &a, JObj &out)
    {
        need_session();
        ea_t lo = (ea_t)a.u64(0), hi = (ea_t)a.u64(1);
        CallSiteResult r;
        if ( !annotate_indirect_calls(&mgr(), { { lo, hi } }, &r) )
            fail("the call site sweep did not run: %s", r.error.c_str());
        // What it wrote: the repeatable comment at each annotated site.
        JArr arr;
        for ( ea_t ea = lo; ea < hi && ea != BADADDR && arr.size() < 64; ea = next_head(ea, hi) )
        {
            qstring cmt;
            if ( get_cmt(&cmt, ea, true) > 0 && strncmp(cmt.c_str(), "TTD:", 4) == 0 )
            {
                JObj o;
                o.hex("site", ea).str("comment", cmt);
                tinfo_t ct;
                qstring ts;
                if ( get_tinfo(&ct, ea) && ct.print(&ts) )
                    o.str("call_type", ts);
                arr.add(o.done());
            }
        }
        out.num("sites", (int64_t)r.sites).num("targets", (int64_t)r.targets)
           .num("polymorphic", (int64_t)r.polymorphic).num("undefined", (int64_t)r.undefined)
           .num("typed", (int64_t)r.typed)
           .boolean("truncated", r.truncated).boolean("cancelled", r.cancelled)
           .raw("annotated", arr.done());
    }

    static void cmd_an_trace(const Args &a, JObj &out)
    {
        need_session();
        FunctionTracer &tr = g_plugin->tracer();
        uint64_t max = a.u64_or(1, 40);
        tr.reset();
        // An address, or a "module!Glob*" pattern as Find calls by pattern
        // takes it. A hex word with "0x" or a leading digit is an address
        // (no symbol starts with a digit, and ida_ttd.py sends ints as bare
        // hex). One starting with a letter ("add", "face") is a name first,
        // and an address only when no function matches it.
        const qstring &word = a.at(0);
        uint64_t ea = 0;
        const bool is_hex = parse_u64(word, &ea);
        if ( is_hex && (word.starts_with("0x") || word.starts_with("0X") || qisdigit((uchar)word[0])) )
        {
            tr.add_func((ea_t)ea);
        }
        else
        {
            for ( ea_t f : mgr().modules().resolve_function_pattern(word.c_str()) )
                tr.add_func(f);
            if ( tr.count_traced() == 0 && is_hex )
                tr.add_func((ea_t)ea);
        }
        out.num("traced", (int64_t)tr.count_traced());
        qstring err;
        if ( !tr.run_sweep(&err) )
            fail("the trace did not run: %s", err.c_str());
        std::vector<FunctionInvocation> v = tr.snapshot_events();
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JArr args;
            for ( const qstring &s : v[i].args )
            {
                qstring q;
                json_escape(&q, s.c_str());
                args.add(q);
            }
            JObj o;
            qstring name;
            if ( get_name(&name, v[i].func_ea) <= 0 || name.empty() )
                name = mgr().modules().export_name_at(v[i].func_ea);
            o.hex("func", v[i].func_ea).str("name", name).str("pos", format_position(v[i].pos))
             .str("end", v[i].has_ret ? format_position(v[i].end_pos) : qstring())
             .num("tid", v[i].tid).raw("args", args.done()).str("ret", v[i].retval);
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).raw("calls", arr.done());
    }

    static void cmd_an_memmap(const Args &a, JObj &out)
    {
        need_session();
        // The session's map, as the Memory map window and IDA's segments
        // have it: built when there is none, again with 'rebuild'.
        bool rebuild = false;
        uint64_t max = 40;
        for ( size_t i = 0; i < a.count(); i++ )
        {
            if ( a.at(i) == "rebuild" )
                rebuild = true;
            else
                max = a.u64(i);
        }
        bool cancelled = false;
        qstring err;
        if ( !session_memory_map(&mgr(), rebuild, &cancelled, &err) )
            fail("%s", err.c_str());
        const MemoryMap &mm = mgr().memmap_for_update();
        // The regions as they stand at the playhead.
        std::vector<Region> regions;
        mm.state_at(mgr().current_position(), regions);
        JArr arr;
        for ( size_t i = 0; i < regions.size() && i < max; i++ )
        {
            JObj o;
            o.hex("base", regions[i].base).hex("size", (ea_t)regions[i].size)
             .hex("protect", regions[i].protect).str("origin", change_name(regions[i].origin));
            arr.add(o.done());
        }
        out.num("changes", (int64_t)mm.size()).boolean("cancelled", cancelled)
           .num("regions", (int64_t)regions.size()).raw("at_playhead", arr.done());
    }

    // What the automatic indirect-call resolution does on a stop in the
    // function at EA.
    static void cmd_an_autocalls(const Args &a, JObj &out)
    {
        need_session();
        ea_t ea = (ea_t)a.u64(0);
        func_entry_info_t fi;
        if ( !get_func_entry_info(&fi, ea) )
            fail("no function there");
        bool ok = auto_annotate_function(&mgr(), fi.start_ea, fi.end_ea);
        out.boolean("done", ok).hex("start", fi.start_ea).hex("end", fi.end_ea);
    }

    // A "from=POS" argument, removed from the list: the position a command
    // works at instead of the playhead.
    bool from_arg(Args *a, Position *p)
    {
        for ( size_t i = 1; i < a->v.size(); i++ )
        {
            if ( !a->v[i].starts_with("from=") )
                continue;
            *p = position_arg(a->v[i].substr(5));
            a->v.erase(a->v.begin() + i);
            return true;
        }
        return false;
    }

    static void origin_target_json(const OriginTarget &t, JObj &o)
    {
        o.str("what", origin_target_text(t));
        if ( t.is_reg )
            o.str("reg", origin_target_text(t));
        else
            o.hex("addr", t.addr).num("size", t.size);
    }

    // Remove 'word' from the arguments; whether it was there.
    static bool flag_arg(Args *a, const char *word)
    {
        for ( size_t i = 1; i < a->v.size(); i++ )
            if ( a->v[i] == word )
            {
                a->v.erase(a->v.begin() + i);
                return true;
            }
        return false;
    }

    // REG, or mem ADDR [SIZE], from the front of the arguments.
    OriginTarget origin_target_arg(const Args &a, const char *cmd)
    {
        OriginTarget t;
        uint32_t reg = 0;
        if ( a.count() >= 2 && a.at(0) == "mem" )
        {
            t.is_reg = false;
            t.addr   = (ea_t)a.u64(1);
            t.size   = (uint32_t)std::min<uint64_t>(std::max<uint64_t>(a.u64_or(2, 8), 1), 64);
        }
        else if ( a.count() >= 1 && parse_register(a.at(0).c_str(), &reg) )
        {
            t.reg = reg;
        }
        else
        {
            fail("usage: %s REG | %s mem ADDR [SIZE], then from=POS to start there", cmd, cmd);
        }
        return t;
    }

    static qstring hop_json(const OriginHop &h)
    {
        JObj o;
        o.str("what", origin_target_text(h.what)).str("value", origin_value_text(h.value))
         .str("at", format_position(h.at)).str("kind", origin_kind_name(h.kind))
         .str("by_pos", h.by_pos.is_valid() ? format_position(h.by_pos) : qstring())
         .hex("by_pc", h.by_pc).str("insn", h.insn).str("note", h.note).boolean("combined", h.combined);
        return o.done();
    }

    // Where a value came from: "an.origin rax", "an.origin mem ADDR [SIZE]".
    static void cmd_an_origin(const Args &args, JObj &out)
    {
        need_session();
        Args a = args;
        Position from;
        const bool has_from = from_arg(&a, &from);
        const bool through  = !flag_arg(&a, "stop");
        const OriginTarget t = origin_target_arg(a, "an.origin");
        std::vector<OriginHop> hops;
        if ( !(has_from ? trace_value_origin(&mgr(), t, from, 40, &hops, through)
                        : trace_value_origin(&mgr(), t, 40, &hops, through)) )
            fail("not traced");
        JArr arr;
        for ( const OriginHop &h : hops )
            arr.add(hop_json(h));
        out.num("hops", (int64_t)hops.size()).raw("chain", arr.done());
    }

    // Every chain at once, as the value origin graph draws it.
    static void cmd_an_origingraph(const Args &args, JObj &out)
    {
        need_session();
        Args a = args;
        Position from = mgr().current_position();
        from_arg(&a, &from);
        size_t max_nodes = 60;
        for ( size_t i = 1; i < a.v.size(); i++ )
            if ( a.v[i].starts_with("max=") )
            {
                uint64_t n = 0;
                if ( !parse_u64(a.v[i].substr(4), &n) || n == 0 )
                    fail("max= takes a hex number of values");
                max_nodes = (size_t)n;
                a.v.erase(a.v.begin() + i);
                break;
            }
        const OriginTarget t = origin_target_arg(a, "an.origingraph");
        OriginGraph g;
        if ( !build_origin_graph(&mgr(), t, from, max_nodes, &g) )
            fail("not traced");
        JArr nodes;
        for ( const OriginHop &h : g.nodes )
            nodes.add(hop_json(h));
        JArr edges;
        for ( const OriginGraph::Edge &e : g.edges )
        {
            JObj o;
            o.num("from", e.from).num("to", e.to).boolean("input", e.input);
            edges.add(o.done());
        }
        out.raw("nodes", nodes.done()).raw("edges", edges.done())
           .boolean("truncated", g.truncated).boolean("cancelled", g.cancelled);
    }

    // What the instruction about to run at a position read: the next links
    // of a chain that ended at a computation.
    static void cmd_an_inputs(const Args &a, JObj &out)
    {
        need_session();
        Position at = a.count() >= 1 ? position_arg(a.at(0)) : mgr().current_position();
        std::vector<OriginInput> v;
        if ( !origin_inputs(&mgr(), at, &v) )
            fail("no replay session is running");
        JArr arr;
        for ( const OriginInput &in : v )
        {
            JObj o;
            origin_target_json(in.what, o);
            o.str("value", origin_value_text(in.value)).boolean("address", in.address);
            arr.add(o.done());
        }
        out.str("pos", format_position(at)).raw("inputs", arr.done());
    }

    // The handle list.
    static void cmd_an_handles(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 200);
        std::vector<HandleRecord> v;
        bool cancelled = false;
        if ( !list_handles(&mgr(), &v, &cancelled) )
            fail("the recording's syscalls cannot be listed");
        JArr arr;
        for ( size_t i = 0; i < v.size() && i < max; i++ )
        {
            JObj o;
            o.hex("handle", (ea_t)v[i].handle).str("type", v[i].type).str("name", v[i].name)
             .str("opened", v[i].opened.is_valid() ? format_position(v[i].opened) : qstring())
             .str("by", v[i].opened_by)
             .str("closed", v[i].closed.is_valid() ? format_position(v[i].closed) : qstring());
            arr.add(o.done());
        }
        out.num("count", (int64_t)v.size()).boolean("cancelled", cancelled).raw("handles", arr.done());
    }

    // The Memory map listing's rows. Builds the change timeline first if
    // there is none (as the menu does, without asking).
    static void cmd_an_regions(const Args &a, JObj &out)
    {
        need_session();
        uint64_t max = a.u64_or(0, 200);
        bool cancelled = false;
        qstring err;
        if ( !session_memory_map(&mgr(), false, &cancelled, &err) )
            fail("%s", err.c_str());
        std::vector<AddressRegion> regions;
        address_space_at(&mgr(), &regions);
        JArr arr;
        for ( size_t i = 0; i < regions.size() && i < max; i++ )
        {
            const AddressRegion &r = regions[i];
            JObj o;
            o.hex("base", r.base).hex("size", (ea_t)r.size)
             .str("protect", r.reserved ? qstring("reserved")
                           : r.protect != 0 ? protection_text(r.protect) : qstring())
             .str("type", region_type_name(r.type)).str("use", r.use)
             .boolean("in_module", r.in_module)
             .str("since", r.since.is_valid() ? format_position(r.since) : qstring());
            arr.add(o.done());
        }
        out.num("changes", (int64_t)mgr().memmap_for_update().size()).num("count", (int64_t)regions.size())
           .raw("regions", arr.done());
    }

    // ------------------------------------------------------------------ commands

    static const Command ANALYSIS_COMMANDS[] = {
        { "an.search",      cmd_an_search,      "LO HI [rwx] [MAX] memory search, as the dialog runs it" },
        { "an.coverage",    cmd_an_coverage,    "LO HI [COLOR] measure and color execution coverage" },
        { "an.callsites",   cmd_an_callsites,   "LO HI annotate indirect calls, and list the comments" },
        { "an.trace",       cmd_an_trace,       "EA|module!Glob* [MAX] find all calls to a function, with arguments" },
        { "an.memmap",      cmd_an_memmap,      "[MAX] [rebuild] the session's memory map (built if there is none); the regions at the playhead" },
        { "an.regions",     cmd_an_regions,     "[MAX] the Memory map listing at the playhead" },
        { "an.handles",     cmd_an_handles,     "[MAX] the handles the program opened and closed" },
        { "an.origin",      cmd_an_origin,      "REG | mem ADDR [SIZE] [from=POS] [stop] where the value at the playhead (or POS) came from; stop: at every computation" },
        { "an.origingraph", cmd_an_origingraph, "REG | mem ADDR [SIZE] [from=POS] [max=N] every chain at once, as the graph draws it" },
        { "an.inputs",      cmd_an_inputs,      "[POS] the values the instruction about to run there read" },
        { "an.autocalls",   cmd_an_autocalls,   "EA resolve indirect calls in the function there, as a stop does automatically" },
        { "an.decode",      cmd_an_decode,      "[MAX] [file=PATH] [saved] decode every syscall's arguments as the Syscalls window does (not saved), with where the time went; file= writes every row, saved: the database's rows" },
        { "an.syscalls",    cmd_an_syscalls,    "[MAX] the recording's syscalls, with arguments" },
        { "an.selfmod",     cmd_an_selfmod,     "[MAX] code the program wrote and then ran" },
        { "an.calltree",    cmd_an_calltree,    "[MAX] the calls the function at the playhead made in this run of it" },
        { "an.strings",     cmd_an_strings,     "[MIN [MAX]] [registry=DIR] [root=DIR] [strict] [host] [anyregistry] [net] strings recovered by a replay" },
        { "an.buffers",     cmd_an_buffers,     "[MAX] [registry=DIR] [root=DIR] [strict] [host] [anyregistry] [net] buffers recovered by a replay" },
        { "an.heat",        cmd_an_heat,        "count every access by page and slice of time (the heatmap)" },
    };

    std::span<const Command> analysis_commands() { return ANALYSIS_COMMANDS; }
}
