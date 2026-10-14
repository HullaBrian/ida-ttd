// The memory heatmap: which pages the recording read, wrote and ran from,
// and when. The backend counts (ITraceBackend::query_access_heat); a PySide6
// window draws it (heatmap_py.hh), asking for the counts with
// ttd("ui.heat") and travelling with ttd("ui.showbytes POS EA").
#include "ui/ui.h"
#include "ui/heatmap_py.hh"
#include "analysis/query_runner.h"
#include <expr.hpp>

namespace idattd
{
    static const uint32_t kHeatPageShift = 12;
    static const uint32_t kHeatSlices    = 256;

    static qstring g_heatJson;

    const qstring &heatmap_json()
    {
        return g_heatJson;
    }

    static void json_str(qstring *out, const char *s)
    {
        out->append('"');
        for ( ; *s != '\0'; s++ )
        {
            unsigned char c = (unsigned char)*s;
            if ( c == '"' || c == '\\' )
            {
                out->append('\\');
                out->append((char)c);
            }
            else if ( c < 0x20 )
            {
                out->cat_sprnt("\\u%04x", c);
            }
            else
            {
                out->append((char)c);
            }
        }
        out->append('"');
    }

    // {"page_shift":12,"slices":256,"starts":["HI:LO",...],
    //  "pages":[{"page":N,"label":"ntdll","cells":[[slice,r,w,x],...]},...]}
    static qstring heat_json(TraceManager *mgr, const std::vector<HeatCell> &cells)
    {
        ITraceBackend *b = mgr->backend();
        qstring j;
        j.sprnt("{\"page_shift\":%u,\"slices\":%u,\"starts\":[", kHeatPageShift, kHeatSlices);
        for ( uint32_t s = 0; s < kHeatSlices; s++ )
        {
            if ( s != 0 )
                j.append(',');
            Position p = b->heat_slice_position(kHeatSlices, s);
            json_str(&j, p.is_valid() ? format_position(p).c_str() : "");
        }
        j.append("],\"pages\":[");
        for ( size_t i = 0; i < cells.size(); )
        {
            const uint64_t page = cells[i].page;
            if ( i != 0 )
                j.append(',');
            const ea_t ea = (ea_t)(page << kHeatPageShift);
            j.cat_sprnt("{\"page\":%llu,\"label\":", (unsigned long long)page);
            json_str(&j, mgr->modules().name_at(ea).c_str());
            j.append(",\"cells\":[");
            bool first = true;
            for ( ; i < cells.size() && cells[i].page == page; i++ )
            {
                const HeatCell &c = cells[i];
                j.cat_sprnt("%s[%u,%u,%u,%u]", first ? "" : ",", c.slice, c.reads, c.writes, c.executes);
                first = false;
            }
            j.append("]}");
        }
        j.append("]}");
        return j;
    }

    static bool open_heatmap_window()
    {
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr )
            return false;
        qstring err;
        if ( py->eval_snippet(HEATMAP_PY, &err) )
            return true;
        msg("[ida-ttd] the heatmap window could not be opened: %s\n", err.c_str());
        return false;
    }

    // Count, keep the answer for the window, and open it.
    bool build_heatmap(TraceManager *mgr, qstring *err)
    {
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            *err = "no trace is being replayed";
            return false;
        }
        std::vector<HeatCell> cells;
        ITraceBackend *b = mgr->backend();
        QueryResult qr = run_query("Counting every memory access", [&](ProgressSink *p)
        {
            return b->query_access_heat(kHeatPageShift, kHeatSlices, &cells, p);
        });
        if ( !qr.ran )
        {
            *err = "this recording's backend cannot count its accesses";
            return false;
        }
        if ( qr.cancelled )
        {
            *err = "cancelled";
            return false;
        }
        g_heatJson = heat_json(mgr, cells);
        return true;
    }

    int idaapi HeatmapHandler::activate(action_activation_ctx_t *)
    {
        if ( mgr() == nullptr || !mgr()->is_active() )
        {
            warning("The memory heatmap is only available while replaying a trace.");
            return 1;
        }
        qstring err;
        if ( !build_heatmap(mgr(), &err) )
        {
            if ( err != "cancelled" )
                warning("Could not build the memory heatmap: %s", err.c_str());
            return 1;
        }
        if ( !open_heatmap_window() )
            warning("The memory heatmap needs IDAPython with PySide6.");
        return 1;
    }
}
