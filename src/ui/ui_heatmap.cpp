// The memory heatmap: which pages the recording read, wrote and ran from,
// and when. The backend counts (ITraceBackend::query_access_heat); a PySide6
// window draws it (heatmap_py.hh), asking for the counts with
// ttd("ui.heat") and travelling with ttd("ui.showbytes POS EA").
#include "ui/ui.h"
#include "ui/graph_view.h"
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

    // {"page_shift":12,"slices":256,"starts":["HI:LO",...],"end":"HI:LO",
    //  "whole":true,"can_zoom":true,
    //  "pages":[{"page":N,"label":"ntdll","cells":[[slice,r,w,x],...]},...]}
    // 'end' is where the last slice ends: the window's last position, or the
    // recording's.
    static qstring heat_json(TraceManager *mgr, const std::vector<HeatCell> &cells, PositionRange when)
    {
        ITraceBackend *b = mgr->backend();
        qstring j;
        j.sprnt("{\"page_shift\":%u,\"slices\":%u,\"starts\":[", kHeatPageShift, kHeatSlices);
        for ( uint32_t s = 0; s < kHeatSlices; s++ )
        {
            if ( s != 0 )
                j.append(',');
            Position p = b->heat_window_slice_position(kHeatSlices, s, when);
            json_str(&j, p.is_valid() ? format_position(p).c_str() : "");
        }
        Position end = when.last == Position::end() ? b->info().last : when.last;
        j.append("],\"end\":");
        json_str(&j, end.is_valid() ? format_position(end).c_str() : "");
        j.cat_sprnt(",\"whole\":%s,\"can_zoom\":%s",
                    when.whole_trace() ? "true" : "false", b->can_window_heat() ? "true" : "false");
        j.append(",\"pages\":[");
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
    bool build_heatmap(TraceManager *mgr, qstring *err, PositionRange when)
    {
        if ( mgr == nullptr || !mgr->is_active() || mgr->backend() == nullptr )
        {
            *err = "no trace is being replayed";
            return false;
        }
        ITraceBackend *b = mgr->backend();
        if ( !when.whole_trace() && !b->can_window_heat() )
        {
            *err = "this recording's backend can only count the whole recording";
            return false;
        }
        if ( !when.whole_trace() && !(when.first < when.last) )
        {
            *err = "the span is empty: its start must come before its end";
            return false;
        }
        std::vector<HeatCell> cells;
        QueryResult qr = run_query(when.whole_trace() ? "Counting every memory access"
                                                      : "Counting the memory accesses in this span",
                                   [&](ProgressSink *p)
        {
            return b->query_access_heat_window(kHeatPageShift, kHeatSlices, when, &cells, p);
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
        g_heatJson = heat_json(mgr, cells, when);
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
