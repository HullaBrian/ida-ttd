#include "debugger/memory_reader.h"
#include "core/diag.h"

namespace idattd
{
    void MemoryReader::bind(ModuleRegistry *modules)
    {
        reset();
        m_modules = modules;
    }

    void MemoryReader::reset()
    {
        m_modules = nullptr;
        // The scratch buffer keeps its capacity on purpose: it is sized by the
        // largest read so far.
        m_known.clear();
    }

    ssize_t MemoryReader::read(ITraceCursor *playhead, size_t *nbytes, ea_t ea, void *buffer, size_t size)
    {
        qstring what;
        what.sprnt("%a+%llX", ea, (uint64_t)size);
        DiagTimer diag_timer("IDA read", what);
        *nbytes = 0;
        if ( playhead == nullptr || buffer == nullptr || size == 0 )
            return DRC_OK;

        uint8_t *out = (uint8_t *)buffer;
        memset(out, 0, size);

        // ---- 1: the recording, as the backend has it ----
        playhead->read_memory(ea, out, size, &m_known);
        uint8_t *known = m_known.data();
        size_t resolved_end = 0;     // one past the last byte resolved
        for ( size_t i = 0; i < size; i++ )
        {
            if ( known[i] == ITTD_KNOWN_YES )
                resolved_end = i + 1;
            else
                out[i] = 0;          // placeholder or hole: zero until something better
        }

        // ---- 2: the on-disk image fills the gaps ----
        //
        // Placeholders are a gap here: the whole point is to give the image a
        // chance to supply what the engine could not.
        size_t o = 0;
        while ( o < size )
        {
            if ( known[o] == ITTD_KNOWN_YES )
            {
                o++;
                continue;
            }
            // Measure the contiguous gap so an image run cannot clobber recorded
            // bytes.
            size_t gap = 0;
            while ( o + gap < size && known[o + gap] != ITTD_KNOWN_YES )
                gap++;

            ea_t              base = BADADDR;
            const ModuleImage *img = m_modules != nullptr ? m_modules->image_for(ea + o, base) : nullptr;
            if ( img == nullptr )
            {
                o += gap;            // not image-backed: the gap stays as it is
                continue;
            }
            // Fill the gap one image run at a time (a run stops at a section edge).
            size_t g = 0;
            while ( g < gap )
            {
                uint32_t rva = (uint32_t)((uint64_t)(ea + o + g) - (uint64_t)base);
                size_t run = read_module_image_rva(*img, rva, out + o + g, gap - g);
                if ( run == 0 )
                {
                    g++;             // zero-fill tail / unmapped rva
                    continue;
                }
                for ( size_t i = 0; i < run; i++ )
                    known[o + g + i] = ITTD_KNOWN_YES;
                if ( o + g + run > resolved_end )
                    resolved_end = o + g + run;
                g += run;
            }
            o += gap;
        }

        // ---- 3: the backend's placeholder zeros, now that nothing better did ----
        //
        // What the engine says about memory it knows is mapped: heap and stack
        // pages with no value at this position must still read as zeros rather
        // than as a failed read.
        for ( size_t i = 0; i < size; i++ )
            if ( known[i] == ITTD_KNOWN_PLACEHOLDER && i + 1 > resolved_end )
                resolved_end = i + 1;

        *nbytes = resolved_end;
        // Nothing at this address is recorded, rebuilt or image-backed: it is
        // unmapped or unknown memory. Report a read failure rather than a
        // silent zero-fill (see the header).
        return resolved_end == 0 ? DRC_FAILED : DRC_OK;
    }

    bool MemoryReader::reconstruct(ITraceCursor *playhead, ea_t lo, ea_t hi)
    {
        if ( playhead == nullptr || hi <= lo )
            return false;
        // A replay from the start of the recording on a replay engine: it can
        // take a while, and it cannot be interrupted.
        show_wait_box("HIDECANCEL\nReconstructing memory from recorded writes...");
        bool got = playhead->rebuild_range(lo, hi, false) > 0;
        hide_wait_box();
        return got;
    }

    size_t MemoryReader::reread(ITraceCursor *playhead, ea_t lo, ea_t hi)
    {
        if ( playhead == nullptr || lo >= hi )
            return 0;
        show_wait_box("HIDECANCEL\nReconstructing memory from recorded writes...");
        size_t got = playhead->rebuild_range(lo, hi, true);
        hide_wait_box();
        return got;
    }
}
