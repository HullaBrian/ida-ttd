#include "debugger/memory_reader.h"
#include "debugger/msttd_position.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    void MemoryReader::bind(IReplayEngine *engine, ModuleRegistry *modules)
    {
        reset();
        m_engine  = engine;
        m_modules = modules;
    }

    void MemoryReader::reset()
    {
        m_engine  = nullptr;
        m_modules = nullptr;
        m_cursor.reset();
        m_posValid = false;
        m_regions.clear();
        // The scratch buffers keep their capacity on purpose: they are sized by
        // the largest read so far and reallocating them per session would undo
        // the point of reusing them.
        m_filled.clear();
        m_probe.clear();
    }

    ssize_t MemoryReader::read(ICursorView *playhead,
                              size_t *nbytes, ea_t ea, void *buffer, size_t size)
    {
        *nbytes = 0;
        if ( playhead == nullptr || buffer == nullptr || size == 0 )
            return DRC_OK;

        // The read cursor is parked at the playhead, re-seeking only when the
        // position actually changed. Why it is a cursor of its own rather than
        // the execution cursor is in the header.
        if ( !m_cursor && m_engine != nullptr )
        {
            m_cursor = UniqueCursor{ m_engine->NewCursor() };
            if ( m_cursor )
                m_cursor->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);
            m_posValid = false;
        }
        // Without one of our own, fall back on the execution cursor: a degraded
        // answer beats no answer, and it is what this did before the dedicated
        // cursor existed.
        ICursorView *mc = m_cursor ? m_cursor.get() : playhead;
        if ( m_cursor )
        {
            TtdPosition cur = playhead->GetPosition();
            if ( !m_posValid || cur.Sequence != m_pos.Sequence || cur.Steps != m_pos.Steps )
            {
                m_cursor->SetPosition(cur);
                m_pos      = cur;
                m_posValid = true;
            }
        }

        // QueryMemoryBuffer only ever returns the single contiguous run that begins
        // exactly at the queried address. If that address is a "hole" (a byte TTD
        // didn't record at this position) it returns Size==0 -- and a naive single
        // call then loses every known byte further into the buffer. So fill the whole
        // range in two passes:
        //
        //   Pass 1 (authoritative): walk the range querying TTD's recorded memory,
        //   skipping over holes, so every recorded byte is delivered. This reflects
        //   the true position-in-time state, including self-modified code.
        //
        //   Pass 2 (image fallback): for bytes TTD never recorded, copy from the
        //   module's on-disk image. TTD only records accessed memory; image-backed
        //   code that was never executed on this run (the other side of a branch, a
        //   cold epilogue, the terminating ret) is in the trace at no position, yet
        //   it is right there in the file -- this is exactly what WinDbg shows. Image
        //   bytes only fill gaps; recorded bytes always win.
        static const QueryMemoryPolicy kPolicies[] = {
            QueryMemoryPolicy::GloballyAggressive,   // the cursor default; cheap first
            QueryMemoryPolicy::InFragmentAggressive, // look across the whole fragment
        };

        // What we know about each byte of the answer. The distinction between the
        // last two is the whole point of this pass: an engine that says "this page
        // is mapped, here is zero" has not told us the value, and treating that as
        // data is what stopped the image fallback from ever correcting it.
        enum : uint8_t
        {
            FILL_NONE = 0,   // nothing to serve
            FILL_REAL = 1,   // recorded, reconstructed, or read from the image
            FILL_ZERO = 2,   // the engine's zero placeholder; better may exist
        };

        uint8_t *out = (uint8_t *)buffer;
        m_filled.assign(size, FILL_NONE);    // reuses capacity; no per-call allocation
        uint8_t *filled = m_filled.data();
        size_t resolved_end = 0;     // one past the last byte we resolved (either source)

        // ---- Pass 1: recorded memory ----
        size_t off = 0;
        while ( off < size )
        {
            MemoryBuffer mb{};
            for ( QueryMemoryPolicy p : kPolicies )
            {
                mb = mc->QueryMemoryBuffer(
                    GuestAddress{ (uint64_t)(ea + off) },
                    BufferView{ out + off, size - off }, p);
                if ( mb.Memory.Size > 0 )
                    break;
            }
            if ( mb.Memory.Size > 0 )
            {
                size_t run = mb.Memory.Size;

                // A non-zero Size does not mean these bytes are real. For memory
                // the engine knows is mapped but has no value to attribute at the
                // current position -- a byte last written in an EARLIER fragment
                // is the common case -- the aggressive policies answer "here is
                // zero" rather than admitting they do not know. Accepting that as
                // an answer is what made the front of a string literal read back
                // as eight zero bytes, so IDA rendered "[+] Starting...\n" as
                // "ting...\n" and stopped following code at the first such run.
                //
                // ThreadLocal is the one policy that is honest about it, so an
                // all-zero run is only believed if ThreadLocal confirms it was
                // genuinely recorded. Unconfirmed zeros are kept as a PLACEHOLDER:
                // the image fallback below gets first refusal on them, and they
                // are only served if nothing better turns up. The probe is skipped
                // for any run with a non-zero byte in it -- zero-fill is all zeros
                // by definition -- which keeps the extra query off the hot path.
                uint8_t flag = FILL_REAL;
                bool all_zero = true;
                for ( size_t i = 0; i < run && all_zero; i++ )
                    all_zero = out[off + i] == 0;
                if ( all_zero )
                {
                    m_probe.assign(run, 0);
                    MemoryBuffer probe = mc->QueryMemoryBuffer(
                        GuestAddress{ (uint64_t)(ea + off) },
                        BufferView{ m_probe.data(), run },
                        QueryMemoryPolicy::ThreadLocal);
                    if ( probe.Memory.Size == 0 )
                        flag = FILL_ZERO;
                }

                for ( size_t i = 0; i < run; i++ )
                    filled[off + i] = flag;
                off += run;
                if ( flag == FILL_REAL )
                    resolved_end = off;
            }
            else
            {
                out[off] = 0;        // hole: leave 0 for now, later passes may fill it
                off++;
            }
        }

        // ---- Pass R: override with bytes reconstructed from recorded writes ----
        // For non-module memory the position query only zero-fills (it knows the page
        // is mapped but has no recorded value to attribute here). Where we've rebuilt
        // the real bytes from the trace's writes, those win -- they equal the live
        // value as of the reconstruction position, so this also corrects pass 1's
        // zero-fill for never-executed code (the other half of a branch, the ret).
        for ( const ReconRegion &r : m_regions )
        {
            ea_t s = ea > r.lo ? ea : r.lo;
            ea_t e = (ea + (ea_t)size) < r.hi ? (ea + (ea_t)size) : r.hi;
            for ( ea_t a = s; a < e; a++ )
            {
                size_t ri = (size_t)(a - r.lo);
                if ( !r.known[ri] )
                    continue;
                size_t oi = (size_t)(a - ea);
                out[oi]    = r.data[ri];
                filled[oi] = FILL_REAL;
                if ( oi + 1 > resolved_end )
                    resolved_end = oi + 1;
            }
        }

        // ---- Pass 2: on-disk image fills the gaps ----
        size_t o = 0;
        while ( o < size )
        {
            // Placeholder zeros are not a filled byte here: the whole point is to
            // give the image a chance to supply what the engine could not.
            if ( filled[o] == FILL_REAL )
            {
                o++;
                continue;
            }
            // Measure the contiguous gap so an image run can't clobber recorded bytes.
            size_t gap = 0;
            while ( o + gap < size && filled[o + gap] != FILL_REAL )
                gap++;

            ea_t              base = BADADDR;
            const ModuleImage *img = m_modules != nullptr
                                   ? m_modules->image_for(ea + o, base) : nullptr;
            if ( img == nullptr )
            {
                o += gap;            // not image-backed: the gap stays zero
                continue;
            }
            // Fill the gap one image-run at a time (a run stops at a section edge).
            size_t g = 0;
            while ( g < gap )
            {
                uint32_t rva = (uint32_t)((uint64_t)(ea + o + g) - (uint64_t)base);
                size_t run = read_module_image_rva(*img, rva, out + o + g, gap - g);
                if ( run == 0 )
                {
                    g++;             // zero-fill tail / unmapped rva: leave 0
                    continue;
                }
                for ( size_t i = 0; i < run; i++ )
                    filled[o + g + i] = FILL_REAL;
                if ( o + g + run > resolved_end )
                    resolved_end = o + g + run;
                g += run;
            }
            o += gap;
        }

        // ---- Pass Z: fall back on the engine's zero-fill placeholders ----
        // Nothing better turned up for these bytes, so serve the zeros after all.
        // This is what the engine says about memory it knows is mapped, and it is
        // what this function returned for them before placeholders were told apart
        // from recorded data -- heap and stack pages with no value at this position
        // must still read as zeros rather than as a failed read.
        for ( size_t i = 0; i < size; i++ )
        {
            if ( filled[i] != FILL_ZERO )
                continue;
            out[i] = 0;
            if ( i + 1 > resolved_end )
                resolved_end = i + 1;
        }

        *nbytes = resolved_end;
        // Nothing at this address is recorded, reconstructed, or image-backed: it
        // is unmapped/unknown memory. Report a read FAILURE rather than a silent
        // zero-fill -- otherwise IDA treats the whole address space (advertised as
        // one big segment) as readable and the register/stack views dereference a
        // garbage pointer into 0, then dereference that 0, ad infinitum.
        return resolved_end == 0 ? DRC_FAILED : DRC_OK;
    }

    // Build the memory layout IDA should see at the cursor's current position.
    //
    // With no reconstructed map this is what it has always been: one flat
    // read/write/execute range over user space. With a map, the regions the
    // recording actually created are reported individually, named and carrying
    // their real protection, and everything between them keeps the flat range.
    //
    // The filler is not optional. Stacks, heaps, the PEB and the TEB are never
    // created by a call we watch, so reporting only the discovered regions would
    // make IDA stop reading them and break the stack and register views. What the
    // map adds is names and honest permissions where we know them, never less
    // reachability than before.
    bool MemoryReader::reconstruct(ICursorView *playhead, ea_t lo, ea_t hi)
    {
        if ( m_engine == nullptr || playhead == nullptr || hi <= lo )
            return false;

        // hard CAP on the window. The callers derive 'hi' from segment bounds, and
        // our own memory map advertises one segment spanning the entire user address
        // space -- so a bad bound arrives here as a request to allocate terabytes,
        // which throws bad_alloc out of a plugin that does not catch it and takes
        // IDA down. A megabyte is far more than the code windows we actually ask for.
        static const uint64_t kMaxReconBytes = 1u << 20;
        if ( (uint64_t)(hi - lo) > kMaxReconBytes )
            hi = lo + (ea_t)kMaxReconBytes;

        // Already reconstructed something covering this range?
        for ( const ReconRegion &r : m_regions )
            if ( r.lo <= lo && hi <= r.hi )
                return true;

        UniqueCursor cur{ m_engine->NewCursor() };
        if ( !cur )
            return false;

        const TtdPosition target = playhead->GetPosition();

        ReconRegion reg;
        reg.lo = lo;
        reg.hi = hi;
        reg.data.assign((size_t)(hi - lo), 0);
        reg.known.assign((size_t)(hi - lo), false);

        size_t hits = 0;
        // On each recorded write touching [lo,hi), copy the just-written bytes (read
        // thread-locally from the writing thread, which definitely has them) into the
        // shadow. Replaying sequentially forward means the last write to each byte
        // before 'target' wins -- i.e. the value as of the current position. Return
        // false so the watchpoint never stops the replay.
        auto on_write = [&](ICursorView::MemoryWatchpointResult const &wp,
                            IThreadView const *t) noexcept -> bool
        {
            uint64_t a  = (uint64_t)wp.Address;
            uint64_t e  = a + wp.Size;
            uint64_t s  = a > (uint64_t)lo ? a : (uint64_t)lo;
            uint64_t en = e < (uint64_t)hi ? e : (uint64_t)hi;
            if ( s >= en )
                return false;
            uint8_t  buf[512];
            uint64_t off = s;
            while ( off < en )
            {
                size_t chunk = (size_t)((en - off) < sizeof(buf) ? (en - off) : sizeof(buf));
                MemoryBuffer mb = t->QueryMemoryBuffer(GuestAddress{ off }, BufferView{ buf, chunk });
                size_t got = mb.Memory.Size;
                if ( got == 0 )
                    break;
                for ( size_t i = 0; i < got; i++ )
                {
                    reg.data[(size_t)(off - lo) + i]  = buf[i];
                    reg.known[(size_t)(off - lo) + i] = true;
                }
                off += got;
            }
            hits++;
            return false;
        };

        MemoryWatchpointData wp{};
        wp.Address    = GuestAddress{ (uint64_t)lo };
        wp.Size       = (uint64_t)(hi - lo);
        wp.AccessMask = DataAccessMask::Write;
        cur->AddMemoryWatchpoint(wp);
        cur->SetMemoryWatchpointCallback(on_write);
        cur->SetEventMask(EventMask::MemoryWatchpoint);
        cur->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially); // chronological -> last write wins
        cur->SetPosition(TtdPosition::Min);

        show_wait_box("HIDECANCEL\nReconstructing memory from recorded writes...");
        cur->ReplayForward(target);
        hide_wait_box();

        cur->SetMemoryWatchpointCallback(nullptr, 0);

        size_t nknown = 0;
        for ( bool b : reg.known )
            if ( b )
                nknown++;
        msg("[ida-ttd] reconstructed 0x%llX-0x%llX: %u/%u byte(s) from %u write(s).\n",
            (uint64_t)lo, (uint64_t)hi, (unsigned)nknown, (unsigned)reg.data.size(), (unsigned)hits);

        if ( nknown == 0 )
            return false;
        m_regions.push_back(std::move(reg));
        return true;
    }

    size_t MemoryReader::reread(ICursorView *playhead, ea_t lo, ea_t hi)
    {
        if ( playhead == nullptr || lo >= hi )
            return 0;

        m_regions.erase(
            std::remove_if(m_regions.begin(), m_regions.end(),
                           [lo, hi](const ReconRegion &r)
                           { return r.lo < hi && lo < r.hi; }),
            m_regions.end());

        size_t recovered = 0;
        if ( reconstruct(playhead, lo, hi) )
        {
            for ( const ReconRegion &r : m_regions )
            {
                if ( r.lo >= hi || lo >= r.hi )
                    continue;
                for ( size_t i = 0; i < r.known.size(); i++ )
                    if ( r.known[i] )
                        recovered++;
            }
        }
        return recovered;
    }
}
