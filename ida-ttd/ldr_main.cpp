// ---------------------------------------------------------------------------
// ida-ttd .run loader
//
// Lets IDA open a Microsoft Time Travel Debugging recording (.run) as a file in
// its own right, with no copy of the recorded binary on disk. The recorded
// program's image is read back out of the recording itself -- its PE headers and
// section bytes, at the position where the loader mapped it -- and laid down as
// ordinary IDA segments at the address it really occupied.
//
// This is a separate binary from the plugin: IDA finds loaders by looking for an
// exported LDSC in DLLs under loaders/, and plugins by looking for PLUGIN under
// plugins/. One file cannot sit in both places without being loaded twice, with
// two copies of every global fighting over the debugger pointer.
//
// What the loader leaves behind is a database plus a small record (trace_link)
// naming the recording, so the plugin can offer to start replaying it. The
// loader itself never touches the debugger.
// ---------------------------------------------------------------------------
#include "pch.h"
// idaldr.h's validate_array_count template trips C4018/C4267 at this project's
// warning level. It is SDK code we do not control, so the warnings are silenced
// around the include only -- our own code still compiles at Level3.
#pragma warning(push)
#pragma warning(disable: 4018 4267)
#include <idaldr.h>
#pragma warning(pop)
#include <lines.hpp>
#include <segregs.hpp>

#include "trace_open.h"
#include "trace_link.h"
#include "symbols.h"

using namespace TTD;
using namespace TTD::Replay;
using namespace idattd;

// The path accept_file was shown, kept as a fallback for load_file.
//
// accept_file is given the file name; load_file is not. The database's input
// path is the primary source there, and this is the belt to its braces: IDA
// calls accept_file for every loader while building the format list, then
// load_file for the one the user picked, so the last value stashed here is ours.
static qstring g_accepted_path;

static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *filename)
{
    // Magic bytes only. This runs for every file IDA is asked to open, so it
    // must not pull TTDReplay.dll into the process just to answer "no" -- which
    // is also why the trace is not opened with the replay engine until
    // load_file. TraceManager::on_start_process validates the same six bytes.
    char magic[6];
    qlseek(li, 0, SEEK_SET);
    if ( qlread(li, magic, sizeof(magic)) != sizeof(magic) )
        return 0;
    if ( memcmp(magic, "TTDLog", sizeof(magic)) != 0 )
        return 0;

    if ( filename != nullptr )
        g_accepted_path = filename;

    *fileformatname = "Microsoft TTD trace (.run)";
    *processor      = "metapc";
    // ACCEPT_FIRST puts this above IDA's always-present "Binary file" entry in
    // the load dialog, which is the only other thing that will claim a .run.
    return 1 | ACCEPT_FIRST;
}

// Where the .run actually is. INF_INPUT_FILE_PATH is set before load_file runs;
// the stashed name covers the case where it is not (an archive member name, for
// instance, which names a file that does not exist).
static qstring trace_file_path()
{
    char buf[QMAXPATH];
    if ( get_input_file_path(buf, sizeof(buf)) > 0 && qfileexist(buf) )
        return qstring(buf);
    return g_accepted_path;
}

// Permissions and class for one PE section, from its characteristics.
static void section_attrs(uint32_t chars, uint32_t rawsize, uchar *perm, const char **sclass)
{
    uchar p = 0;
    if ( (chars & IMAGE_SCN_MEM_EXECUTE) != 0 ) p |= SEGPERM_EXEC;
    if ( (chars & IMAGE_SCN_MEM_READ)    != 0 ) p |= SEGPERM_READ;
    if ( (chars & IMAGE_SCN_MEM_WRITE)   != 0 ) p |= SEGPERM_WRITE;
    // A section that claims none of the three is malformed rather than
    // inaccessible; treat it as readable so its bytes are still browsable.
    if ( p == 0 )
        p = SEGPERM_READ;
    *perm = p;

    if ( (chars & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0 )
        *sclass = CLASS_CODE;
    else if ( rawsize == 0 || (chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 )
        *sclass = CLASS_BSS;
    else if ( (chars & IMAGE_SCN_MEM_WRITE) == 0 )
        *sclass = CLASS_CONST;
    else
        *sclass = CLASS_DATA;
}

// Copy [lo, hi) out of the recording into the database.
//
// Two things make this more than a loop around QueryMemoryBuffer.
//
// TTD only records memory that was actually touched, and QueryMemoryBuffer
// returns only the contiguous run that begins exactly at the address asked for
// -- it does not skip holes -- so a hole is stepped over a page at a time rather
// than ending the copy.
//
// A non-zero result also does not mean the bytes are real. For a page the engine
// knows is mapped but has no recorded value for, every aggressive policy returns
// the requested length filled with zeros rather than an error or a short read.
// ThreadLocal returns nothing at all for memory that was not genuinely recorded,
// so an all-zero page is confirmed against it before being kept.
static size_t fill_from_trace(ICursorView *cur, ea_t lo, ea_t hi)
{
    static const size_t PAGE = 0x1000;
    uint8_t page[PAGE];
    uint8_t probe[PAGE];
    size_t  total = 0;

    for ( ea_t a = lo; a < hi; a += PAGE )
    {
        size_t want = (size_t)qmin((uint64_t)PAGE, (uint64_t)(hi - a));

        MemoryBuffer mb = cur->QueryMemoryBuffer(
            GuestAddress{ (uint64_t)a }, BufferView{ page, want },
            QueryMemoryPolicy::GloballyAggressive);
        size_t got = mb.Memory.Size;
        if ( got == 0 )
            continue;                       // nothing here at all

        bool all_zero = true;
        for ( size_t k = 0; k < got; k++ )
            if ( page[k] != 0 )
            {
                all_zero = false;
                break;
            }

        if ( all_zero )
        {
            // Either a recorded run of zeros or the engine's "this page exists,
            // here is zero" placeholder. Only ThreadLocal can tell them apart.
            MemoryBuffer tl = cur->QueryMemoryBuffer(
                GuestAddress{ (uint64_t)a }, BufferView{ probe, got },
                QueryMemoryPolicy::ThreadLocal);
            if ( tl.Memory.Size == 0 )
                continue;                   // placeholder: leave it out
        }

        mem2base(page, a, a + got, -1);     // -1: these bytes have no file offset
        total += got;
    }
    return total;
}

// Does the recording actually have this address's bytes at the cursor's
// position? Used to choose where to read the image from, so the same
// zero-fill-looks-like-success trap that fill_from_trace guards against does not
// decide the read position either. Real code is never 64 zero bytes.
static bool image_readable_here(ICursorView *cur, ea_t ea)
{
    uint8_t b[64] = { 0 };
    MemoryBuffer mb = cur->QueryMemoryBuffer(
        GuestAddress{ (uint64_t)ea }, BufferView{ b, sizeof(b) },
        QueryMemoryPolicy::GloballyAggressive);
    for ( size_t i = 0; i < mb.Memory.Size; i++ )
        if ( b[i] != 0 )
            return true;
    return false;
}

// The module the recording is of.
//
// The plugin's convention is element 0 of the engine's module list, but the SDK
// documents no ordering and the whole database hangs off this choice, so prefer
// the module with the earliest load event: the first image mapped is the program
// being recorded.
static const Module *pick_main_module(IReplayEngine *engine, Position *load_pos)
{
    *load_pos = Position::Min;

    size_t nev = engine->GetModuleLoadedEventCount();
    const ModuleLoadedEvent *evs = engine->GetModuleLoadedEventList();
    const Module *best = nullptr;
    for ( size_t i = 0; i < nev; i++ )
    {
        if ( evs[i].pModule == nullptr )
            continue;
        if ( best == nullptr || evs[i].Position < *load_pos )
        {
            best      = evs[i].pModule;
            *load_pos = evs[i].Position;
        }
    }
    if ( best != nullptr )
        return best;

    // No load events at all (a trace that starts mid-execution). Fall back to
    // the plugin's convention and read the headers wherever we can.
    *load_pos = engine->GetFirstPosition();
    return engine->GetModuleCount() > 0 ? &engine->GetModuleList()[0] : nullptr;
}

// loader_failure() does not return -- it longjmps -- so no destructor between
// here and IDA's handler runs. That matters for the replay engine in
// particular: leaking it keeps the .run file open for the rest of the session,
// so a user who fixes the problem and tries again cannot even move the file.
// This releases what we hold, then fails.
static UniqueReplayEngine *g_engine = nullptr;
static UniqueCursor       *g_cursor = nullptr;

AS_PRINTF(1, 2) static void fail(const char *format, ...)
{
    qstring m;
    va_list va;
    va_start(va, format);
    m.vsprnt(format, va);
    va_end(va);

    if ( g_cursor != nullptr ) g_cursor->reset();
    if ( g_engine != nullptr ) g_engine->reset();
    g_cursor = nullptr;
    g_engine = nullptr;

    loader_failure("%s", m.c_str());
}

void idaapi load_file(linput_t * /*li*/, ushort neflags, const char *fileformatname)
{
    // The processor module owns the segment defaults, so it has to be chosen
    // before any segment or byte is created. With SETPROC_LOADER this reports
    // its own failure and does not return.
    set_processor_type("metapc", SETPROC_LOADER);

    qstring path = trace_file_path();
    if ( path.empty() || !qfileexist(path.c_str()) )
        loader_failure("Cannot find the trace file to load.");

    static IdaErrorReporting err;
    auto made = MakeReplayEngine();
    UniqueReplayEngine engine = std::move(made.first);
    if ( made.second != 0 || !engine )
    {
        loader_failure("Failed to create the TTD replay engine (0x%08X).\n\n"
                       "TTDReplay.dll and TTDReplayCPU.dll must be next to ida.exe.",
                       made.second);
    }
    g_engine = &engine;
    engine->RegisterDebugModeAndLogging(DebugModeType::None, &err);
    if ( !engine->Initialize(to_wstring(path.c_str()).c_str()) )
        fail("Failed to load the trace: %s", path.c_str());

    Position      mainPos;
    const Module *main = pick_main_module(engine.get(), &mainPos);
    if ( main == nullptr )
        fail("The trace records no modules, so there is no image to load.");

    ea_t        mainBase = (ea_t)(uint64_t)main->Address;
    std::string mainPath = to_utf8(main->pName, main->NameLength);
    std::string mainName = base_name(mainPath);

    // ---- the index ------------------------------------------------------
    //
    // Reading the image out of the recording needs one, and building it is
    // uninterruptible and can run for minutes. That is not something to start
    // without asking during a File > Open. Declining still produces a useful
    // database -- correct addresses, names and permissions, no bytes -- and the
    // plugin will build the index when the user starts the replay.
    bool haveIndex = engine->GetIndexStatus() == IndexStatus::IndexFileLoaded;
    if ( !haveIndex && (neflags & NEF_MINI) == 0 )
    {
        int r = ask_yn(ASKBTN_YES,
                       "This trace has no index yet.\n\n"
                       "Building one can take several minutes and cannot be "
                       "interrupted, but without it the recorded program's bytes "
                       "cannot be read.\n\n"
                       "Build the index now?\n"
                       "(No: create the database with the right addresses, names "
                       "and permissions but no code. The index is then built when "
                       "you start the replay.)");
        if ( r == ASKBTN_CANCEL )
            fail("Loading the trace was cancelled.");
        if ( r == ASKBTN_YES )
        {
            // loader_failure() longjmps, so nothing here may fail while the wait
            // box is up or the worker thread is alive. build_trace_index joins
            // its worker and hides its box before returning.
            build_trace_index(engine.get());
            haveIndex = true;
        }
    }

    UniqueCursor cur{ engine->NewCursor() };
    g_cursor = &cur;
    if ( !cur )
        fail("Failed to create a replay cursor over the trace.");
    cur->SetPosition(mainPos);
    cur->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);

    // ---- the recorded image's own headers --------------------------------
    GuestPeInfo pe;
    bool havePe = read_guest_pe_info(cur.get(), mainBase, &pe);

    // Bitness comes from the optional header magic. It must not come from the
    // engine's SystemInfo: that describes the recording machine, so a 32-bit
    // program recorded on an x64 box would report itself as 64-bit and every
    // register read afterwards would use the wrong register table.
    bool is64 = havePe ? pe.is64 : ((uint64_t)main->Address > 0xFFFFFFFFull);
    if ( !havePe )
    {
        msg("[ida-ttd] could not read %s's PE headers out of the recording; "
            "assuming %d-bit from its load address.\n", mainName.c_str(), is64 ? 64 : 32);
    }

    // Where to read the image from.
    //
    // The natural answer is the position at which the loader mapped it, and that
    // is the right static baseline. But TTD records memory as it is accessed,
    // and at the instant a module appears nothing in it has been touched, so the
    // engine may have nothing to attribute there. When the entry point reads
    // back as nothing, take the end of the recording instead, by which point
    // everything the program executed has been seen.
    if ( havePe && pe.entry_rva != 0 && haveIndex
      && !image_readable_here(cur.get(), mainBase + pe.entry_rva) )
    {
        cur->SetPosition(engine->GetLastPosition());
        if ( image_readable_here(cur.get(), mainBase + pe.entry_rva) )
        {
            msg("[ida-ttd] %s is not recorded at the position it was mapped; "
                "reading it from the end of the recording instead.\n",
                mainName.c_str());
        }
        else
        {
            cur->SetPosition(mainPos);      // no better anywhere; keep the baseline
        }
    }

    inf_set_app_bitness(is64 ? 64 : 32);
    // f_PE rather than f_LOADER: the PDB plugin and the x86 module both gate
    // real behaviour on it (symbol loading, MS calling conventions), and the
    // debugger backend copies it into debugger_t::filetype.
    inf_set_filetype(f_PE);
    inf_set_baseaddr(0);
    inf_set_dll(false);
    set_imagebase(mainBase);
    set_compiler_id(COMP_MS);

    // ---- segments --------------------------------------------------------
    // One flat selector for the whole image: this is a 32/64-bit PC program,
    // not a segmented one.
    sel_t sel      = setup_selector(0);
    ea_t  imageEnd = mainBase + (ea_t)(havePe && pe.size_of_image != 0
                                     ? pe.size_of_image : main->Size);
    int   nsegs    = 0;

    uint64_t loaded = 0;
    auto add_one = [&](ea_t lo, ea_t hi, const char *name, const char *sclass, uchar perm)
    {
        if ( hi <= lo )
            return;
        size_t got = 0;
        if ( haveIndex && (neflags & NEF_MINI) == 0 )
            got = fill_from_trace(cur.get(), lo, hi);
        loaded += got;

        segment_info_t si;
        si.start_ea = lo;
        si.end_ea   = hi;
        si.set_sel(sel);
        si.set_bitness(is64 ? 2 : 1);
        si.set_align(saRelByte);
        si.set_comb(scPub);
        si.set_perm(perm);
        si.set_name(name);
        si.set_sclass(sclass);
        // SFL_LOADER: these segments came from the file, not from a debugger.
        // The plugin relies on that distinction to tell code that survives the
        // session from code that only exists while a trace is loaded.
        si.set_loader_segm(true);
        // Sparse storage only where nothing was loaded. Where bytes were, the
        // ranges mem2base enabled are already dense and mixing the two buys
        // nothing.
        int flags = ADDSEG_NOSREG | ADDSEG_QUIET;
        if ( got == 0 )
            flags |= ADDSEG_SPARSE;
        if ( add_segment_ex(&si, flags) )
            nsegs++;
    };

    if ( havePe && !pe.sections.empty() )
    {
        if ( pe.size_of_headers != 0 )
        {
            // Clamp to the first section. A malformed SizeOfHeaders that runs
            // past it would otherwise make that section truncate or destroy the
            // header segment when it is added.
            ea_t hdrEnd = mainBase + pe.size_of_headers;
            ea_t first  = mainBase + pe.sections[0].va;
            if ( hdrEnd > first )
                hdrEnd = first;
            add_one(mainBase, hdrEnd, "HEADER", CLASS_CONST, SEGPERM_READ);
        }

        for ( size_t i = 0; i < pe.sections.size(); i++ )
        {
            const GuestPeSection &s = pe.sections[i];
            uint32_t span = s.vsize != 0 ? s.vsize : s.rawsize;
            if ( span == 0 )
                continue;
            ea_t lo = mainBase + s.va;
            ea_t hi = lo + span;
            // Sections are given in ascending order; clamp a section that runs
            // into the next one so add_segment_ex is never asked to overlap.
            if ( i + 1 < pe.sections.size() )
            {
                ea_t next = mainBase + pe.sections[i + 1].va;
                if ( hi > next )
                    hi = next;
            }
            if ( hi > imageEnd )
                hi = imageEnd;

            uchar       perm   = 0;
            const char *sclass = CLASS_DATA;
            section_attrs(s.characteristics, s.rawsize, &perm, &sclass);
            add_one(lo, hi, s.name[0] != '\0' ? s.name : ".seg", sclass, perm);
        }
    }
    else
    {
        // No readable section table: one segment over the module's recorded
        // extent is still far better than nothing.
        add_one(mainBase, imageEnd, mainName.c_str(), CLASS_CODE,
                SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC);
    }
    set_default_dataseg(sel);

    // ---- entry point ------------------------------------------------------
    if ( havePe && pe.entry_rva != 0 )
    {
        ea_t entry = mainBase + pe.entry_rva;
        inf_set_start_ea(entry);
        inf_set_start_ip(entry);
        inf_set_start_cs(sel);
        add_entry(entry, entry, "start", true);
    }

    // Names and function bounds we can have for free, since a cursor is already
    // open at a position where the module is mapped. Without this the database
    // is bytes with no structure until the debugger attaches.
    if ( haveIndex && (neflags & NEF_MINI) == 0 )
    {
        size_t named = apply_module_exports(cur.get(), mainBase, is64);
        if ( named != 0 )
            msg("[ida-ttd] named %d export(s) of %s from the recording.\n",
                (int)named, mainName.c_str());
    }

    // ---- provenance -------------------------------------------------------
    //
    // The database's input path becomes the RECORDED module's path rather than
    // the .run. That is what the title bar should say, and it also makes the
    // debugger backend's "is this the module the database is of?" test work
    // unchanged: IDA passes this path to ev_start_process, and TraceManager
    // compares its base name against each module the trace loads.
    set_root_filename(mainPath.c_str());
    create_filename_cmt();
    add_pgm_cmt("TTD trace:       %s", path.c_str());
    add_pgm_cmt("Recorded module: %s", mainPath.c_str());
    add_pgm_cmt("Recorded base:   %a, size %08X", mainBase, (uint32)main->Size);

    TraceLink link;
    link.trace_path  = path;
    link.module_path = mainPath.c_str();
    link.module_name = mainName.c_str();
    link.module_base = mainBase;
    link.module_size = main->Size;
    link.bitness     = is64 ? 64 : 32;
    trace_link_write(link);

    msg("[ida-ttd] loaded %s from %s: %d segment(s) at %a, %d-bit, "
        "0x%llX byte(s) recovered from the recording.\n",
        mainName.c_str(), fileformatname != nullptr ? fileformatname : "a TTD trace",
        nsegs, mainBase, is64 ? 64 : 32, loaded);
    if ( loaded == 0 )
    {
        msg("[ida-ttd] the recording holds no bytes of %s at the position it was "
            "mapped, so the database has its layout but no code. Starting the "
            "replay will serve the bytes as you navigate.\n", mainName.c_str());
    }

    // Both are about to be destroyed normally; the guard must not outlive them.
    g_cursor = nullptr;
    g_engine = nullptr;
}

// Nothing in this database was relocated: the bytes came from recorded memory
// at the address they really occupied, so there are no fixups to patch when a
// segment moves. Saying so explicitly beats a null, which IDA has to treat as
// "this loader cannot move segments at all".
static int idaapi move_segm(ea_t, ea_t, asize_t, const char *)
{
    return 1;
}

loader_t LDSC =
{
    IDP_INTERFACE_VERSION,
    0,                  // no LDRF_RELOAD: reloading bytes from a .run is meaningless
    accept_file,
    load_file,
    nullptr,            // save_file: a database cannot be written back as a recording
    move_segm,
    nullptr,            // process_archive
};
