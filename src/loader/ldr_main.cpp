// ---------------------------------------------------------------------------
// ida-ttd trace loader
//
// Lets IDA open a recording (a Microsoft TTD .run, or anything an installed
// backend reads) as a file, with no copy of the recorded binary on disk. The
// program's PE headers and section bytes are read from the recording, at the
// position where it was mapped, and laid down as IDA segments at the address
// it really occupied.
//
// A separate binary from the plugin: IDA finds loaders (LDSC) under loaders/
// and plugins (PLUGIN) under plugins/, and one file in both places would be
// loaded twice, with two copies of every global.
//
// The loader leaves a database plus a trace_link record naming the
// recording, so the plugin can offer to replay it. It never touches the
// debugger.
// ---------------------------------------------------------------------------
#include "common/pch.h"
// idaldr.h's validate_array_count trips C4018/C4267; silenced around the SDK
// include only.
#pragma warning(push)
#pragma warning(disable: 4018 4267)
#include <idaldr.h>
#pragma warning(pop)
#include <lines.hpp>
#include <segregs.hpp>

#include "common/trace_link.h"
#include "common/symbols.h"
#include "core/backend_module.h"
#include "core/backend_registry.h"
#include "core/guest_view.h"
#include "analysis/query_runner.h"

using namespace idattd;

// The path accept_file was given, as load_file's fallback (load_file gets no
// file name; the database's input path comes first). IDA calls accept_file
// while building the format list, then load_file, so the last value is right.
static qstring g_accepted_path;

// The backend that reads 'path'. Loads the backend modules on first use,
// without installing a log callback: IDA unloads this DLL after loading, and
// the backend DLLs (shared with the plugin) stay. load_file attaches the log
// only for its own work and detaches it before returning.
static ITraceBackend *backend_for(const char *path)
{
    load_backend_modules(false);
    return BackendRegistry::instance().for_file(path);
}

// Whether a file could be a recording some backend reads, judged without
// loading any backend: accept_file sees every file IDA opens, and loading the
// backend DLLs (Sogen's is large) for each .exe would be slow and would map
// code nobody asked for. The ABI has no way to learn a backend's signature
// before loading it, so the known formats are listed here: Sogen's .sogttd,
// whose header starts "SOGTTD" followed by a version digit and a NUL. A new
// backend's format needs a line here to be opened through File > Open.
static bool may_be_backend_recording(const char *filename, const char *head, size_t n)
{
    if ( n >= 6 && memcmp(head, "SOGTTD", 6) == 0 )
        return true;
    const char *ext = filename != nullptr ? strrchr(filename, '.') : nullptr;
    return ext != nullptr && _stricmp(ext, ".sogttd") == 0;
}

static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *filename)
{
    // Runs for every file IDA opens, so it must stay cheap. A .run is known
    // by its six magic bytes without loading anything (least of all
    // TTDReplay.dll); anything else whose name or header looks like a known
    // backend format goes to the backends' can_open, which only reads a
    // signature.
    char magic[8] = { 0 };
    qlseek(li, 0, SEEK_SET);
    ssize_t got = qlread(li, magic, sizeof(magic));
    bool is_run = got >= 6 && memcmp(magic, "TTDLog", 6) == 0;

    ITraceBackend *b = nullptr;
    if ( !is_run )
    {
        if ( filename == nullptr || !qfileexist(filename)
          || !may_be_backend_recording(filename, magic, got > 0 ? (size_t)got : 0) )
            return 0;
        b = backend_for(filename);
        if ( b == nullptr )
            return 0;
    }

    if ( filename != nullptr )
        g_accepted_path = filename;

    if ( is_run )
        *fileformatname = "Microsoft TTD trace (.run)";
    else
        fileformatname->sprnt("%s recording", b->display_name());
    *processor      = "metapc";
    // ACCEPT_FIRST puts this above IDA's "Binary file" entry, the only other
    // format that claims a trace.
    return 1 | ACCEPT_FIRST;
}

// Where the trace is: the input file path, or the stashed name when that path
// does not exist (an archive member name, for instance).
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
    // A section with none of the three is malformed; keep it readable.
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

// Copy the bytes of [lo, hi) the recording really has into the database.
// Placeholders (mapped memory with no recorded value) are skipped: zeros would
// claim a value nobody saw, while an unloaded byte shows as what it is.
static size_t fill_from_trace(ITraceCursor *cur, ea_t lo, ea_t hi)
{
    static const size_t PAGE = 0x1000;
    uint8_t buf[PAGE];
    std::vector<uint8_t> known;
    size_t total = 0;

    for ( ea_t a = lo; a < hi; )
    {
        size_t want = (size_t)qmin((uint64_t)PAGE - (a & (PAGE - 1)), (uint64_t)(hi - a));
        memset(buf, 0, want);
        cur->read_memory(a, buf, want, &known);
        // A backend that cannot read memory leaves 'known' as it was.
        if ( known.size() < want )
        {
            a += want;
            continue;
        }
        for ( size_t i = 0; i < want; )
        {
            if ( known[i] != ITTD_KNOWN_YES )
            {
                i++;
                continue;
            }
            size_t j = i;
            while ( j < want && known[j] == ITTD_KNOWN_YES )
                j++;
            mem2base(buf + i, a + i, a + j, -1);   // -1: these bytes have no file offset
            total += j - i;
            i = j;
        }
        a += want;
    }
    return total;
}

// Whether the recording has this address's bytes at the cursor's position.
// Real code is never 64 zero bytes, so a placeholder page does not count.
static bool image_readable_here(ITraceCursor *cur, ea_t ea)
{
    uint8_t b[64] = { 0 };
    std::vector<uint8_t> known;
    cur->read_memory(ea, b, sizeof(b), &known);
    if ( known.size() < sizeof(b) )
        return false;
    for ( size_t i = 0; i < sizeof(b); i++ )
        if ( known[i] == ITTD_KNOWN_YES && b[i] != 0 )
            return true;
    return false;
}

static bool is_exe(const qstring &name)
{
    size_t n = name.length();
    return n > 4 && _stricmp(name.c_str() + n - 4, ".exe") == 0;
}

// The recorded program: the first .exe mapped (only system DLLs come earlier;
// a Sogen recording maps win32u first), else the backend's main module, else
// the first module.
static const ModuleInfo *pick_main_module(ITraceBackend *backend,
                                          const std::vector<ModuleInfo> &mods)
{
    auto when = [](const ModuleInfo &m)
    {
        return m.loaded.is_valid() ? m.loaded : Position::begin();
    };
    const ModuleInfo *best = nullptr;
    for ( const ModuleInfo &m : mods )
        if ( is_exe(m.name) && (best == nullptr || when(m) < when(*best)) )
            best = &m;
    if ( best != nullptr )
        return best;

    const char *named = backend->info().main_module.c_str();
    for ( const ModuleInfo &m : mods )
        if ( named[0] != '\0' && _stricmp(m.name.c_str(), named) == 0 )
            return &m;
    return mods.empty() ? nullptr : &mods.front();
}

// loader_failure() longjmps, so no destructor runs. A recording left open stays
// locked for the session, so fail() releases it first. The handles live here,
// not on load_file's stack, so they are not in a frame the longjmp abandons.
static ITraceBackend *g_backend = nullptr;
static CursorPtr      g_cursor;

static void release_trace()
{
    g_cursor.reset();
    if ( g_backend != nullptr )
        g_backend->close();
    g_backend = nullptr;
    // Nothing of the backend runs on after this, so its log can be taken
    // back and what it queued printed while this DLL is still loaded.
    detach_backend_log();
}

AS_PRINTF(1, 2) static void fail(const char *format, ...)
{
    qstring m;
    va_list va;
    va_start(va, format);
    m.vsprnt(format, va);
    va_end(va);

    release_trace();
    loader_failure("%s", m.c_str());
}

void idaapi load_file(linput_t * /*li*/, ushort neflags, const char *fileformatname)
{
    // The processor owns segment defaults, so it is set before any segment.
    // With SETPROC_LOADER a failure does not return.
    set_processor_type("metapc", SETPROC_LOADER);

    qstring path = trace_file_path();
    if ( path.empty() || !qfileexist(path.c_str()) )
        loader_failure("Cannot find the trace file to load.");

    ITraceBackend *backend = backend_for(path.c_str());
    if ( backend == nullptr )
        loader_failure("No installed backend reads %s.", path.c_str());
    // The backend's diagnostics (index building can take minutes) reach the
    // output window during the load. Lines from other threads are only
    // queued, never posted as UI requests, which could run after IDA unloads
    // this DLL; release_trace() detaches the log and prints them, on every
    // way out (fail() calls it too).
    attach_backend_log(false);
    qstring err;
    if ( !backend->open(path.c_str(), &err) )
        fail("%s", err.c_str());
    g_backend = backend;

    std::vector<ModuleInfo> mods = backend->modules();
    const ModuleInfo *main = pick_main_module(backend, mods);
    if ( main == nullptr )
        fail("The trace records no modules, so there is no image to load.");
    Position mainPos = main->loaded.is_valid() ? main->loaded : backend->info().first;

    ea_t        mainBase = main->base;
    std::string mainPath = main->path.empty() ? main->name.c_str() : main->path.c_str();
    std::string mainName = main->name.c_str();

    // ---- preparation ----------------------------------------------------
    //
    // A Microsoft trace needs its memory index to read the image, and building
    // it is uninterruptible and can take minutes, so ask. Declining still gives
    // correct addresses, names and permissions (no bytes); the plugin builds
    // the index when the replay starts.
    bool haveIndex = backend->prepared();
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
            // Nothing may longjmp while a wait box or worker is alive;
            // prepare_backend() returns with both gone.
            haveIndex = prepare_backend(backend);
        }
    }

    g_cursor = backend->make_cursor();
    CursorPtr &cur = g_cursor;
    if ( !cur )
        fail("Failed to create a cursor over the trace.");
    cur->seek(mainPos);

    // ---- the recorded image's own headers --------------------------------
    GuestPeInfo pe;
    bool havePe = read_guest_pe_info(guest_read(cur.get()), mainBase, &pe);

    // Bitness from the optional header magic, not the recording machine: a
    // 32-bit program recorded on x64 would otherwise get the wrong register
    // table.
    bool is64 = havePe ? pe.is64 : ((uint64_t)mainBase > 0xFFFFFFFFull);
    if ( !havePe )
    {
        msg("[ida-ttd] could not read %s's PE headers out of the recording; "
            "assuming %d-bit from its load address.\n", mainName.c_str(), is64 ? 64 : 32);
    }

    // Read the image where it was mapped, the right static baseline. But a
    // recording may hold memory only once accessed, and nothing is touched
    // yet when a module appears; if the entry point reads back empty, use the
    // end of the recording, by which time all executed code has been seen.
    if ( havePe && pe.entry_rva != 0 && haveIndex
      && !image_readable_here(cur.get(), mainBase + pe.entry_rva) )
    {
        cur->seek(backend->info().last);
        if ( image_readable_here(cur.get(), mainBase + pe.entry_rva) )
        {
            msg("[ida-ttd] %s is not recorded at the position it was mapped; "
                "reading it from the end of the recording instead.\n",
                mainName.c_str());
        }
        else
        {
            cur->seek(mainPos);      // no better anywhere; keep the baseline
        }
    }

    inf_set_app_bitness(is64 ? 64 : 32);
    // f_PE, not f_LOADER: the PDB plugin and the x86 module gate behaviour on
    // it (symbols, MS calling conventions), and the debugger copies it into
    // debugger_t::filetype.
    inf_set_filetype(f_PE);
    inf_set_baseaddr(0);
    inf_set_dll(false);
    set_imagebase(mainBase);
    set_compiler_id(COMP_MS);
    // The Windows SDK type library, as IDA's PE loader would choose. Left alone
    // IDA picked the kernel DDK's (ntddk64_win7), which has no user-mode API,
    // so resolved calls got no prototypes. A recording is always user mode.
    add_til(is64 ? "mssdk64_win10" : "mssdk_win10", ADDTIL_DEFAULT);

    // ---- segments --------------------------------------------------------
    // One flat selector for the whole image.
    sel_t sel      = setup_selector(0);
    // The smaller of the PE's SizeOfImage and the engine's module size: a
    // corrupt or hostile header must not stretch the segments past what the
    // recording mapped.
    uint64_t imageSize = main->size;
    if ( havePe && pe.size_of_image != 0 )
        imageSize = imageSize != 0 ? qmin((uint64_t)pe.size_of_image, (uint64_t)imageSize)
                                   : (uint64_t)pe.size_of_image;
    ea_t  imageEnd = mainBase + (ea_t)imageSize;
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
        // SFL_LOADER: the plugin uses it to tell segments that survive the
        // session from debugger segments.
        si.set_loader_segm(true);
        // Sparse only where nothing was loaded; mem2base already made the
        // loaded ranges dense.
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
            // Clamp to the first section, which would otherwise truncate or
            // destroy the header segment on a malformed SizeOfHeaders.
            ea_t hdrEnd = mainBase + pe.size_of_headers;
            ea_t first  = mainBase + pe.sections[0].va;
            if ( hdrEnd > first )
                hdrEnd = first;
            // And to the image, like every section: a hostile SizeOfHeaders
            // with a far first section would cover other modules' memory
            // (and read it page by page from the recording).
            if ( hdrEnd > imageEnd )
                hdrEnd = imageEnd;
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
            if ( lo >= imageEnd )
                continue;
            // Clamp a section running into the next one above it, so
            // segments never overlap. The next by address, not by table
            // order: a malformed image can list them out of order.
            for ( size_t k = 0; k < pe.sections.size(); k++ )
            {
                ea_t next = mainBase + pe.sections[k].va;
                if ( next > lo && hi > next )
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
        // No readable section table: one segment over the recorded extent.
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

    // Export names come for free while a cursor is open where the module is
    // mapped; without them the database has no structure until a replay.
    if ( haveIndex && (neflags & NEF_MINI) == 0 )
    {
        size_t named = apply_module_exports(guest_read(cur.get()), mainBase, is64);
        if ( named != 0 )
            msg("[ida-ttd] named %d export(s) of %s from the recording.\n",
                (int)named, mainName.c_str());
    }

    // ---- provenance -------------------------------------------------------
    //
    // The input path becomes the recorded module's path, not the recording's:
    // the title bar shows it, and IDA passes it to ev_start_process, where
    // TraceManager matches its base name against the trace's modules.
    set_root_filename(mainPath.c_str());
    create_filename_cmt();
    add_pgm_cmt("Trace:           %s (%s)", path.c_str(), backend->display_name());
    add_pgm_cmt("Recorded module: %s", mainPath.c_str());
    add_pgm_cmt("Recorded base:   %a, size %08X", mainBase, (uint32)main->size);

    TraceLink link;
    link.trace_path  = path;
    link.module_path = mainPath.c_str();
    link.module_name = mainName.c_str();
    link.module_base = mainBase;
    link.module_size = main->size;
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

    // The plugin opens the recording again when the replay starts.
    release_trace();
}

// The bytes came from recorded memory at their real address, so there are no
// fixups to patch when a segment moves. A null here would tell IDA this loader
// cannot move segments at all.
static int idaapi move_segm(ea_t, ea_t, asize_t, const char *)
{
    return 1;
}

loader_t LDSC =
{
    IDP_INTERFACE_VERSION,
    0,                  // no LDRF_RELOAD: reloading bytes from a recording is meaningless
    accept_file,
    load_file,
    nullptr,            // save_file: a database cannot be written back as a recording
    move_segm,
    nullptr,            // process_archive
};
