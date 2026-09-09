#include "symbols.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    // Read exactly 'size' bytes of guest memory; return false on a short read.
    static bool read_mem(ICursorView *c, uint64_t addr, void *buf, size_t size)
    {
        MemoryBuffer mb = c->QueryMemoryBuffer(GuestAddress{ addr }, BufferView{ buf, size });
        return mb.Memory.Size == size;
    }

    template <typename T>
    static bool read_val(ICursorView *c, uint64_t addr, T *out)
    {
        return read_mem(c, addr, out, sizeof(T));
    }

    // Read a NUL-terminated ASCII string from guest memory (bounded).
    static std::string read_cstr(ICursorView *c, uint64_t addr, size_t maxlen = 512)
    {
        std::string s;
        char chunk[64];
        while ( s.size() < maxlen )
        {
            MemoryBuffer mb = c->QueryMemoryBuffer(
                GuestAddress{ addr + s.size() }, BufferView{ chunk, sizeof(chunk) });
            if ( mb.Memory.Size == 0 )
                break;
            for ( size_t i = 0; i < mb.Memory.Size; i++ )
            {
                if ( chunk[i] == '\0' )
                    return s;
                s.push_back(chunk[i]);
            }
        }
        return s;
    }

    // Locate a module's NT headers and say which flavour they are. Shared by
    // read_guest_pe_info and resolve_export_va so the DOS/NT walk is written once.
    static bool locate_nt_headers(ICursorView *c, uint64_t base, uint64_t *nt_addr_out,
                                  bool *is64_out)
    {
        IMAGE_DOS_HEADER dos{};
        if ( !read_val(c, base, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE )
            return false;
        // e_lfanew is attacker-controlled (we analyse malware): a wild value would
        // send every read that follows somewhere unrelated.
        if ( dos.e_lfanew < 0 || (uint32_t)dos.e_lfanew > 0x10000000u )
            return false;

        uint64_t ntAddr = base + (uint32_t)dos.e_lfanew;
        uint32_t sig = 0;
        if ( !read_val(c, ntAddr, &sig) || sig != IMAGE_NT_SIGNATURE )
            return false;

        // The optional header magic sits after the signature and the file header,
        // and it -- not the recording machine's architecture -- says whether this
        // image is 32- or 64-bit.
        uint16_t magic = 0;
        if ( !read_val(c, ntAddr + 4 + sizeof(IMAGE_FILE_HEADER), &magic) )
            return false;
        if ( magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
            return false;

        *nt_addr_out = ntAddr;
        *is64_out    = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        return true;
    }

    // The export data directory of a module whose NT header is at 'ntAddr', or
    // false when it has none.
    static bool read_export_dir(ICursorView *c, uint64_t ntAddr, bool is64,
                                uint32_t *rva_out, uint32_t *size_out)
    {
        if ( is64 )
        {
            IMAGE_NT_HEADERS64 nt{};
            if ( !read_val(c, ntAddr, &nt) )
                return false;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            *rva_out  = dd.VirtualAddress;
            *size_out = dd.Size;
        }
        else
        {
            IMAGE_NT_HEADERS32 nt{};
            if ( !read_val(c, ntAddr, &nt) )
                return false;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            *rva_out  = dd.VirtualAddress;
            *size_out = dd.Size;
        }
        return *rva_out != 0 && *size_out != 0;
    }

    bool read_guest_pe_info(ICursorView *cursor, ea_t base, GuestPeInfo *out)
    {
        if ( cursor == nullptr || out == nullptr || base == BADADDR )
            return false;
        *out = GuestPeInfo();

        uint64_t b = (uint64_t)base;
        uint64_t ntAddr = 0;
        bool     is64   = false;
        if ( !locate_nt_headers(cursor, b, &ntAddr, &is64) )
            return false;

        out->is64 = is64;

        // The section table follows the optional header, whose SIZE the file
        // header states -- it is not always sizeof(IMAGE_OPTIONAL_HEADER), and
        // assuming so puts the table read a few bytes off on a hand-built image.
        IMAGE_FILE_HEADER fh{};
        if ( !read_val(cursor, ntAddr + 4, &fh) )
            return false;
        uint16_t nsections = fh.NumberOfSections;
        uint64_t sectAddr  = ntAddr + 4 + sizeof(IMAGE_FILE_HEADER) + fh.SizeOfOptionalHeader;

        if ( is64 )
        {
            IMAGE_NT_HEADERS64 nt{};
            if ( !read_val(cursor, ntAddr, &nt) )
                return false;
            out->entry_rva       = nt.OptionalHeader.AddressOfEntryPoint;
            out->size_of_image   = nt.OptionalHeader.SizeOfImage;
            out->size_of_headers = nt.OptionalHeader.SizeOfHeaders;
            out->preferred_base  = nt.OptionalHeader.ImageBase;
        }
        else
        {
            IMAGE_NT_HEADERS32 nt{};
            if ( !read_val(cursor, ntAddr, &nt) )
                return false;
            out->entry_rva       = nt.OptionalHeader.AddressOfEntryPoint;
            out->size_of_image   = nt.OptionalHeader.SizeOfImage;
            out->size_of_headers = nt.OptionalHeader.SizeOfHeaders;
            out->preferred_base  = nt.OptionalHeader.ImageBase;
        }

        // NumberOfSections is a 16-bit file field: 65535 would ask for a 2.5 MB
        // read of a module that has three sections. The format caps a loadable
        // image at 96.
        static const uint16_t kMaxSections = 96;
        if ( nsections > kMaxSections )
            nsections = kMaxSections;
        if ( nsections == 0 )
            return true;    // valid headers; a sectionless image is merely odd

        std::vector<IMAGE_SECTION_HEADER> hdrs(nsections);
        MemoryBuffer mb = cursor->QueryMemoryBuffer(
            GuestAddress{ sectAddr },
            BufferView{ hdrs.data(), (size_t)nsections * sizeof(IMAGE_SECTION_HEADER) });
        size_t got = mb.Memory.Size / sizeof(IMAGE_SECTION_HEADER);

        out->sections.reserve(got);
        for ( size_t i = 0; i < got; i++ )
        {
            const IMAGE_SECTION_HEADER &sh = hdrs[i];
            GuestPeSection s;
            memcpy(s.name, sh.Name, 8);
            s.name[8]         = '\0';
            s.va              = sh.VirtualAddress;
            s.vsize           = sh.Misc.VirtualSize;
            s.rawsize         = sh.SizeOfRawData;
            s.characteristics = sh.Characteristics;
            out->sections.push_back(s);
        }
        return true;
    }

    ea_t resolve_export_va(ICursorView *cursor, ea_t base, bool is64, const char *name)
    {
        qnotused(is64);   // the image's own header is the authority; see below
        if ( cursor == nullptr || base == BADADDR || name == nullptr || *name == '\0' )
            return BADADDR;

        uint64_t b = (uint64_t)base;
        uint64_t ntAddr = 0;
        // Trust the image over the caller: a WoW64 recording has a 32-bit and a
        // 64-bit ntdll, and the caller cannot know which one this base is.
        bool     hdr64  = false;
        if ( !locate_nt_headers(cursor, b, &ntAddr, &hdr64) )
            return BADADDR;

        uint32_t exportRva = 0, exportSize = 0;
        if ( !read_export_dir(cursor, ntAddr, hdr64, &exportRva, &exportSize) )
            return BADADDR;

        IMAGE_EXPORT_DIRECTORY exp{};
        if ( !read_val(cursor, b + exportRva, &exp) )
            return BADADDR;
        if ( exp.NumberOfNames == 0 || exp.AddressOfNames == 0
          || exp.AddressOfNameOrdinals == 0 || exp.AddressOfFunctions == 0 )
            return BADADDR;

        static const uint32_t kMaxExports = 1u << 20;
        uint32_t nNames = exp.NumberOfNames < kMaxExports ? exp.NumberOfNames : kMaxExports;
        uint32_t nFuncs = exp.NumberOfFunctions < kMaxExports ? exp.NumberOfFunctions : kMaxExports;
        if ( nNames == 0 || nFuncs == 0 )
            return BADADDR;

        std::vector<uint32_t> nameRvas(nNames);
        std::vector<uint16_t> ordinals(nNames);
        std::vector<uint32_t> funcRvas(nFuncs);

        MemoryBuffer mbN = cursor->QueryMemoryBuffer(
            GuestAddress{ b + exp.AddressOfNames },
            BufferView{ nameRvas.data(), (size_t)nNames * sizeof(uint32_t) });
        MemoryBuffer mbO = cursor->QueryMemoryBuffer(
            GuestAddress{ b + exp.AddressOfNameOrdinals },
            BufferView{ ordinals.data(), (size_t)nNames * sizeof(uint16_t) });
        MemoryBuffer mbF = cursor->QueryMemoryBuffer(
            GuestAddress{ b + exp.AddressOfFunctions },
            BufferView{ funcRvas.data(), (size_t)nFuncs * sizeof(uint32_t) });

        size_t gotNames = mbN.Memory.Size / sizeof(uint32_t);
        size_t gotOrds  = mbO.Memory.Size / sizeof(uint16_t);
        size_t gotFuncs = mbF.Memory.Size / sizeof(uint32_t);
        size_t usable   = gotNames < gotOrds ? gotNames : gotOrds;

        for ( size_t i = 0; i < usable; i++ )
        {
            uint16_t ordinal = ordinals[i];
            if ( (size_t)ordinal >= gotFuncs )
                continue;
            uint32_t funcRva = funcRvas[ordinal];
            if ( funcRva == 0 )
                continue;
            // A forwarder's "address" points back inside the export directory.
            // Returning it would leave the caller watching a string.
            if ( funcRva >= exportRva && funcRva < exportRva + exportSize )
                continue;
            if ( read_cstr(cursor, b + nameRvas[i]) != name )
                continue;
            return (ea_t)(b + funcRva);
        }
        return BADADDR;
    }

    size_t apply_module_exports(ICursorView *cursor, ea_t base, bool is64)
    {
        if ( cursor == nullptr || base == BADADDR )
            return 0;

        uint64_t b = (uint64_t)base;

        // DOS header -> NT headers offset.
        IMAGE_DOS_HEADER dos{};
        if ( !read_val(cursor, b, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE )
            return 0;

        uint64_t ntAddr = b + (uint32_t)dos.e_lfanew;

        // The export data directory location differs between PE32 and PE32+.
        uint32_t exportRva = 0;
        uint32_t exportSize = 0;
        if ( is64 )
        {
            IMAGE_NT_HEADERS64 nt{};
            if ( !read_val(cursor, ntAddr, &nt) || nt.Signature != IMAGE_NT_SIGNATURE )
                return 0;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            exportRva  = dd.VirtualAddress;
            exportSize = dd.Size;
        }
        else
        {
            IMAGE_NT_HEADERS32 nt{};
            if ( !read_val(cursor, ntAddr, &nt) || nt.Signature != IMAGE_NT_SIGNATURE )
                return 0;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            exportRva  = dd.VirtualAddress;
            exportSize = dd.Size;
        }

        if ( exportRva == 0 || exportSize == 0 )
            return 0;

        IMAGE_EXPORT_DIRECTORY exp{};
        if ( !read_val(cursor, b + exportRva, &exp) )
            return 0;

        if ( exp.NumberOfNames == 0
          || exp.AddressOfNames == 0
          || exp.AddressOfNameOrdinals == 0
          || exp.AddressOfFunctions == 0 )
            return 0;

        // Pull the three parallel arrays in one query each instead of three
        // queries per export. ntdll alone exports ~2400 names, and this runs for
        // every module in the trace, so the per-entry form cost tens of thousands
        // of engine round-trips at trace-load time.
        // The counts come from the PE header, i.e. untrusted input: clamp them
        // before sizing any buffer.
        static const uint32_t kMaxExports = 1u << 20;
        uint32_t nNames = exp.NumberOfNames < kMaxExports ? exp.NumberOfNames : kMaxExports;
        uint32_t nFuncs = exp.NumberOfFunctions < kMaxExports ? exp.NumberOfFunctions : kMaxExports;
        if ( nNames == 0 || nFuncs == 0 )
            return 0;

        std::vector<uint32_t> nameRvas(nNames);
        std::vector<uint16_t> ordinals(nNames);
        std::vector<uint32_t> funcRvas(nFuncs);

        MemoryBuffer mbN = cursor->QueryMemoryBuffer(
            GuestAddress{ b + exp.AddressOfNames },
            BufferView{ nameRvas.data(), (size_t)nNames * sizeof(uint32_t) });
        MemoryBuffer mbO = cursor->QueryMemoryBuffer(
            GuestAddress{ b + exp.AddressOfNameOrdinals },
            BufferView{ ordinals.data(), (size_t)nNames * sizeof(uint16_t) });
        MemoryBuffer mbF = cursor->QueryMemoryBuffer(
            GuestAddress{ b + exp.AddressOfFunctions },
            BufferView{ funcRvas.data(), (size_t)nFuncs * sizeof(uint32_t) });

        // Each array may come back short (TTD only records accessed memory); use
        // whatever prefix actually resolved.
        size_t gotNames = mbN.Memory.Size / sizeof(uint32_t);
        size_t gotOrds  = mbO.Memory.Size / sizeof(uint16_t);
        size_t gotFuncs = mbF.Memory.Size / sizeof(uint32_t);
        size_t usable   = gotNames < gotOrds ? gotNames : gotOrds;

        size_t named = 0;
        for ( size_t i = 0; i < usable; i++ )
        {
            uint32_t nameRva = nameRvas[i];
            uint16_t ordinal = ordinals[i];
            if ( (size_t)ordinal >= gotFuncs )
                continue;

            uint32_t funcRva = funcRvas[ordinal];
            if ( funcRva == 0 )
                continue;

            // Forwarder exports point back inside the export directory; skip them
            // (the real target lives in another module).
            if ( funcRva >= exportRva && funcRva < exportRva + exportSize )
                continue;

            std::string name = read_cstr(cursor, b + nameRva);
            if ( name.empty() )
                continue;

            ea_t va = (ea_t)(b + funcRva);
            // Several exports routinely share one address: ntdll exports every
            // syscall stub twice, as NtXxx and ZwXxx. The export name table is
            // sorted alphabetically, so without care the Zw spelling arrives
            // second and renames the address, and every call site in the
            // database then reads ZwAllocateVirtualMemory.
            //
            // Whichever real name got there first keeps the address, except that
            // a Zw name is replaced by the Nt spelling of the same stub. A dummy
            // sub_/loc_ name is always replaced.
            if ( has_user_name(get_flags(va)) )
            {
                qstring cur;
                if ( get_name(&cur, va) <= 0 )
                    continue;
                bool zw_to_nt = cur.length() == name.length()
                             && cur.length() > 2
                             && strncmp(cur.c_str(), "Zw", 2) == 0
                             && name.compare(0, 2, "Nt") == 0
                             && strcmp(cur.c_str() + 2, name.c_str() + 2) == 0;
                if ( !zw_to_nt )
                    continue;
            }
            if ( set_name(va, name.c_str(), SN_NOWARN | SN_FORCE | SN_NOCHECK) )
                named++;
        }

        return named;
    }

    size_t parse_pdata_functions(ICursorView *cursor, ea_t base, bool is64,
                                 std::vector<std::pair<ea_t, ea_t>> &out)
    {
        out.clear();
        // The RUNTIME_FUNCTION table only exists for x64 (x86 SEH is different).
        if ( cursor == nullptr || base == BADADDR || !is64 )
            return 0;

        uint64_t b = (uint64_t)base;
        IMAGE_DOS_HEADER dos{};
        if ( !read_val(cursor, b, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE )
            return 0;

        IMAGE_NT_HEADERS64 nt{};
        if ( !read_val(cursor, b + (uint32_t)dos.e_lfanew, &nt) || nt.Signature != IMAGE_NT_SIGNATURE )
            return 0;

        const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        uint32_t rva  = dd.VirtualAddress;
        uint32_t size = dd.Size;
        if ( rva == 0 || size == 0 )
            return 0;

        // RUNTIME_FUNCTION = { uint32 BeginRva; uint32 EndRva; uint32 UnwindRva; }.
        struct RtFunc { uint32_t Begin, End, Unwind; };
        // 'size' is an attacker-controllable header field (we analyse malware);
        // cap it so a corrupt directory can't ask for a multi-gigabyte buffer.
        static const size_t kMaxFuncs = 1u << 22;   // 4M functions ~ 48 MB
        size_t maxEntries = size / sizeof(RtFunc);
        if ( maxEntries == 0 )
            return 0;
        if ( maxEntries > kMaxFuncs )
            maxEntries = kMaxFuncs;

        std::vector<RtFunc> buf(maxEntries);
        MemoryBuffer mb = cursor->QueryMemoryBuffer(
            GuestAddress{ b + rva }, BufferView{ buf.data(), maxEntries * sizeof(RtFunc) });
        size_t got = mb.Memory.Size / sizeof(RtFunc);

        out.reserve(got);
        for ( size_t i = 0; i < got; i++ )
        {
            const RtFunc &rf = buf[i];
            if ( rf.Begin == 0 || rf.End <= rf.Begin )
                continue;
            out.emplace_back((ea_t)(b + rf.Begin), (ea_t)(b + rf.End));
        }
        std::sort(out.begin(), out.end());
        return out.size();
    }

    size_t parse_pdata_functions_from_file(const char *path, ea_t base, bool is64,
                                           uint32_t want_timestamp, uint32_t want_checksum,
                                           std::vector<std::pair<ea_t, ea_t>> &out)
    {
        out.clear();
        if ( path == nullptr || *path == '\0' || base == BADADDR || !is64 )
            return 0;

        std::ifstream f(path, std::ios::binary);
        if ( !f.is_open() )
            return 0;

        IMAGE_DOS_HEADER dos{};
        f.read((char *)&dos, sizeof(dos));
        if ( !f || dos.e_magic != IMAGE_DOS_SIGNATURE )
            return 0;

        f.seekg((std::streamoff)(uint32_t)dos.e_lfanew, std::ios::beg);
        IMAGE_NT_HEADERS64 nt{};
        f.read((char *)&nt, sizeof(nt));
        if ( !f || nt.Signature != IMAGE_NT_SIGNATURE
          || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
            return 0;

        // Same build as the one in the trace? The path came off the recording
        // machine; a local file at that path with different headers is a different
        // build, and its function bounds would be silently wrong.
        if ( (want_timestamp != 0 && nt.FileHeader.TimeDateStamp != want_timestamp)
          || (want_checksum  != 0 && nt.OptionalHeader.CheckSum  != want_checksum) )
            return 0;

        const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        uint32_t rva  = dd.VirtualAddress;
        uint32_t size = dd.Size;
        if ( rva == 0 || size == 0 )
            return 0;

        // Map the .pdata RVA to a file offset via the section headers (which
        // follow the optional header).
        uint64_t secOff = (uint64_t)(uint32_t)dos.e_lfanew + 4
                        + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
        f.seekg((std::streamoff)secOff, std::ios::beg);

        uint32_t fileOff = 0;
        bool     found   = false;
        for ( uint16_t i = 0; i < nt.FileHeader.NumberOfSections; i++ )
        {
            IMAGE_SECTION_HEADER sec{};
            f.read((char *)&sec, sizeof(sec));
            if ( !f )
                break;
            uint32_t vsize = sec.Misc.VirtualSize != 0 ? sec.Misc.VirtualSize : sec.SizeOfRawData;
            if ( rva >= sec.VirtualAddress && rva < sec.VirtualAddress + vsize )
            {
                fileOff = sec.PointerToRawData + (rva - sec.VirtualAddress);
                found   = true;
                break;
            }
        }
        if ( !found )
            return 0;

        struct RtFunc { uint32_t Begin, End, Unwind; };
        // As above: 'size' is untrusted header data. Bound it by both a hard cap
        // and what the file could actually contain.
        static const size_t kMaxFuncs = 1u << 22;
        size_t count = size / sizeof(RtFunc);
        if ( count == 0 )
            return 0;
        f.seekg(0, std::ios::end);
        uint64_t fileLen = (uint64_t)f.tellg();
        if ( fileOff >= fileLen )
            return 0;
        size_t avail = (size_t)((fileLen - fileOff) / sizeof(RtFunc));
        if ( count > avail )
            count = avail;
        if ( count > kMaxFuncs )
            count = kMaxFuncs;
        if ( count == 0 )
            return 0;

        std::vector<RtFunc> buf(count);
        f.seekg((std::streamoff)fileOff, std::ios::beg);
        f.read((char *)buf.data(), (std::streamsize)(count * sizeof(RtFunc)));
        size_t got = (size_t)f.gcount() / sizeof(RtFunc);

        uint64_t b = (uint64_t)base;
        out.reserve(got);
        for ( size_t i = 0; i < got; i++ )
        {
            const RtFunc &rf = buf[i];
            if ( rf.Begin == 0 || rf.End <= rf.Begin )
                continue;
            out.emplace_back((ea_t)(b + rf.Begin), (ea_t)(b + rf.End));
        }
        std::sort(out.begin(), out.end());
        return out.size();
    }

    bool load_module_image(const char *path, ModuleImage &out)
    {
        out = ModuleImage{};
        if ( path == nullptr || *path == '\0' )
            return false;

        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if ( !f.is_open() )
            return false;
        std::streamoff len = f.tellg();
        if ( len <= 0 )
            return false;
        out.file.resize((size_t)len);
        f.seekg(0, std::ios::beg);
        f.read((char *)out.file.data(), (std::streamsize)len);
        if ( (size_t)f.gcount() != out.file.size() )
            out.file.resize((size_t)f.gcount());

        const uint8_t *base = out.file.data();
        size_t         fsz  = out.file.size();
        if ( fsz < sizeof(IMAGE_DOS_HEADER) )
            return false;

        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
        if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
            return false;

        uint32_t ntoff = (uint32_t)dos->e_lfanew;
        if ( (size_t)ntoff + sizeof(IMAGE_NT_HEADERS32) > fsz )
            return false;
        const IMAGE_NT_HEADERS32 *nt32 = (const IMAGE_NT_HEADERS32 *)(base + ntoff);
        if ( nt32->Signature != IMAGE_NT_SIGNATURE )
            return false;

        uint16_t nsec    = nt32->FileHeader.NumberOfSections;
        uint16_t optsz   = nt32->FileHeader.SizeOfOptionalHeader;
        out.timestamp    = nt32->FileHeader.TimeDateStamp;
        if ( nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
        {
            // IMAGE_NT_HEADERS64 is larger than the ...32 form we bounds-checked
            // above, so re-check before reading through the wider view. (A
            // truncated PE32+ file would otherwise be read past its end.)
            if ( (size_t)ntoff + sizeof(IMAGE_NT_HEADERS64) > fsz )
                return false;
            const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)(base + ntoff);
            out.sizeOfHeaders = nt64->OptionalHeader.SizeOfHeaders;
            out.checksum      = nt64->OptionalHeader.CheckSum;
            out.sizeOfImage   = nt64->OptionalHeader.SizeOfImage;
        }
        else
        {
            out.sizeOfHeaders = nt32->OptionalHeader.SizeOfHeaders;
            out.checksum      = nt32->OptionalHeader.CheckSum;
            out.sizeOfImage   = nt32->OptionalHeader.SizeOfImage;
        }

        size_t secOff = (size_t)ntoff + 4 + sizeof(IMAGE_FILE_HEADER) + optsz;
        if ( secOff + (size_t)nsec * sizeof(IMAGE_SECTION_HEADER) > fsz )
            return false;

        const IMAGE_SECTION_HEADER *secs = (const IMAGE_SECTION_HEADER *)(base + secOff);
        out.sections.reserve(nsec);
        for ( uint16_t i = 0; i < nsec; i++ )
        {
            ModuleImage::Section s{};
            s.va      = secs[i].VirtualAddress;
            s.vsize   = secs[i].Misc.VirtualSize != 0 ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
            s.raw     = secs[i].PointerToRawData;
            s.rawsize = secs[i].SizeOfRawData;
            out.sections.push_back(s);
        }
        out.ok = true;
        return true;
    }

    size_t read_module_image_rva(const ModuleImage &img, uint32_t rva, void *buf, size_t size)
    {
        if ( !img.ok || size == 0 )
            return 0;

        // The PE headers are mapped 1:1 from file offset 0.
        if ( rva < img.sizeOfHeaders )
        {
            size_t avail = img.sizeOfHeaders - rva;
            if ( (size_t)rva >= img.file.size() )
                return 0;
            size_t fileAvail = img.file.size() - rva;
            size_t run = size < avail ? size : avail;
            if ( run > fileAvail )
                run = fileAvail;
            memcpy(buf, img.file.data() + rva, run);
            return run;
        }

        // Otherwise locate the section whose virtual range contains rva.
        for ( const ModuleImage::Section &s : img.sections )
        {
            if ( rva < s.va || rva >= s.va + s.vsize )
                continue;
            uint32_t inSec = rva - s.va;
            if ( inSec >= s.rawsize )
                return 0;                       // zero-fill tail (.bss): leave it 0
            uint32_t fileOff = s.raw + inSec;
            if ( (size_t)fileOff >= img.file.size() )
                return 0;
            size_t avail     = s.rawsize - inSec;            // contiguous raw bytes
            size_t fileAvail = img.file.size() - fileOff;
            size_t run = size < avail ? size : avail;
            if ( run > fileAvail )
                run = fileAvail;
            memcpy(buf, img.file.data() + fileOff, run);
            return run;
        }
        return 0;
    }
}
