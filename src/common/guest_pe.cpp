#include "common/guest_pe.h"

namespace idattd
{
    // Read exactly 'size' bytes of guest memory; return false on a short read.
    bool pe_read(const GuestRead &c, uint64_t addr, void *buf, size_t size)
    {
        return c(addr, buf, size) == size;
    }

    // Read a NUL-terminated ASCII string from guest memory (bounded).
    std::string pe_read_cstr(const GuestRead &c, uint64_t addr, size_t maxlen)
    {
        std::string s;
        char chunk[64];
        while ( s.size() < maxlen )
        {
            size_t got = c(addr + s.size(), chunk, qmin(sizeof(chunk), maxlen - s.size()));
            if ( got == 0 )
                break;
            for ( size_t i = 0; i < got; i++ )
            {
                if ( chunk[i] == '\0' )
                    return s;
                s.push_back(chunk[i]);
            }
        }
        return s;
    }

    // Locate a module's NT headers and their flavour. Shared by every reader here
    // so the DOS/NT walk and its e_lfanew guard exist once.
    static bool locate_nt_headers(const GuestRead &c, uint64_t base, uint64_t *nt_addr_out,
                                  bool *is64_out)
    {
        IMAGE_DOS_HEADER dos{};
        if ( !pe_read_val(c, base, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE )
            return false;
        // e_lfanew is attacker-controlled (the image may be malware); a wild value
        // would send every following read somewhere unrelated.
        if ( dos.e_lfanew < 0 || (uint32_t)dos.e_lfanew > 0x10000000u )
            return false;

        uint64_t ntAddr = base + (uint32_t)dos.e_lfanew;
        uint32_t sig = 0;
        if ( !pe_read_val(c, ntAddr, &sig) || sig != IMAGE_NT_SIGNATURE )
            return false;

        // The optional header magic (after the signature and file header) says
        // whether the image is 32- or 64-bit; the recording machine's
        // architecture does not.
        uint16_t magic = 0;
        if ( !pe_read_val(c, ntAddr + 4 + sizeof(IMAGE_FILE_HEADER), &magic) )
            return false;
        if ( magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
            return false;

        *nt_addr_out = ntAddr;
        *is64_out    = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        return true;
    }

    // Data directory 'index' (IMAGE_DIRECTORY_ENTRY_*) of the module whose NT
    // header is at 'ntAddr'; false when absent. Entries past
    // NumberOfRvaAndSizes are not directories, whatever bytes sit there.
    static bool read_data_dir(const GuestRead &c, uint64_t ntAddr, bool is64, int index,
                              uint32_t *rva_out, uint32_t *size_out)
    {
        if ( is64 )
        {
            IMAGE_NT_HEADERS64 nt{};
            if ( !pe_read_val(c, ntAddr, &nt) || nt.OptionalHeader.NumberOfRvaAndSizes <= (DWORD)index )
                return false;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[index];
            *rva_out  = dd.VirtualAddress;
            *size_out = dd.Size;
        }
        else
        {
            IMAGE_NT_HEADERS32 nt{};
            if ( !pe_read_val(c, ntAddr, &nt) || nt.OptionalHeader.NumberOfRvaAndSizes <= (DWORD)index )
                return false;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[index];
            *rva_out  = dd.VirtualAddress;
            *size_out = dd.Size;
        }
        return *rva_out != 0 && *size_out != 0;
    }

    bool read_guest_pe_info(const GuestRead &cursor, ea_t base, GuestPeInfo *out)
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

        // The section table follows the optional header, whose size comes from
        // the file header. It is not always sizeof(IMAGE_OPTIONAL_HEADER); a
        // hand-built image would put the table a few bytes off.
        IMAGE_FILE_HEADER fh{};
        if ( !pe_read_val(cursor, ntAddr + 4, &fh) )
            return false;
        out->timestamp = fh.TimeDateStamp;
        uint16_t nsections = fh.NumberOfSections;
        uint64_t sectAddr  = ntAddr + 4 + sizeof(IMAGE_FILE_HEADER) + fh.SizeOfOptionalHeader;

        if ( is64 )
        {
            IMAGE_NT_HEADERS64 nt{};
            if ( !pe_read_val(cursor, ntAddr, &nt) )
                return false;
            out->entry_rva       = nt.OptionalHeader.AddressOfEntryPoint;
            out->size_of_image   = nt.OptionalHeader.SizeOfImage;
            out->size_of_headers = nt.OptionalHeader.SizeOfHeaders;
            out->preferred_base  = nt.OptionalHeader.ImageBase;
            out->checksum        = nt.OptionalHeader.CheckSum;
        }
        else
        {
            IMAGE_NT_HEADERS32 nt{};
            if ( !pe_read_val(cursor, ntAddr, &nt) )
                return false;
            out->entry_rva       = nt.OptionalHeader.AddressOfEntryPoint;
            out->size_of_image   = nt.OptionalHeader.SizeOfImage;
            out->size_of_headers = nt.OptionalHeader.SizeOfHeaders;
            out->preferred_base  = nt.OptionalHeader.ImageBase;
            out->checksum        = nt.OptionalHeader.CheckSum;
        }

        // NumberOfSections is untrusted: 65535 would ask for a 2.5 MB read of a
        // module with three sections. The loader requires the section table
        // to lie within SizeOfHeaders, so that bounds it (Windows loads images
        // with more than the 96 sections the PE documentation names). An
        // image whose SizeOfHeaders leaves no room for the table still gets
        // the documented 96, in case the field alone is malformed.
        static const uint64_t kFallbackSections = 96;
        uint64_t tableOff = sectAddr - b;
        uint64_t fit = out->size_of_headers > tableOff
                     ? (out->size_of_headers - tableOff) / sizeof(IMAGE_SECTION_HEADER)
                     : 0;
        if ( fit < kFallbackSections )
            fit = kFallbackSections;
        if ( nsections > fit )
            nsections = (uint16_t)fit;
        if ( nsections == 0 )
            return true;    // valid headers; a sectionless image is merely odd

        std::vector<IMAGE_SECTION_HEADER> hdrs(nsections);
        size_t mb = cursor(sectAddr, hdrs.data(), (size_t)nsections * sizeof(IMAGE_SECTION_HEADER));
        size_t got = mb / sizeof(IMAGE_SECTION_HEADER);

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

    bool read_guest_pdb_info(const GuestRead &cursor, ea_t base, GuestPdbInfo *out)
    {
        if ( cursor == nullptr || out == nullptr || base == BADADDR )
            return false;
        *out = GuestPdbInfo();

        uint64_t b = (uint64_t)base;
        uint64_t ntAddr = 0;
        bool     is64   = false;
        if ( !locate_nt_headers(cursor, b, &ntAddr, &is64) )
            return false;

        uint32_t dbgRva = 0, dbgSize = 0;
        if ( !read_data_dir(cursor, ntAddr, is64, IMAGE_DIRECTORY_ENTRY_DEBUG, &dbgRva, &dbgSize) )
            return false;

        // Cap the entry count like the section table: the size field is
        // untrusted and a wild value would ask for an enormous read.
        static const uint32_t kMaxEntries = 64;
        uint32_t nentries = dbgSize / (uint32_t)sizeof(IMAGE_DEBUG_DIRECTORY);
        if ( nentries > kMaxEntries )
            nentries = kMaxEntries;

        for ( uint32_t i = 0; i < nentries; i++ )
        {
            IMAGE_DEBUG_DIRECTORY dd{};
            if ( !pe_read_val(cursor, b + dbgRva + i * sizeof(IMAGE_DEBUG_DIRECTORY), &dd) )
                return false;
            if ( dd.Type != IMAGE_DEBUG_TYPE_CODEVIEW || dd.AddressOfRawData == 0 )
                continue;

            // The CodeView record: "RSDS", a GUID, an age, then the PDB path as
            // the linker wrote it. Other formats give no symbol-server name.
            struct RsdsHeader
            {
                uint32_t signature;     // 'SDSR'
                GUID     guid;
                uint32_t age;
            } rs{};
            uint64_t cv = b + dd.AddressOfRawData;
            if ( !pe_read_val(cursor, cv, &rs) || rs.signature != 0x53445352 )
                continue;

            std::string path = pe_read_cstr(cursor, cv + sizeof(RsdsHeader), MAX_PATH);
            if ( path.empty() )
                continue;
            // The path is the build machine's; only the file name matters here.
            size_t slash = path.find_last_of("/" "\\");
            out->name = slash == std::string::npos ? path : path.substr(slash + 1);

            // Symbol-server key: the GUID in registry order without separators,
            // then the age in hex, both upper case.
            char sig[64];
            qsnprintf(sig, sizeof(sig),
                      "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                      rs.guid.Data1, rs.guid.Data2, rs.guid.Data3,
                      rs.guid.Data4[0], rs.guid.Data4[1], rs.guid.Data4[2],
                      rs.guid.Data4[3], rs.guid.Data4[4], rs.guid.Data4[5],
                      rs.guid.Data4[6], rs.guid.Data4[7], rs.age);
            out->signature = sig;
            return true;
        }
        return false;
    }

    // Call 'visit(address, name)' for each named, non-forwarded export of the
    // module at 'base' until it returns false; returns how many were visited.
    //
    // The image's own optional header decides PE32 versus PE32+: a WoW64
    // recording has both a 32- and a 64-bit ntdll, and the caller's process
    // bitness cannot tell which one 'base' is.
    template <typename Visit>
    static size_t walk_exports(const GuestRead &cursor, ea_t base, Visit visit)
    {
        if ( cursor == nullptr || base == BADADDR )
            return 0;

        uint64_t b = (uint64_t)base;
        uint64_t ntAddr = 0;
        bool     is64   = false;
        if ( !locate_nt_headers(cursor, b, &ntAddr, &is64) )
            return 0;

        uint32_t exportRva = 0, exportSize = 0;
        if ( !read_data_dir(cursor, ntAddr, is64, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportRva, &exportSize) )
            return 0;

        IMAGE_EXPORT_DIRECTORY exp{};
        if ( !pe_read_val(cursor, b + exportRva, &exp) )
            return 0;
        if ( exp.AddressOfNames == 0 || exp.AddressOfNameOrdinals == 0 || exp.AddressOfFunctions == 0 )
            return 0;

        // One read per parallel array rather than three reads per export:
        // ntdll alone exports ~2400 names and this runs for every module. The
        // counts are untrusted, so they are clamped before sizing buffers.
        static const uint32_t kMaxExports = 1u << 20;
        uint32_t nNames = exp.NumberOfNames < kMaxExports ? exp.NumberOfNames : kMaxExports;
        uint32_t nFuncs = exp.NumberOfFunctions < kMaxExports ? exp.NumberOfFunctions : kMaxExports;
        if ( nNames == 0 || nFuncs == 0 )
            return 0;

        std::vector<uint32_t> nameRvas(nNames);
        std::vector<uint16_t> ordinals(nNames);
        std::vector<uint32_t> funcRvas(nFuncs);

        size_t mbN = cursor(b + exp.AddressOfNames, nameRvas.data(), (size_t)nNames * sizeof(uint32_t));
        size_t mbO = cursor(b + exp.AddressOfNameOrdinals, ordinals.data(), (size_t)nNames * sizeof(uint16_t));
        size_t mbF = cursor(b + exp.AddressOfFunctions, funcRvas.data(), (size_t)nFuncs * sizeof(uint32_t));

        // An array may come back short (a recording holds only accessed
        // memory); use the prefix that resolved.
        size_t gotNames = mbN / sizeof(uint32_t);
        size_t gotOrds  = mbO / sizeof(uint16_t);
        size_t gotFuncs = mbF / sizeof(uint32_t);
        size_t usable   = gotNames < gotOrds ? gotNames : gotOrds;

        size_t visited = 0;
        for ( size_t i = 0; i < usable; i++ )
        {
            uint16_t ordinal = ordinals[i];
            if ( (size_t)ordinal >= gotFuncs )
                continue;
            uint32_t funcRva = funcRvas[ordinal];
            if ( funcRva == 0 )
                continue;
            // A forwarder's "address" points at a string inside the export
            // directory; its target is in another module. Written as a
            // difference so a directory near 4 GB cannot wrap the bound.
            if ( funcRva >= exportRva && funcRva - exportRva < exportSize )
                continue;
            std::string name = pe_read_cstr(cursor, b + nameRvas[i]);
            if ( name.empty() )
                continue;
            visited++;
            if ( !visit((ea_t)(b + funcRva), std::move(name)) )
                break;
        }
        return visited;
    }

    size_t read_guest_exports(const GuestRead &cursor, ea_t base, bool is64,
                              std::vector<std::pair<ea_t, std::string>> *out)
    {
        qnotused(is64);   // the image's own header is the authority (walk_exports)
        return walk_exports(cursor, base, [&](ea_t ea, std::string &&n)
        {
            if ( out != nullptr )
                out->emplace_back(ea, std::move(n));
            return true;
        });
    }
}
