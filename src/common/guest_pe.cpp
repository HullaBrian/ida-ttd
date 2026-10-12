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
            size_t got = c(addr + s.size(), chunk, sizeof(chunk));
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

    // Locate a module's NT headers and say which flavour they are. Shared by
    // read_guest_pe_info and resolve_export_va so the DOS/NT walk is written once.
    static bool locate_nt_headers(const GuestRead &c, uint64_t base, uint64_t *nt_addr_out,
                                  bool *is64_out)
    {
        IMAGE_DOS_HEADER dos{};
        if ( !pe_read_val(c, base, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE )
            return false;
        // e_lfanew is attacker-controlled (we analyse malware): a wild value would
        // send every read that follows somewhere unrelated.
        if ( dos.e_lfanew < 0 || (uint32_t)dos.e_lfanew > 0x10000000u )
            return false;

        uint64_t ntAddr = base + (uint32_t)dos.e_lfanew;
        uint32_t sig = 0;
        if ( !pe_read_val(c, ntAddr, &sig) || sig != IMAGE_NT_SIGNATURE )
            return false;

        // The optional header magic sits after the signature and the file header,
        // and it -- not the recording machine's architecture -- says whether this
        // image is 32- or 64-bit.
        uint16_t magic = 0;
        if ( !pe_read_val(c, ntAddr + 4 + sizeof(IMAGE_FILE_HEADER), &magic) )
            return false;
        if ( magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
            return false;

        *nt_addr_out = ntAddr;
        *is64_out    = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        return true;
    }

    // The export data directory of a module whose NT header is at 'ntAddr', or
    // false when it has none.
    static bool read_export_dir(const GuestRead &c, uint64_t ntAddr, bool is64,
                                uint32_t *rva_out, uint32_t *size_out)
    {
        if ( is64 )
        {
            IMAGE_NT_HEADERS64 nt{};
            if ( !pe_read_val(c, ntAddr, &nt) )
                return false;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            *rva_out  = dd.VirtualAddress;
            *size_out = dd.Size;
        }
        else
        {
            IMAGE_NT_HEADERS32 nt{};
            if ( !pe_read_val(c, ntAddr, &nt) )
                return false;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
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

        // The section table follows the optional header, whose SIZE the file
        // header states -- it is not always sizeof(IMAGE_OPTIONAL_HEADER), and
        // assuming so puts the table read a few bytes off on a hand-built image.
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

        // NumberOfSections is a 16-bit file field: 65535 would ask for a 2.5 MB
        // read of a module that has three sections. The format caps a loadable
        // image at 96.
        static const uint16_t kMaxSections = 96;
        if ( nsections > kMaxSections )
            nsections = kMaxSections;
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

    // The debug data directory of a module whose NT header is at 'ntAddr'.
    static bool read_debug_dir(const GuestRead &c, uint64_t ntAddr, bool is64,
                               uint32_t *rva_out, uint32_t *size_out)
    {
        if ( is64 )
        {
            IMAGE_NT_HEADERS64 nt{};
            if ( !pe_read_val(c, ntAddr, &nt) )
                return false;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            *rva_out  = dd.VirtualAddress;
            *size_out = dd.Size;
        }
        else
        {
            IMAGE_NT_HEADERS32 nt{};
            if ( !pe_read_val(c, ntAddr, &nt) )
                return false;
            const IMAGE_DATA_DIRECTORY &dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            *rva_out  = dd.VirtualAddress;
            *size_out = dd.Size;
        }
        return *rva_out != 0 && *size_out != 0;
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
        if ( !read_debug_dir(cursor, ntAddr, is64, &dbgRva, &dbgSize) )
            return false;

        // The directory is an array of fixed-size entries. Cap the count the same
        // way the section table is capped: the size field comes out of an image we
        // do not control, and a wild value would ask for an enormous read.
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
            // the linker wrote it. Anything else is a format we cannot name a
            // symbol-server directory for.
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
            // The linker records a build-machine path; only the file name is
            // meaningful anywhere else.
            size_t slash = path.find_last_of("/" "\\");
            out->name = slash == std::string::npos ? path : path.substr(slash + 1);

            // Symbol servers key on the GUID in registry order with no separators,
            // followed by the age in hex. Both are upper case.
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

    ea_t resolve_export_va(const GuestRead &cursor, ea_t base, bool is64, const char *name)
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
        if ( !pe_read_val(cursor, b + exportRva, &exp) )
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

        size_t mbN = cursor(b + exp.AddressOfNames, nameRvas.data(), (size_t)nNames * sizeof(uint32_t));
        size_t mbO = cursor(b + exp.AddressOfNameOrdinals, ordinals.data(), (size_t)nNames * sizeof(uint16_t));
        size_t mbF = cursor(b + exp.AddressOfFunctions, funcRvas.data(), (size_t)nFuncs * sizeof(uint32_t));

        size_t gotNames = mbN / sizeof(uint32_t);
        size_t gotOrds  = mbO / sizeof(uint16_t);
        size_t gotFuncs = mbF / sizeof(uint32_t);
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
            if ( pe_read_cstr(cursor, b + nameRvas[i]) != name )
                continue;
            return (ea_t)(b + funcRva);
        }
        return BADADDR;
    }
}
