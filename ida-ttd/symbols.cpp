#include "symbols.h"

using namespace TTD;
using namespace TTD::Replay;

namespace idattd
{
    //-----------------------------------------------------------------------
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

    //-----------------------------------------------------------------------
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

    //-----------------------------------------------------------------------
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

        size_t named = 0;
        for ( uint32_t i = 0; i < exp.NumberOfNames; i++ )
        {
            uint32_t nameRva = 0;
            uint16_t ordinal = 0;
            if ( !read_val(cursor, b + exp.AddressOfNames + i * sizeof(uint32_t), &nameRva)
              || !read_val(cursor, b + exp.AddressOfNameOrdinals + i * sizeof(uint16_t), &ordinal) )
                continue;

            uint32_t funcRva = 0;
            if ( !read_val(cursor, b + exp.AddressOfFunctions + (uint32_t)ordinal * sizeof(uint32_t), &funcRva) )
                continue;
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
            if ( set_name(va, name.c_str(), SN_NOWARN | SN_FORCE | SN_NOCHECK) )
                named++;
        }

        return named;
    }
}
