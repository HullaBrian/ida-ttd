#include "core/guest_view.h"
#include "core/backend.h"

namespace idattd
{
    GuestRead guest_read(ITraceCursor *cursor)
    {
        return [cursor](uint64_t addr, void *buf, size_t size) -> size_t
        {
            if ( cursor == nullptr || buf == nullptr || size == 0 )
                return 0;
            memset(buf, 0, size);
            std::vector<uint8_t> known;
            cursor->read_memory((ea_t)addr, buf, size, &known);
            size_t n = 0;
            while ( n < size && n < known.size() && known[n] != 0 )
                n++;
            return n;
        };
    }

    GuestView guest_view(ITraceCursor *cursor)
    {
        GuestView v;
        v.read = guest_read(cursor);
        v.regs = [cursor](ittd_regs *out)
        {
            return cursor != nullptr && cursor->read_registers(out);
        };
        return v;
    }
}
