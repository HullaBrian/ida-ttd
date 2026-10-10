#include "ui/clipboard.h"

namespace idattd
{
    void copy_to_clipboard(const char *text)
    {
        if ( text == nullptr || !OpenClipboard(nullptr) )
            return;
        EmptyClipboard();
        size_t  n = qstrlen(text) + 1;
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n);
        if ( h != nullptr )
        {
            void *p = GlobalLock(h);
            if ( p != nullptr )
            {
                memcpy(p, text, n);
                GlobalUnlock(h);
                // The clipboard only takes ownership of the block when
                // SetClipboardData succeeds; on failure it is still ours to free.
                if ( SetClipboardData(CF_TEXT, h) == nullptr )
                    GlobalFree(h);
            }
            else
            {
                GlobalFree(h);
            }
        }
        CloseClipboard();
    }
}
