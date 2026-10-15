#include "ui/clipboard.h"
#include "common/strings.h"

namespace idattd
{
    void copy_to_clipboard(const char *text)
    {
        // As UTF-16: CF_TEXT is read in the ANSI code page, which garbles any
        // character outside it (a path with an accent in it). Windows makes the
        // CF_TEXT form from this one for readers that want it.
        if ( text == nullptr || !OpenClipboard(nullptr) )
            return;
        EmptyClipboard();
        const std::wstring w = to_wstring(text);
        const size_t       n = (w.size() + 1) * sizeof(wchar_t);
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n);
        if ( h != nullptr )
        {
            void *p = GlobalLock(h);
            if ( p != nullptr )
            {
                memcpy(p, w.c_str(), n);
                GlobalUnlock(h);
                // The clipboard only takes ownership of the block when
                // SetClipboardData succeeds; on failure it is still ours to free.
                if ( SetClipboardData(CF_UNICODETEXT, h) == nullptr )
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
