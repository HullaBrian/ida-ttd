#include "ui/clipboard.h"
#include "common/strings.h"

namespace idattd
{
    void copy_to_clipboard(const char *text)
    {
        // As UTF-16: CF_TEXT uses the ANSI code page and garbles anything
        // outside it. Windows synthesizes CF_TEXT from this for readers.
        // Opened for a window of this (the UI) thread: with no owner,
        // EmptyClipboard leaves the clipboard ownerless and SetClipboardData
        // then fails, so the copy would silently do nothing.
        if ( text == nullptr || !OpenClipboard(GetActiveWindow()) )
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
                // The clipboard owns the block only when SetClipboardData
                // succeeds; on failure it must be freed here.
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
