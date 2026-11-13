#include "common/json_str.h"

namespace idattd
{
    void json_str(qstring *out, const char *s)
    {
        // Through UTF-16, so bytes that are not UTF-8 (a guest's console
        // output in Sogen's log) come out as U+FFFD rather than as a bad
        // byte that fails the whole Python call.
        qwstring w;
        utf8_utf16(&w, s);
        out->append('"');
        for ( size_t i = 0; i < w.length(); i++ )
        {
            uint32_t c = (uint16_t)w[i];
            if ( c >= 0xD800 && c < 0xDC00 && i + 1 < w.length()
              && (uint16_t)w[i + 1] >= 0xDC00 && (uint16_t)w[i + 1] < 0xE000 )
            {
                // Outside the BMP: as UTF-8. JSON would take a surrogate pair
                // of escapes, but Python reads those as two lone surrogates.
                c = 0x10000 + ((c - 0xD800) << 10) + ((uint16_t)w[++i] - 0xDC00);
                out->append((char)(0xF0 | (c >> 18)));
                out->append((char)(0x80 | ((c >> 12) & 0x3F)));
                out->append((char)(0x80 | ((c >> 6) & 0x3F)));
                out->append((char)(0x80 | (c & 0x3F)));
            }
            else if ( c >= 0xD800 && c < 0xE000 )
            {
                out->append("\\ufffd");          // a lone surrogate Qt would refuse
            }
            else if ( c == '"' || c == '\\' )
            {
                out->append('\\');
                out->append((char)c);
            }
            else if ( c < 0x20 || c >= 0x7F )
            {
                out->cat_sprnt("\\u%04x", c);
            }
            else
            {
                out->append((char)c);
            }
        }
        out->append('"');
    }
}
