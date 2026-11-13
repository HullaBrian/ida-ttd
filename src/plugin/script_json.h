#pragma once

// The JSON the script interface answers in (script_api.h).
#include "common/pch.h"

#include <vector>

namespace idattd
{
    // ------------------------------------------------------------------ JSON
    //
    // Just enough to write answers. Addresses and other 64-bit values go out
    // as "0x..." strings, since a JSON reader that parses into doubles would
    // lose bits.

    // Length of the well-formed UTF-8 sequence at 'p', or 0 when it is not one
    // (a stray continuation byte, an overlong or truncated sequence).
    inline size_t utf8_sequence(const unsigned char *p)
    {
        size_t n;
        if ( (p[0] & 0xE0) == 0xC0 && p[0] >= 0xC2 )
            n = 2;
        else if ( (p[0] & 0xF0) == 0xE0 )
            n = 3;
        else if ( (p[0] & 0xF8) == 0xF0 && p[0] <= 0xF4 )
            n = 4;
        else
            return 0;
        // The NUL terminator is not a continuation byte, so this never reads
        // past the end of the string.
        for ( size_t i = 1; i < n; i++ )
            if ( (p[i] & 0xC0) != 0x80 )
                return 0;
        // Overlong forms, UTF-16 surrogates and code points past U+10FFFF.
        if ( (p[0] == 0xE0 && p[1] < 0xA0) || (p[0] == 0xED && p[1] >= 0xA0)
          || (p[0] == 0xF0 && p[1] < 0x90) || (p[0] == 0xF4 && p[1] >= 0x90) )
            return 0;
        return n;
    }

    inline void json_escape(qstring *out, const char *s)
    {
        out->append('"');
        for ( const unsigned char *p = (const unsigned char *)s; *p != 0; p++ )
        {
            switch ( *p )
            {
                case '"':  out->append("\\\""); break;
                case '\\': out->append("\\\\"); break;
                case '\n': out->append("\\n");  break;
                case '\r': out->append("\\r");  break;
                case '\t': out->append("\\t");  break;
                default:
                    if ( *p < 0x20 )
                    {
                        out->cat_sprnt("\\u%04x", *p);
                    }
                    else if ( *p < 0x80 )
                    {
                        out->append((char)*p);
                    }
                    else if ( size_t n = utf8_sequence(p); n != 0 )
                    {
                        out->append((const char *)p, n);
                        p += n - 1;
                    }
                    else
                    {
                        // Text from a recording need not be UTF-8, and one bad
                        // byte would make the answer unparseable: emit it as
                        // the Latin-1 character.
                        out->cat_sprnt("\\u%04x", *p);
                    }
            }
        }
        out->append('"');
    }

    class JObj
    {
    public:
        JObj &raw(const char *key, const qstring &json)
        {
            sep();
            json_escape(&m_s, key);
            m_s.append(':');
            m_s.append(json);
            return *this;
        }
        JObj &str(const char *key, const char *v)
        {
            qstring j;
            json_escape(&j, v != nullptr ? v : "");
            return raw(key, j);
        }
        JObj &str(const char *key, const qstring &v) { return str(key, v.c_str()); }
        JObj &num(const char *key, int64_t v)
        {
            qstring j;
            j.sprnt("%lld", (long long)v);
            return raw(key, j);
        }
        // A number written as a "0x..." string (JSON numbers lose 64-bit
        // values in many parsers). Its key is listed in the object's "_hex",
        // which is how ida_ttd.py's py() knows to make it an int: a text
        // field that happens to read "0x41" stays text.
        JObj &hex(const char *key, uint64_t v)
        {
            qstring j;
            j.sprnt("\"0x%llX\"", (unsigned long long)v);
            mark_hex(key);
            return raw(key, j);
        }
        // An array of such numbers, listed in "_hex" the same way.
        JObj &hex_list(const char *key, const uint64_t *v, size_t n)
        {
            qstring j = "[";
            for ( size_t i = 0; i < n; i++ )
                j.cat_sprnt("%s\"0x%llX\"", i == 0 ? "" : ",", (unsigned long long)v[i]);
            j.append(']');
            mark_hex(key);
            return raw(key, j);
        }
        JObj &boolean(const char *key, bool v) { return raw(key, qstring(v ? "true" : "false")); }
        qstring done() const
        {
            qstring s = "{";
            s.append(m_s);
            if ( !m_hexKeys.empty() )
            {
                s.append(m_s.empty() ? "\"_hex\":[" : ",\"_hex\":[");
                for ( size_t i = 0; i < m_hexKeys.size(); i++ )
                {
                    if ( i != 0 )
                        s.append(',');
                    json_escape(&s, m_hexKeys[i].c_str());
                }
                s.append(']');
            }
            s.append('}');
            return s;
        }

    private:
        void sep() { if ( !m_s.empty() ) m_s.append(','); }
        void mark_hex(const char *key)
        {
            for ( const qstring &k : m_hexKeys )
                if ( k == key )
                    return;
            m_hexKeys.push_back(key);
        }
        qstring m_s;
        std::vector<qstring> m_hexKeys;
    };

    class JArr
    {
    public:
        void add(const qstring &json)
        {
            if ( !m_s.empty() )
                m_s.append(',');
            m_s.append(json);
            m_n++;
        }
        size_t size() const { return m_n; }
        qstring done() const
        {
            qstring s = "[";
            s.append(m_s);
            s.append(']');
            return s;
        }

    private:
        qstring m_s;
        size_t  m_n = 0;
    };
}
