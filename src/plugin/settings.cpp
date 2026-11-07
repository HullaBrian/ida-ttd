#include "plugin/settings.h"
#include "common/symsrv.h"
#include "core/diag.h"

#include <diskio.hpp>
#include <expr.hpp>

namespace idattd
{
    static Settings g_settings;

    const Settings &settings()
    {
        return g_settings;
    }

    // Every key, for ida_ttd_settings.dump().
    static const char ALL_KEYS[] = "replay_on_open symbol_downloads symbol_server auto_coverage auto_callsites "
                                   "fork_instructions registry_folder diagnostics_log memmap_flag_code";

    static bool parse_bool(const qstring &v, bool *out)
    {
        if ( v == "true" )
            *out = true;
        else if ( v == "false" )
            *out = false;
        else
            return false;
        return true;
    }

    // Apply one "key=value" line from dump(). False for a value the plugin
    // cannot use (it keeps its default); ida-settings already validated it
    // against ida-plugin.json, so this means the two disagree.
    static bool apply(Settings *s, const qstring &key, const qstring &value)
    {
        if ( key == "replay_on_open" )
            return parse_bool(value, &s->replay_on_open);
        if ( key == "symbol_downloads" )
            return parse_bool(value, &s->symbol_downloads);
        if ( key == "auto_coverage" )
            return parse_bool(value, &s->auto_coverage);
        if ( key == "auto_callsites" )
            return parse_bool(value, &s->auto_callsites);
        if ( key == "diagnostics_log" )
            return parse_bool(value, &s->diagnostics_log);
        if ( key == "memmap_flag_code" )
            return parse_bool(value, &s->memmap_flag_code);
        if ( key == "symbol_server" )
        {
            if ( strncmp(value.c_str(), "https://", 8) != 0 && strncmp(value.c_str(), "http://", 7) != 0 )
                return false;
            s->symbol_server = value;
            while ( s->symbol_server.length() > 8 && s->symbol_server.last() == '/' )
                s->symbol_server.remove_last();
            return true;
        }
        if ( key == "fork_instructions" )
        {
            // Digits only: strtoull also takes leading blanks and a sign, and
            // turns "-1" into 2^64-1, a fork that runs to the recording's end.
            for ( size_t i = 0; i < value.length(); i++ )
                if ( !qisdigit(value[i]) )
                    return false;
            char *end = nullptr;
            errno = 0;
            unsigned long long n = strtoull(value.c_str(), &end, 10);
            if ( value.empty() || end == nullptr || *end != '\0' || errno == ERANGE )
                return false;
            s->fork_instructions = n;
            return true;
        }
        if ( key == "registry_folder" )
        {
            s->registry_folder = value;
            return true;
        }
        return false;
    }

    // dump()'s answer, or empty without IDAPython, without ida-settings, or
    // without the module (a build folder copied by hand).
    static qstring read_values()
    {
        qstring text;
        extlang_object_t py = find_extlang_by_name("Python");
        if ( py == nullptr || py->eval_snippet == nullptr || py->eval_expr == nullptr )
            return text;
        qstring err;
        if ( !py->eval_snippet("import ida_ttd_settings\n", &err) )
            return text;
        qstring expr;
        expr.sprnt("ida_ttd_settings.dump('%s')", ALL_KEYS);
        idc_value_t rv;
        if ( py->eval_expr(&rv, BADADDR, expr.c_str(), &err) && rv.vtype == VT_STR )
            text = rv.qstr();
        else if ( !err.empty() )
            msg("[ida-ttd] could not read the plugin's settings (%s); using the defaults.\n", err.c_str());
        return text;
    }

    // ida-config.json's modification time and size when the values were last
    // read. The time has one-second resolution, so two saves within a second
    // could look like none; the size catches most of those (a changed value
    // usually changes the length).
    struct ConfigStamp
    {
        qtime64_t mtime = 0;
        uint64    size  = 0;
        bool operator!=(const ConfigStamp &o) const { return mtime != o.mtime || size != o.size; }
    };
    static ConfigStamp g_configStamp;

    static ConfigStamp config_stamp()
    {
        qstring path = get_user_idadir();
        path.append("\\ida-config.json");
        qstatbuf st;
        ConfigStamp c;
        if ( qstat(path.c_str(), &st) == 0 )
        {
            c.mtime = st.qst_mtime;
            c.size  = (uint64)st.qst_size;
        }
        return c;
    }

    void reload_settings_if_changed()
    {
        if ( config_stamp() != g_configStamp )
            load_settings();
    }

    void load_settings()
    {
        g_configStamp = config_stamp();
        Settings s;
        qstring text = read_values();
        size_t at = 0;
        while ( at < text.length() )
        {
            size_t nl = text.find('\n', at);
            if ( nl == qstring::npos )
                nl = text.length();
            qstring line = text.substr(at, nl);
            at = nl + 1;
            ssize_t eq = line.find('=');
            if ( eq <= 0 )
                continue;
            const bool bad = line[0] == '!';
            qstring key = line.substr(bad ? 1 : 0, eq);
            qstring value = line.substr(eq + 1);
            if ( bad )
                msg("[ida-ttd] setting %s is not valid (%s); using its default.\n",
                    key.c_str(), value.c_str());
            else if ( !apply(&s, key, value) )
                msg("[ida-ttd] setting %s=\"%s\" cannot be used; using its default.\n",
                    key.c_str(), value.c_str());
        }
        g_settings = s;

        symsrv_configure(s.symbol_downloads, s.symbol_server.c_str());
        diag_set_enabled(s.diagnostics_log);
    }
}
