"""ida-ttd's settings, read through ida-settings for the plugin.

The settings are declared in ida-plugin.json (every one with a default and
"prompt": false, so installing asks nothing). Their values live in IDA's
ida-config.json, where `hcli plugin config ida-ttd set KEY VALUE` and the IDA
Settings Editor plugin put them. ida-settings is the library that reads them,
and it is Python, so the plugin (C++) asks this module: dump() hands back
every value as text, and the plugin keeps its own defaults for anything
missing, which is all of them when ida-settings is not installed.

Copied beside ida_ttd.py (ida-ttd-python/), which the plugin puts on sys.path.
"""

PLUGIN = "ida-ttd"

EDITOR_FUNC = "ida_settings_show_plugin_settings"


def _settings():
    try:
        import ida_settings
    except Exception:                   # not installed, or broken: defaults
        return None
    return ida_settings.PluginSettings(PLUGIN)


def available():
    return _settings() is not None


def dump(keys):
    """'key=value' lines for each of the space-separated 'keys' that has a
    value (booleans as true/false), and '!key=reason' for one whose stored
    value could not be read. Empty without ida-settings."""
    s = _settings()
    if s is None:
        return ""
    out = []
    for key in keys.split():
        try:
            v = s.get_setting(key)
        except KeyError:
            continue
        except Exception as e:          # an invalid stored value, say
            # hcli finds plugins by their folder in $IDAUSR/plugins; a copy
            # loaded from anywhere else has no settings, only defaults.
            if type(e).__name__ == "PluginNotInstalledError":
                return ""
            out.append("!%s=%s" % (key, str(e).replace("\n", " ")))
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        out.append("%s=%s" % (key, str(v).replace("\n", " ")))
    return "\n".join(out)


def show_editor():
    """TTD > Settings...: the IDA Settings Editor on ida-ttd's settings, or how
    to change them without it."""
    import ida_expr
    import ida_kernwin
    import idc
    if ida_expr.find_idc_func(EDITOR_FUNC) == EDITOR_FUNC:
        idc.eval_idc('%s("%s")' % (EDITOR_FUNC, PLUGIN))
        return
    have = available()
    ida_kernwin.info(
        "ida-ttd's settings are edited in the IDA Settings Editor, which is not installed.\n\n"
        "Install it with:\n    hcli plugin install ida-settings-editor\n\n"
        "Or set a value from the command line:\n    hcli plugin config ida-ttd set KEY VALUE\n"
        "    hcli plugin config ida-ttd list\n\n"
        "Settings take effect the next time a database is opened.%s"
        % ("" if have else
           "\n\nThe ida-settings Python package is not installed either, so ida-ttd uses its "
           "defaults. Installing ida-ttd with hcli installs it."))
