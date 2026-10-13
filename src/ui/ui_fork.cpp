// Forking the recording: the dialog, and opening what it made.
#include "ui/ui.h"
#include "analysis/fork.h"

namespace idattd
{
    static bool backend_forks(TraceManager *mgr)
    {
        return mgr != nullptr && mgr->is_active() && mgr->backend() != nullptr
            && mgr->backend()->capabilities().fork;
    }

    int idaapi ForkHandler::activate(action_activation_ctx_t *)
    {
        if ( !backend_forks(mgr()) )
        {
            warning("This recording cannot be forked. Sogen recordings can: the program "
                    "is replayed to the position and runs on in Sogen's emulator.");
            return 1;
        }

        static const char form[] =
            "Fork the recording here\n"
            "\n"
            "\n"
            "Replay the program to this position, change registers and memory, and let\n"
            "it run on, recording into a new trace. This recording is not touched.\n"
            "\n"
            "A recording made against the host (no emulation root) runs its program's\n"
            "file and network operations on this machine again -- only allow that for\n"
            "programs you trust.\n"
            "\n"
            "Registers belong to the thread that runs next. Memory changes are\n"
            "ADDRESS = 90 90 C3, or ADDRESS = q:VALUE for a 64-bit value; separate\n"
            "several with semicolons.\n"
            "\n"
            "<~N~ew trace:f:1:64::>\n"
            "<~I~nstructions to record (0: until the program exits):D::18::>\n"
            "<~R~egisters (rax=1 rcx=0x10):q::64::>\n"
            "<~M~emory:q::64::>\n"
            "<Registry ~h~ives folder (empty: next to the Sogen backend):F::64::>\n"
            "<##Replay##~S~trict (stop where the replay differs from the recording):C>\n"
            "<~A~llow a recording made against the host to touch this machine:C>>\n"
            "\n";

        char path[QMAXPATH];
        qstrncpy(path, default_fork_path(mgr()).c_str(), sizeof(path));
        static sval_t count = 1000000;
        static qstring regs_text, mem_text;
        char registry[QMAXPATH];
        qstrncpy(registry, saved_registry_dir().c_str(), sizeof(registry));
        ushort strict = 0;

        ForkRequest req;
        for ( ;; )
        {
            if ( ask_form(form, path, &count, &regs_text, &mem_text, registry, &strict) <= 0 )
                return 1;
            qstring err;
            if ( !parse_fork_registers(regs_text.c_str(), &req.regs, &err)
              || !parse_fork_memory(mem_text.c_str(), &req.memory, &err) )
            {
                warning("%s", err.c_str());
                continue;
            }
            if ( path[0] == '\0' )
            {
                warning("Name the file the new trace goes into.");
                continue;
            }
            if ( qfileexist(path)
              && ask_yn(ASKBTN_NO, "%s already exists. Replace it?", path) != ASKBTN_YES )
                continue;
            break;
        }
        save_registry_dir(registry);

        req.at               = mgr()->current_position();
        req.path             = path;
        req.max_instructions = count > 0 ? (uint64_t)count : 0;
        req.registry_dir     = registry;
        req.strict           = (strict & 1) != 0;
        req.allow_host       = (strict & 2) != 0;
        req.note.sprnt("forked at %s", format_position(req.at).c_str());
        if ( !regs_text.empty() )
            req.note.cat_sprnt("; registers: %s", regs_text.c_str());
        if ( !mem_text.empty() )
            req.note.cat_sprnt("; memory: %s", mem_text.c_str());

        ForkResult r = run_fork(mgr(), req);
        if ( !r.ok )
        {
            if ( r.cancelled )
                msg("[ida-ttd] fork cancelled.\n");
            else
                warning("The fork failed: %s", r.error.c_str());
            return 1;
        }
        msg("[ida-ttd] forked at %s: %llu instruction(s) recorded into %s%s.\n",
            format_position(req.at).c_str(), (unsigned long long)r.instructions, path,
            r.cancelled ? " (stopped early; what ran is a complete trace)" : "");
        if ( ask_yn(ASKBTN_YES, "HIDECANCEL\nRecorded %llu instruction(s) into\n%s\n\n"
                                "Open it in a new IDA window?",
                    (unsigned long long)r.instructions, path) == ASKBTN_YES
          && !open_in_new_ida(path) )
            warning("Could not start another IDA. Open %s from IDA's File menu.", path);
        return 1;
    }

    action_state_t idaapi ForkHandler::update(action_update_ctx_t *)
    {
        return backend_forks(mgr()) ? AST_ENABLE : AST_DISABLE;
    }
}
