#include "common/symsrv.h"
#include "common/strings.h"
#include "common/local_path.h"

#include <condition_variable>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

namespace idattd
{
    // Where PDBs come from: Microsoft's server unless the symbol_server setting
    // names another (symsrv_configure). Set at plugin load, before any fetch,
    // and copied into each fetch so workers never read the global.
    struct Server
    {
        bool          enabled = true;
        qstring       url     = "https://msdl.microsoft.com/download/symbols";
        std::wstring  host    = L"msdl.microsoft.com";
        INTERNET_PORT port    = INTERNET_DEFAULT_HTTPS_PORT;
        bool          secure  = true;
        std::wstring  root    = L"/download/symbols";
    };
    static Server g_server;
    // The conventional symbol-client user agent; some servers serve only it.
    static const wchar_t SYM_AGENT[] = L"Microsoft-Symbol-Server/10.0.0.0";

    // Timeouts in milliseconds: generous on receive (a PDB can be tens of MB),
    // tight on connect (an unreachable server is the case this file is for).
    static const int TMO_RESOLVE = 5000;
    static const int TMO_CONNECT = 5000;
    static const int TMO_SEND    = 15000;
    static const int TMO_RECEIVE = 60000;

    // Asking for dozens of PDBs at once made the server stop answering some
    // of them on a fresh machine (ntdll's among them). So a few at a time,
    // and an unanswered request is retried after a pause.
    static const size_t MAX_PARALLEL = 4;
    static const int    ATTEMPTS     = 3;
    static const int    RETRY_MS[]   = { 2000, 6000 };

    namespace
    {
        // A download thread and the flag it sets when it has finished, so
        // fetch_pdb can join it without blocking.
        struct Worker
        {
            std::thread                        thread;
            std::shared_ptr<std::atomic<bool>> done;
        };

        struct State
        {
            std::mutex               mtx;
            std::vector<Worker>      workers;
            std::vector<FetchResult> completed;
            std::set<qstring>        seen;      // identities being fetched now
            size_t                   pending = 0;
            size_t                   running = 0;   // downloads holding a slot
            std::condition_variable  cv;            // a slot freed, or abort
            std::atomic<bool>        abort{ false };
            // Requests a worker may be blocked in. Closing one from another
            // thread makes the blocked WinHTTP call fail at once; the abort
            // flag is only checked between reads.
            std::set<HINTERNET>      live;
        };

        State &state()
        {
            static State s;
            return s;
        }

        // Create every level of 'dir'. A failure at any level is harmless:
        // either it exists, or the file create that needs it fails and is
        // reported there.
        void make_dirs(const qstring &dir)
        {
            qstring cur;
            for ( size_t i = 0; i < dir.length(); i++ )
            {
                cur.append(dir[i]);
                if ( dir[i] == '/' || dir[i] == '\\' || i + 1 == dir.length() )
                    qmkdir(cur.c_str(), 0755);
            }
        }

        // A closer for every HINTERNET, so no early return leaks one.
        struct Handle
        {
            HINTERNET h = nullptr;
            ~Handle() { if ( h != nullptr ) WinHttpCloseHandle(h); }
            operator HINTERNET() const { return h; }
        };

        // Download one PDB to 'dest' via a ".part" file renamed on success, so
        // an interrupted fetch never leaves a short file that looks complete.
        // '*again' says whether a retry is worthwhile (no answer, or busy),
        // as opposed to a PDB the server does not have.
        bool download(const Server &srv, const std::wstring &url_path, const qstring &dest,
                      qstring *err, bool *again)
        {
            *again = false;
            Handle session;
            session.h = WinHttpOpen(SYM_AGENT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if ( session.h == nullptr )
            {
                *err = "could not open an HTTP session";
                return false;
            }
            WinHttpSetTimeouts(session.h, TMO_RESOLVE, TMO_CONNECT, TMO_SEND, TMO_RECEIVE);

            Handle conn;
            conn.h = WinHttpConnect(session.h, srv.host.c_str(), srv.port, 0);
            if ( conn.h == nullptr )
            {
                *err = "could not reach the symbol server";
                *again = true;
                return false;
            }

            Handle req;
            req.h = WinHttpOpenRequest(conn.h, L"GET", url_path.c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       srv.secure ? WINHTTP_FLAG_SECURE : 0);
            if ( req.h == nullptr )
            {
                *err = "could not build the request";
                return false;
            }

            // Register the request so symsrv_shutdown() can cancel it, and
            // unregister on the way out. If shutdown already closed the
            // handle, it must not be closed again here.
            {
                std::lock_guard<std::mutex> lock(state().mtx);
                if ( state().abort.load() )
                {
                    *err = "canceled";
                    return false;
                }
                state().live.insert(req.h);
            }
            struct Unregister
            {
                Handle &req;
                ~Unregister()
                {
                    std::lock_guard<std::mutex> lock(state().mtx);
                    if ( state().live.erase(req.h) == 0 )
                        req.h = nullptr;
                }
            } unregister{ req };

            if ( !WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
              || !WinHttpReceiveResponse(req.h, nullptr) )
            {
                *err = "no response from the symbol server";
                *again = true;
                return false;
            }

            DWORD status = 0, len = sizeof(status);
            if ( !WinHttpQueryHeaders(req.h,
                                      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                      WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                                      WINHTTP_NO_HEADER_INDEX) )
            {
                *err = "no status from the symbol server";
                return false;
            }
            if ( status != 200 )
            {
                err->sprnt("the symbol server answered %d", (int)status);
                *again = status == 429 || status >= 500;
                return false;
            }

            qstring tmp = dest;
            tmp.append(".part");
            // qfopen, like the qrename/qunlink below, takes IDA's UTF-8 paths.
            FILE *f = qfopen(tmp.c_str(), "wb");
            if ( f == nullptr )
            {
                err->sprnt("could not write %s", tmp.c_str());
                return false;
            }

            // The body becomes the PDB that IDA's PDB plugin and the publics
            // reader open, so it is checked before it is renamed into the
            // store: an error page, a captive portal's answer or a hostile
            // server's endless body must not land there. Only uncompressed
            // PDBs are requested (no .pd_), so the MSF 7.00 magic must lead.
            static const char     kMsfMagic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0";
            static const size_t   kMsfMagicSize = 32;
            static const uint64_t kMaxBody = 1ull << 30;   // far above any real PDB
            char     head[kMsfMagicSize] = { 0 };
            uint64_t total = 0;

            std::vector<char> buf(64 * 1024);
            bool ok = true;
            for ( ;; )
            {
                if ( state().abort.load() )
                {
                    *err = "canceled";
                    ok = false;
                    break;
                }
                DWORD got = 0;
                if ( !WinHttpReadData(req.h, buf.data(), (DWORD)buf.size(), &got) )
                {
                    *err = "the download was interrupted";
                    *again = true;
                    ok = false;
                    break;
                }
                if ( got == 0 )
                    break;                          // end of body
                if ( total < kMsfMagicSize )
                {
                    size_t n = (size_t)qmin((uint64_t)got, kMsfMagicSize - total);
                    memcpy(head + total, buf.data(), n);
                }
                total += got;
                if ( total > kMaxBody )
                {
                    *err = "the symbol server's answer is too large to be a PDB";
                    ok = false;
                    break;
                }
                if ( fwrite(buf.data(), 1, got, f) != got )
                {
                    *err = "could not write the downloaded file";
                    ok = false;
                    break;
                }
            }
            qfclose(f);

            if ( ok && (total < kMsfMagicSize || memcmp(head, kMsfMagic, kMsfMagicSize) != 0) )
            {
                *err = "the symbol server's answer is not a PDB";
                ok = false;
            }

            if ( !ok || qrename(tmp.c_str(), dest.c_str()) != 0 )
            {
                qunlink(tmp.c_str());
                if ( ok )
                    *err = "could not move the downloaded file into place";
                return false;
            }
            return true;
        }

        // Up to ATTEMPTS downloads, holding one MAX_PARALLEL slot throughout.
        // Pauses between attempts end early on shutdown.
        bool download_with_retries(const Server &srv, const std::wstring &url_path, const qstring &dest,
                                   qstring *err)
        {
            State &s = state();
            {
                std::unique_lock<std::mutex> lock(s.mtx);
                s.cv.wait(lock, [&] { return s.abort.load() || s.running < MAX_PARALLEL; });
                if ( s.abort.load() )
                {
                    *err = "canceled";
                    return false;
                }
                s.running++;
            }
            bool ok = false;
            for ( int attempt = 0; attempt < ATTEMPTS; attempt++ )
            {
                bool again = false;
                ok = download(srv, url_path, dest, err, &again);
                if ( ok || !again || attempt + 1 == ATTEMPTS )
                    break;
                std::unique_lock<std::mutex> lock(s.mtx);
                if ( s.cv.wait_for(lock, std::chrono::milliseconds(RETRY_MS[attempt]),
                                   [&] { return s.abort.load(); }) )
                    break;
            }
            {
                std::lock_guard<std::mutex> lock(s.mtx);
                s.running--;
            }
            s.cv.notify_all();
            return ok;
        }
    }

    qstring symbol_store_dir()
    {
        // Under LOCALAPPDATA rather than temp: PDBs are expensive to fetch and
        // worth keeping across reboots. qgetenv, not getenv: IDA's file
        // functions take UTF-8, and getenv's ANSI text mangles a profile path
        // outside the code page.
        qstring dir;
        qstring local;
        if ( qgetenv("LOCALAPPDATA", &local) && !local.empty() )
            dir.sprnt("%s/ida-ttd/symbols", local.c_str());
        else
            dir = "ida-ttd-symbols";
        return dir;
    }

    // Name and signature become store directory and file names and URL path
    // segments, and the name comes from the recorded image (written by the
    // malware author, for a malware recording). Only the characters of real
    // PDB names and signatures are accepted: no separators, drive or stream
    // colons, URL metacharacters, "." or "..", and a bounded length.
    static bool safe_component(const char *s)
    {
        size_t n = strlen(s);
        if ( n == 0 || n > 128 || strcmp(s, ".") == 0 || strcmp(s, "..") == 0 )
            return false;
        // "nul.pdb" would name a device, not a file in the store.
        if ( is_dos_device_name(s, n) )
            return false;
        for ( size_t i = 0; i < n; i++ )
        {
            unsigned char c = (unsigned char)s[i];
            bool alnum = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
                      || (c >= 'a' && c <= 'z');
            if ( !(alnum || c == '.' || c == '_' || c == '-' || c == '+') )
                return false;
        }
        return true;
    }

    qstring symbol_store_path(const char *name, const char *signature)
    {
        qstring p;
        if ( name == nullptr || signature == nullptr
          || !safe_component(name) || !safe_component(signature) )
        {
            return p;
        }
        p.sprnt("%s/%s/%s/%s", symbol_store_dir().c_str(), name, signature, name);
        return p;
    }

    void symsrv_install_path()
    {
        qstring store = symbol_store_dir();
        qstring want;
        // With downloads off, the store alone, so IDA's PDB plugin does not
        // fetch either.
        if ( g_server.enabled )
            want.sprnt("srv*%s*%s", store.c_str(), g_server.url.c_str());
        else
            want.sprnt("srv*%s", store.c_str());

        // Keep the user's path after this one: their store may hold PDBs the
        // public server lacks.
        qstring existing;
        if ( qgetenv("_NT_SYMBOL_PATH", &existing) && !existing.empty() )
        {
            if ( existing.find(store) != qstring::npos )
                return;                     // already installed this session
            want.cat_sprnt(";%s", existing.c_str());
        }
        qsetenv("_NT_SYMBOL_PATH", want.c_str());
    }

    bool symsrv_configure(bool enabled, const char *url)
    {
        Server srv;
        srv.enabled = enabled;
        if ( url != nullptr && url[0] != '\0' && strcmp(url, srv.url.c_str()) != 0 )
        {
            // WinHttpCrackUrl returns pointers into its input, so the wide
            // copy must outlive the uses below.
            std::wstring wurl = to_wstring(url);
            URL_COMPONENTS uc = { sizeof(uc) };
            uc.dwHostNameLength = (DWORD)-1;
            uc.dwUrlPathLength  = (DWORD)-1;
            if ( !WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc) || uc.dwHostNameLength == 0
              || (uc.nScheme != INTERNET_SCHEME_HTTPS && uc.nScheme != INTERNET_SCHEME_HTTP) )
            {
                g_server.enabled = enabled;
                return false;               // keep the server, honour the switch
            }
            srv.url    = url;
            srv.host   = std::wstring(uc.lpszHostName, uc.dwHostNameLength);
            srv.port   = uc.nPort;
            srv.secure = uc.nScheme == INTERNET_SCHEME_HTTPS;
            srv.root   = std::wstring(uc.lpszUrlPath, uc.dwUrlPathLength);
            while ( !srv.root.empty() && srv.root.back() == L'/' )
                srv.root.pop_back();
        }
        g_server = srv;
        return true;
    }

    qstring symsrv_server_url()
    {
        return g_server.url;
    }

    FetchState fetch_pdb(const char *name, const char *signature, ea_t base)
    {
        qstring dest = symbol_store_path(name, signature);
        if ( dest.empty() )
            return FetchState::Failed;
        if ( qfileexist(dest.c_str()) )
            return FetchState::Cached;
        if ( !g_server.enabled )
            return FetchState::Off;

        State &s = state();
        if ( s.abort.load() )
            return FetchState::Failed;

        qstring key;
        key.sprnt("%s/%s", name, signature);

        std::lock_guard<std::mutex> lock(s.mtx);
        if ( !s.seen.insert(key).second )
            return FetchState::Fetching;    // already being fetched; it reports when done

        // Join the workers that have finished, so a long session does not
        // keep one thread object per PDB until shutdown. A worker sets its
        // flag as the last thing it does under this lock, so one seen done
        // here has released the lock and only has to return: the join does
        // not wait on anything this thread holds.
        for ( size_t i = 0; i < s.workers.size(); )
        {
            if ( s.workers[i].done->load() )
            {
                if ( s.workers[i].thread.joinable() )
                    s.workers[i].thread.join();
                s.workers.erase(s.workers.begin() + i);
            }
            else
            {
                i++;
            }
        }

        // Create the directory here so all path handling stays on one thread.
        qstring dir;
        dir.sprnt("%s/%s/%s", symbol_store_dir().c_str(), name, signature);
        make_dirs(dir);

        std::wstring url;
        url.append(g_server.root);
        url.append(L"/");
        url.append(to_wstring(name));
        url.append(L"/");
        url.append(to_wstring(signature));
        url.append(L"/");
        url.append(to_wstring(name));

        qstring qname = name;
        s.pending++;
        auto done = std::make_shared<std::atomic<bool>>(false);
        Worker w;
        w.done   = done;
        w.thread = std::thread([srv = g_server, url, dest, qname, key, base, done]()
        {
            qstring err;
            bool ok = download_with_retries(srv, url, dest, &err);

            State &st = state();
            std::lock_guard<std::mutex> l(st.mtx);
            // The key leaves the in-flight set either way: a failed identity
            // may be asked for again (the next stop in its module), and a
            // fetched one is found in the store (Cached) from now on.
            st.seen.erase(key);
            FetchResult r;
            r.base  = base;
            r.name  = qname;
            r.path  = ok ? dest : qstring();
            r.error = ok ? qstring() : err;
            st.completed.push_back(r);
            st.pending--;
            done->store(true);      // last, under the lock (see fetch_pdb)
        });
        s.workers.push_back(std::move(w));
        return FetchState::Fetching;
    }

    size_t symsrv_take_completed(std::vector<FetchResult> *out)
    {
        if ( out == nullptr )
            return 0;
        State &s = state();
        std::lock_guard<std::mutex> lock(s.mtx);
        size_t n = s.completed.size();
        for ( const FetchResult &r : s.completed )
            out->push_back(r);
        s.completed.clear();
        return n;
    }

    size_t symsrv_pending()
    {
        State &s = state();
        std::lock_guard<std::mutex> lock(s.mtx);
        return s.pending;
    }

    void symsrv_shutdown()
    {
        State &s = state();
        s.abort.store(true);
        s.cv.notify_all();      // workers waiting for a slot or between attempts

        // Close every request in flight (so no worker waits out a receive
        // timeout), and move the threads out under the lock, then join outside
        // it: a worker takes the same lock on its way out.
        std::vector<Worker> mine;
        {
            std::lock_guard<std::mutex> lock(s.mtx);
            for ( HINTERNET h : s.live )
                WinHttpCloseHandle(h);
            s.live.clear();
            mine.swap(s.workers);
        }
        for ( Worker &w : mine )
            if ( w.thread.joinable() )
                w.thread.join();

        std::lock_guard<std::mutex> lock(s.mtx);
        s.completed.clear();
        s.seen.clear();
        s.pending = 0;
        s.running = 0;
        s.abort.store(false);
    }
}
