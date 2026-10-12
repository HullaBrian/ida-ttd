#include "common/symsrv.h"

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

namespace idattd
{
    static const wchar_t SYM_HOST[] = L"msdl.microsoft.com";
    static const wchar_t SYM_ROOT[] = L"/download/symbols";
    // The conventional symbol-client user agent. Some symbol servers serve only
    // clients that identify themselves this way.
    static const wchar_t SYM_AGENT[] = L"Microsoft-Symbol-Server/10.0.0.0";

    // Timeouts, in milliseconds. Generous on receive because a PDB can be tens
    // of megabytes, tight on connect because an unreachable server is the case
    // this whole file exists to stop hurting.
    static const int TMO_RESOLVE = 5000;
    static const int TMO_CONNECT = 5000;
    static const int TMO_SEND    = 15000;
    static const int TMO_RECEIVE = 60000;

    namespace
    {
        struct State
        {
            std::mutex               mtx;
            std::vector<std::thread> workers;
            std::vector<FetchResult> completed;
            std::set<qstring>        seen;      // identities asked for this session
            size_t                   pending = 0;
            std::atomic<bool>        abort{ false };
            // Requests a worker is blocked in. Closing one from another thread
            // makes the worker's WinHTTP call fail at once, which is the only
            // way to stop a fetch stuck waiting on a slow server: the abort
            // flag is only looked at between reads.
            std::set<HINTERNET>      live;
        };

        State &state()
        {
            static State s;
            return s;
        }

        std::wstring widen(const char *s)
        {
            if ( s == nullptr || *s == '\0' )
                return std::wstring();
            int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
            if ( n <= 0 )
                return std::wstring();
            std::wstring w((size_t)n - 1, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
            return w;
        }

        // Create every level of 'dir'. qmkdir makes one at a time, and a failure
        // at any level is harmless here: either it already exists, or the create
        // that needs it fails next and is reported there.
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

        // Download one PDB to 'dest'. Writes to a temporary beside it and renames
        // on success, so an interrupted fetch never leaves a short file that a
        // later run would mistake for a complete one.
        bool download(const std::wstring &url_path, const qstring &dest, qstring *err)
        {
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
            conn.h = WinHttpConnect(session.h, SYM_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
            if ( conn.h == nullptr )
            {
                *err = "could not reach the symbol server";
                return false;
            }

            Handle req;
            req.h = WinHttpOpenRequest(conn.h, L"GET", url_path.c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
            if ( req.h == nullptr )
            {
                *err = "could not build the request";
                return false;
            }

            // Make the request cancellable by symsrv_shutdown(), and take it
            // back on the way out. If shutdown got there first it has already
            // closed the handle, so it must not be closed again here.
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
                return false;
            }

            qstring tmp = dest;
            tmp.append(".part");
            FILE *f = fopen(tmp.c_str(), "wb");
            if ( f == nullptr )
            {
                err->sprnt("could not write %s", tmp.c_str());
                return false;
            }

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
                    ok = false;
                    break;
                }
                if ( got == 0 )
                    break;                          // end of body
                if ( fwrite(buf.data(), 1, got, f) != got )
                {
                    *err = "could not write the downloaded file";
                    ok = false;
                    break;
                }
            }
            fclose(f);

            if ( !ok || qrename(tmp.c_str(), dest.c_str()) != 0 )
            {
                qunlink(tmp.c_str());
                if ( ok )
                    *err = "could not move the downloaded file into place";
                return false;
            }
            return true;
        }
    }

    qstring symbol_store_dir()
    {
        // Beside IDA's own user files rather than in the system temp directory:
        // a PDB is expensive to fetch and worth keeping across reboots.
        qstring dir;
        const char *local = getenv("LOCALAPPDATA");
        if ( local != nullptr && local[0] != '\0' )
            dir.sprnt("%s/ida-ttd/symbols", local);
        else
            dir = "ida-ttd-symbols";
        return dir;
    }

    // Both parts end up as a directory and file name in the store and as path
    // segments of a URL, and the name comes out of the recorded image -- which,
    // for a recording of malware, its author wrote. So only what a real PDB name
    // and signature are made of is accepted: no separators, no drive or stream
    // colon, no URL metacharacters, no "." or "..", and a sane length.
    static bool safe_component(const char *s)
    {
        size_t n = strlen(s);
        if ( n == 0 || n > 128 || strcmp(s, ".") == 0 || strcmp(s, "..") == 0 )
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
        want.sprnt("srv*%s*https://msdl.microsoft.com/download/symbols", store.c_str());

        // Keep whatever the user had, after ours: their own store may hold PDBs
        // for modules the public server has never heard of.
        const char *existing = getenv("_NT_SYMBOL_PATH");
        if ( existing != nullptr && existing[0] != '\0' )
        {
            if ( strstr(existing, store.c_str()) != nullptr )
                return;                     // already installed this session
            want.cat_sprnt(";%s", existing);
        }
        qstring assign;
        assign.sprnt("_NT_SYMBOL_PATH=%s", want.c_str());
        _putenv(assign.c_str());
    }

    FetchState fetch_pdb(const char *name, const char *signature, ea_t base)
    {
        qstring dest = symbol_store_path(name, signature);
        if ( dest.empty() )
            return FetchState::Failed;
        if ( qfileexist(dest.c_str()) )
            return FetchState::Cached;

        State &s = state();
        if ( s.abort.load() )
            return FetchState::Failed;

        qstring key;
        key.sprnt("%s/%s", name, signature);

        std::lock_guard<std::mutex> lock(s.mtx);
        if ( !s.seen.insert(key).second )
            return FetchState::Failed;      // asked once already; do not retry

        // The store directory has to exist before the worker writes into it, and
        // creating it here keeps all the path handling on one thread.
        qstring dir;
        dir.sprnt("%s/%s/%s", symbol_store_dir().c_str(), name, signature);
        make_dirs(dir);

        std::wstring url;
        url.append(SYM_ROOT);
        url.append(L"/");
        url.append(widen(name));
        url.append(L"/");
        url.append(widen(signature));
        url.append(L"/");
        url.append(widen(name));

        qstring qname = name;
        s.pending++;
        s.workers.emplace_back([url, dest, qname, base]()
        {
            qstring err;
            bool ok = download(url, dest, &err);

            State &st = state();
            std::lock_guard<std::mutex> l(st.mtx);
            FetchResult r;
            r.base  = base;
            r.name  = qname;
            r.path  = ok ? dest : qstring();
            r.error = ok ? qstring() : err;
            st.completed.push_back(r);
            st.pending--;
        });
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

        // Move the threads out under the lock, then join outside it: a worker
        // takes the same lock on its way out and would deadlock against a join
        // held under it. Close every request in flight first, so no worker is
        // left waiting out a receive timeout while IDA waits on the join.
        std::vector<std::thread> mine;
        {
            std::lock_guard<std::mutex> lock(s.mtx);
            for ( HINTERNET h : s.live )
                WinHttpCloseHandle(h);
            s.live.clear();
            mine.swap(s.workers);
        }
        for ( std::thread &t : mine )
            if ( t.joinable() )
                t.join();

        std::lock_guard<std::mutex> lock(s.mtx);
        s.completed.clear();
        s.seen.clear();
        s.pending = 0;
        s.abort.store(false);
    }
}
