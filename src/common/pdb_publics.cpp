#include "common/pdb_publics.h"

#include <cstdio>
#include <cstring>
#include <memory>

namespace idattd
{
    namespace
    {
        // The MSF 7.00 container ("big MSF") and the streams the public
        // symbols need, per llvm.org/docs/PDB/ and Microsoft's microsoft-pdb:
        //
        //   superblock   magic, block size, ..., directory size, block map addr
        //   directory    stream count, every stream's size, every stream's blocks
        //   stream 3     DBI: names the symbol record stream, and its optional
        //                debug header names the section header stream (and an
        //                OMAP stream when the image was rearranged after linking)
        //   symbol records: S_PUB32 { flags, offset, segment, name }
        const char     kMagic[]      = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0";
        const size_t   kMagicSize    = 32;
        const uint32_t kDbiStream    = 3;
        const uint16_t kNilStream    = 0xFFFF;
        const uint16_t S_PUB32       = 0x110E;
        const uint32_t kPubCode      = 0x1;     // cvpsfCode
        const uint32_t kPubFunction  = 0x2;     // cvpsfFunction

        // Optional debug header slots (DbgHeaderType).
        const size_t   kDbgOmapFromSrc  = 4;
        const size_t   kDbgSectionHdr   = 5;

        // Allocation bounds against damaged or hostile files. The biggest
        // system PDBs are a few hundred MB, with streams well under the cap.
        const uint32_t kMaxStreams      = 1u << 20;
        const uint64_t kMaxStreamBytes  = 1ull << 30;

        uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
        uint32_t rd32(const uint8_t *p)
        {
            return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
                 | ((uint32_t)p[3] << 24);
        }

        struct FileCloser { void operator()(FILE *f) const { if ( f != nullptr ) fclose(f); } };

        class Msf
        {
        public:
            bool open(const wchar_t *path, std::string *error)
            {
                FILE *f = nullptr;
                if ( _wfopen_s(&f, path, L"rb") != 0 || f == nullptr )
                    return fail(error, "cannot open the file");
                m_file.reset(f);
                if ( _fseeki64(f, 0, SEEK_END) != 0 )
                    return fail(error, "cannot read the file");
                m_fileSize = (uint64_t)_ftelli64(f);

                uint8_t sb[kMagicSize + 24];
                if ( !read_at(0, sb, sizeof(sb)) || memcmp(sb, kMagic, kMagicSize) != 0 )
                    return fail(error, "not an MSF 7.00 PDB");
                m_blockSize      = rd32(sb + kMagicSize + 0);
                uint32_t nblocks = rd32(sb + kMagicSize + 8);
                uint32_t dirSize = rd32(sb + kMagicSize + 12);
                uint32_t mapAddr = rd32(sb + kMagicSize + 20);
                if ( m_blockSize != 512 && m_blockSize != 1024 && m_blockSize != 2048
                  && m_blockSize != 4096 && m_blockSize != 8192 && m_blockSize != 16384
                  && m_blockSize != 32768 )
                    return fail(error, "unexpected MSF block size");
                if ( (uint64_t)nblocks * m_blockSize > m_fileSize + m_blockSize )
                    return fail(error, "the file is shorter than its header says");
                m_nblocks = nblocks;
                if ( dirSize < 4 || dirSize > kMaxStreamBytes || !fits(dirSize) )
                    return fail(error, "bad stream directory size");
                if ( mapAddr >= m_nblocks )
                    return fail(error, "bad block map address");

                // The block map is one block listing the directory's blocks.
                uint32_t dirBlocks = blocks_for(dirSize);
                if ( (uint64_t)dirBlocks * 4 > m_blockSize )
                    return fail(error, "the stream directory does not fit its block map");
                std::vector<uint8_t> map((size_t)dirBlocks * 4);
                if ( !read_at((uint64_t)mapAddr * m_blockSize, map.data(), map.size()) )
                    return fail(error, "cannot read the stream directory's block map");
                std::vector<uint32_t> dirList(dirBlocks);
                for ( uint32_t i = 0; i < dirBlocks; i++ )
                    dirList[i] = rd32(&map[i * 4]);
                std::vector<uint8_t> dir;
                if ( !gather(dirList, dirSize, dir) )
                    return fail(error, "cannot read the stream directory");

                uint32_t nstreams = rd32(dir.data());
                if ( nstreams > kMaxStreams || 4 + (uint64_t)nstreams * 4 > dir.size() )
                    return fail(error, "bad stream count");
                m_sizes.resize(nstreams);
                m_blocks.resize(nstreams);
                size_t at = 4 + (size_t)nstreams * 4;
                for ( uint32_t s = 0; s < nstreams; s++ )
                {
                    uint32_t size = rd32(&dir[4 + (size_t)s * 4]);
                    if ( size == 0xFFFFFFFF )
                        size = 0;       // a deleted (nil) stream
                    if ( !fits(size) )
                        return fail(error, "a stream is larger than the file");
                    m_sizes[s] = size;
                    uint32_t n = blocks_for(size);
                    if ( at + (uint64_t)n * 4 > dir.size() )
                        return fail(error, "the stream directory ends early");
                    m_blocks[s].resize(n);
                    for ( uint32_t b = 0; b < n; b++ )
                        m_blocks[s][b] = rd32(&dir[at + (size_t)b * 4]);
                    at += (size_t)n * 4;
                }
                return true;
            }

            bool stream(uint32_t index, std::vector<uint8_t> &out) const
            {
                if ( index >= m_sizes.size() || m_sizes[index] > kMaxStreamBytes )
                    return false;
                return gather(m_blocks[index], m_sizes[index], out);
            }

        private:
            static bool fail(std::string *error, const char *why)
            {
                if ( error != nullptr )
                    *error = why;
                return false;
            }

            // A stream cannot hold more bytes than the file has blocks; checked
            // before any buffer is sized from an untrusted length.
            bool fits(uint32_t size) const
            {
                return (uint64_t)size <= (uint64_t)m_nblocks * m_blockSize;
            }

            uint32_t blocks_for(uint32_t size) const
            {
                return (uint32_t)(((uint64_t)size + m_blockSize - 1) / m_blockSize);
            }

            bool read_at(uint64_t off, void *buf, size_t size) const
            {
                if ( off > m_fileSize || size > m_fileSize - off )
                    return false;
                if ( _fseeki64(m_file.get(), (long long)off, SEEK_SET) != 0 )
                    return false;
                return fread(buf, 1, size, m_file.get()) == size;
            }

            bool gather(const std::vector<uint32_t> &blocks, uint32_t size,
                        std::vector<uint8_t> &out) const
            {
                // Every block index must name a block of the file, and the
                // list must be long enough for 'size', before allocating.
                if ( !fits(size) || (uint64_t)blocks.size() * m_blockSize < size )
                    return false;
                out.resize(size);
                size_t done = 0;
                for ( uint32_t b : blocks )
                {
                    if ( done >= size )
                        break;
                    if ( b >= m_nblocks )
                        return false;
                    size_t n = size - done < m_blockSize ? size - done : m_blockSize;
                    if ( !read_at((uint64_t)b * m_blockSize, out.data() + done, n) )
                        return false;
                    done += n;
                }
                return done == size;
            }

            std::unique_ptr<FILE, FileCloser>   m_file;
            uint64_t                            m_fileSize  = 0;
            uint32_t                            m_blockSize = 0;
            uint32_t                            m_nblocks   = 0;
            std::vector<uint32_t>               m_sizes;
            std::vector<std::vector<uint32_t>>  m_blocks;
        };
    }

    bool read_pdb_publics(const wchar_t *path, std::vector<PdbPublic> &out, std::string *error)
    {
        out.clear();
        Msf msf;
        if ( !msf.open(path, error) )
            return false;

        auto fail = [&](const char *why)
        {
            if ( error != nullptr )
                *error = why;
            return false;
        };

        // DBI header (64 bytes): the symbol record stream at 20, then the
        // substream sizes. The optional debug header is the last substream,
        // after the EC substream.
        std::vector<uint8_t> dbi;
        if ( !msf.stream(kDbiStream, dbi) || dbi.size() < 64 )
            return fail("no DBI stream");
        if ( (int32_t)rd32(&dbi[0]) != -1 )
            return fail("an old-format DBI stream");
        uint16_t symStream = rd16(&dbi[20]);
        int32_t  sizes[6]  =
        {
            (int32_t)rd32(&dbi[24]),    // module info
            (int32_t)rd32(&dbi[28]),    // section contributions
            (int32_t)rd32(&dbi[32]),    // section map
            (int32_t)rd32(&dbi[36]),    // source info
            (int32_t)rd32(&dbi[40]),    // type server map
            (int32_t)rd32(&dbi[52]),    // EC substream
        };
        int32_t dbgSize = (int32_t)rd32(&dbi[48]);
        uint64_t at = 64;
        for ( int32_t s : sizes )
        {
            if ( s < 0 )
                return fail("a damaged DBI stream");
            at += (uint64_t)s;
        }
        if ( dbgSize < 0 || at + (uint64_t)dbgSize > dbi.size() )
            return fail("a damaged DBI stream");
        auto dbg_stream = [&](size_t slot) -> uint16_t
        {
            if ( (slot + 1) * 2 > (size_t)dbgSize )
                return kNilStream;
            return rd16(&dbi[(size_t)at + slot * 2]);
        };

        // An OMAP image's public offsets use the pre-rearrangement layout;
        // these section headers would put every name in the wrong place.
        uint16_t omap = dbg_stream(kDbgOmapFromSrc);
        std::vector<uint8_t> omapBytes;
        if ( omap != kNilStream && msf.stream(omap, omapBytes) && !omapBytes.empty() )
            return fail("the image was rearranged after linking (OMAP)");

        // IMAGE_SECTION_HEADER is 40 bytes, VirtualAddress at 12. A public's
        // segment n is section n, counted from one.
        std::vector<uint8_t> sh;
        uint16_t shStream = dbg_stream(kDbgSectionHdr);
        if ( shStream == kNilStream || !msf.stream(shStream, sh) || sh.size() < 40 )
            return fail("no section headers");
        std::vector<uint32_t> sectionRva(sh.size() / 40);
        for ( size_t i = 0; i < sectionRva.size(); i++ )
            sectionRva[i] = rd32(&sh[i * 40 + 12]);

        std::vector<uint8_t> sym;
        if ( symStream == kNilStream || !msf.stream(symStream, sym) )
            return fail("no symbol record stream");

        // Records: u16 length (not counting itself), u16 kind, then the body.
        for ( size_t p = 0; p + 4 <= sym.size(); )
        {
            uint16_t len  = rd16(&sym[p]);
            uint16_t kind = rd16(&sym[p + 2]);
            if ( len < 2 || p + 2 + len > sym.size() )
                break;          // the rest is damaged; keep what was read
            if ( kind == S_PUB32 && len >= 2 + 10 + 1 )
            {
                const uint8_t *b   = &sym[p + 4];
                uint32_t flags     = rd32(b);
                uint32_t offset    = rd32(b + 4);
                uint16_t segment   = rd16(b + 8);
                const char *name   = (const char *)(b + 10);
                size_t maxName     = (size_t)len - 2 - 10;
                size_t nameLen     = strnlen(name, maxName);
                if ( segment >= 1 && segment <= sectionRva.size() && nameLen > 0 )
                {
                    PdbPublic pub;
                    pub.rva  = sectionRva[segment - 1] + offset;
                    pub.code = (flags & (kPubCode | kPubFunction)) != 0;
                    pub.name.assign(name, nameLen);
                    out.push_back(std::move(pub));
                }
            }
            p += 2 + (size_t)len;
        }
        if ( out.empty() )
            return fail("no public symbols");
        return true;
    }
}
