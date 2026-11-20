# String and buffer recovery: the rules

What `src/common/write_scans.h` computes, stated as behavior. Both backends
feed it (the Microsoft backend from watchpoint replays, the Sogen backend from
recorded write events), and both lists are meant to read the same as Sogen's
own TTD string and buffer listings, so the rules (what counts as a string,
which limits apply, which kinds a buffer gets) follow Sogen's.

`write_scans.h` is an implementation written from this document alone, not a
port of Sogen's source: the observable rules are shared, the code is ida-ttd's
(Apache-2.0). When a rule changes, change this document with it.

All byte values are unsigned. A byte is **printable** when it is in
0x20..0x7E inclusive. "Run" always means a maximal run.

## Interface

Header-only, standard library only (the Sogen backend builds without the rest
of the plugin), namespace `idattd::scans`. `Pos` is the backend's position
type, copied through untouched.

Constants callers use: `kStringMaximum = 4096`, `kStringContext = 512`,
`kScanChunk = 65536` (the last two are how callers window memory for
`StringScan::inspect`: chunks of 64 KiB with 512 bytes of overlap each side),
and `kMaximumRegion = 256 * 1024`, the longest a buffer region grows (the
Sogen backend splits long writes by it). All `size_t`.

### `StringScan<Pos>`

- `StringScan(size_t minimum, size_t cap = 500000)`
- `bool truncated` (public, starts false)
- `struct Entry { Pos pos; bool wide; std::string value; }`
- `void inspect(uint64_t address, const std::vector<uint8_t> &bytes, const Pos &pos)`
- `template <typename Fn> void for_each(Fn fn) const`, calls `fn(uint64_t address, const Entry &)`
- `size_t minimum() const`

### `BufferScan<Pos>`

- `explicit BufferScan(uint64_t nearby)`
- `bool truncated` (public, starts false)
- `std::vector<FoundBuffer<Pos>> results` (public)
- `void ingest(uint64_t address, const uint8_t *bytes, size_t size, uint64_t clock, const Pos &pos, uint64_t ip)`
- `void executed(uint64_t address, size_t size)`
- `void mapping_changed(uint64_t address, uint64_t size)`
- `void finish()`

`FoundBuffer<Pos>` has public fields `uint64_t address = 0, size = 0;
Pos first, last; uint64_t writer_ip = 0, writes = 0; std::string kind,
preview;`.

## Strings

`inspect` looks at one window of memory, `bytes` at `address`, and offers
every string in it to the collection with position `pos`. First every ASCII
string in the window, in address order, then every UTF-16LE one, in order of
start offset.

**ASCII.** Each run of printable bytes `[i, e)` is a string when its length is
at least `minimum`, at most 4096, and the window has a byte at `e` that is
0x00 (a run that reaches the end of the window is not one). Runs longer than
4096 are rejected outright, not cut.

**UTF-16LE.** A *pair* at offset `k` is a printable byte at `k` followed by
0x00 at `k + 1`. Every offset `i` with `i + 1 < size` is a candidate start
when there is a pair at `i` and there is not a pair at `i - 2` (only checked
when `i >= 2`). From `i`, consecutive pairs at `i, i + 2, i + 4, ...` give the
characters (the low bytes), stopping at the first offset that is not a pair,
whose high byte would lie outside the window, or once 4096 characters have
been taken. It is a string when it has at least `minimum` characters and the
two bytes at the stopping offset exist and are both 0x00. Candidates are
tried at every offset, odd ones included.

**The collection.** Strings are keyed by address; one address can hold
several entries, kept in the order they were added. Offering
`(address, pos, wide, value)`:

1. Go through the entries already at `address`, in order, skipping those
   whose `wide` differs. If one has the same value, nothing changes. If the
   new value is longer and starts with that entry's value, that entry takes
   the new value and the new `pos`, and nothing else happens. The first entry
   that matches either way decides.
2. Otherwise, if the collection already holds `cap` entries, set `truncated`
   and stop (and leave no empty slot for the address behind).
3. Otherwise append the entry at that address.

`for_each` visits addresses in ascending order, and each address's entries in
their order.

## Buffers

### Regions

The scanner keeps *active regions*, keyed by start address. A region has a
byte array and, per byte, a *known* flag (the program wrote it) and an
*executed* flag; the first and last positions written, the clock of the last
write, the instruction address of the last write, and a count of writes.
Regions may overlap one another.

**`ingest`** records one write of `size` bytes at `address`. A write of size
0, or one whose end would pass 2^64, is ignored. Let `end = address + size`.

The *candidate*: take the region with the greatest start not above `address`.
If there is one and its end plus 16 is at least `address`, it is the
candidate. Otherwise (or if there is none) the candidate is the region with
the smallest start above `address`, if any. The candidate is only considered
if its start is at most `end + 16`.

With a candidate (start `s`, end `t`), let the combined span be from
`min(s, address)` to `max(t, end)`, and say the write *reaches* the region
when `address < t`. (That is weaker than overlapping: a write that ends at or
before `s` also reaches it.)

1. If the write reaches the region and changes a byte that is flagged
   executed, within the bytes the write and the region actually share, to a
   different value, the region is emitted and dropped, and the write starts a
   new region (below).
2. Otherwise, if the write reaches the region or comes within `nearby` clock
   ticks of its last write (`clock - last_clock <= nearby`, in unsigned
   arithmetic, so an earlier clock never counts as near), and the combined
   span is at most 256 KiB, the region grows to the combined span. Bytes it
   gains are zero and not known. The written bytes are stored, flagged known
   and not executed. Its last clock, last position and writer address become
   the write's, and its write count goes up by one. Nothing else happens.
3. Otherwise, if the write reaches the region, the region is emitted and
   dropped, and the write starts a new region.
4. Otherwise the region is left alone, and the write starts a new region.

A new region holds exactly the written bytes, all known and not executed, with
first and last position `pos`, last clock `clock`, writer `ip` and one write.
If a region already starts at `address`, that one is emitted and dropped
first. Then, if there are more than 16,384 active regions, one is evicted:
regions shorter than 512 bytes go before longer ones; within that, the one
written longest ago (smallest last clock); among equals, the lowest start. It
is emitted and dropped.

**`executed`** marks `[address, address + size)` as executed: in every active
region that starts at or below `address`, less than 256 KiB below it, and
extends past it, each byte of that range inside the region is flagged
executed if it is known. Regions starting above `address` are not touched.

**`mapping_changed`** says the memory in `[address, address + size)` was
mapped, unmapped or remapped (the end saturates at 2^64; size 0 does nothing).
For each active region overlapping that range, in ascending order, the
overlapping part is emitted as a region of its own (its bytes and flags, the
region's positions, clock, writer and count, starting where the overlap
starts). In the original region those bytes lose their known and executed
flags. A region left with no known byte is dropped.

**`finish`** emits every active region in ascending order and drops them all.

### Emitting a region

At most 20,000 results are ever kept. Once that many are kept, anything more
that would be recorded is dropped and sets `truncated`; nothing else changes.
A region is emitted *segment by segment*: each run
of known bytes, in order. Segments shorter than 16 bytes are skipped. For a segment of `n`
bytes at offset `begin` (address `start + begin`):

**Its kind**, the first rule that applies:

1. A file signature at its start (below).
2. `contains_executed_code` if any of its bytes is flagged executed.
3. `ascii_text` if `n >= 32` and at least 90% of its bytes are printable
   (`printable * 100 >= n * 90`).
4. `utf16le_text` if `n >= 32` and, counting the pairs at even offsets `0, 2,
   ...` (with both bytes inside the segment), `pairs * 100 >= (n / 2) * 85`,
   `n / 2` rounded down.
5. `high_entropy_buffer` if `n >= 256` and its Shannon entropy is at least
   7.5 bits per byte.
6. `buffer` if `n >= 512`.

With a kind, the whole segment is recorded (see Recording). Rule 3's test,
both halves of it (`n >= 32` and 90% printable), is also "the segment is
text" for what follows, whichever rule gave the kind.

**Then the strings in it.** Each run of at least 16 printable bytes, in order,
is recorded as `ascii_string`, except a run that is the whole segment when the
segment is text. At most 128 per segment.

Then UTF-16LE strings: walking offsets from 0, a start is an offset `i` with
`i + 1 < n`, a pair at `i`, and no pair at `i - 2` (when `i >= 2`). From
there, pairs are taken while both bytes are inside the segment. If they cover
at least 24 bytes, they are recorded as `utf16le_string` (size in bytes, the
pairs only). Either way the walk resumes at the offset where the pairs
stopped. At most 128 per segment.

Then embedded files: each offset `i` from 1 while `i + 16 < n`, whose byte is
one of `M`, 0x89, `G`, `%`, `P`, `S`, `-`, and where a file signature starts
that is neither `bmp_image` nor `jpeg_image`: the rest of the segment from
`i` is recorded under that kind. At most 64 per segment.

**Signatures**, checked in this order against the bytes from the start:

| Kind | Rule |
| --- | --- |
| `pe_image` | at least 64 bytes, starting `MZ`; the 32-bit little-endian value at offset 0x3C, `e`, is at most `n - 4`, and the bytes at `e` are `P E 00 00` |
| `elf_image` | 7F `E L F` |
| `png_image` | 89 `P N G` 0D 0A 1A 0A |
| `jpeg_image` | FF D8 FF |
| `gif_image` | `G I F 8` |
| `bmp_image` | `B M` |
| `pdf_document` | `%PDF-` |
| `zip_archive` | `P K` 03 04 |
| `gzip_stream` | 1F 8B 08 |
| `sqlite_database` | `SQLite format 3` 00 |
| `pem_private_key` | starts `-----BEGIN ` and the first 128 bytes (or all, if fewer) contain `PRIVATE KEY-----` |
| `pem_public_key` | the same start, not private, and those bytes contain `PUBLIC KEY-----` |

A prefix only matches when the bytes are at least that long. An `MZ` start
that fails the PE test goes on to the other rows.

**Recording** a part of `n` bytes (`n > 0`) gives a result with its address,
size `n`, the region's first and last positions, writer address and write
count, the kind, and a preview:

- for `utf16le_string`, the low byte of each pair among the first 96 bytes
  (offsets 0, 2, ... while the offset plus one is below `min(n, 96)`), as is;
- otherwise, of the first 48 bytes: each byte as itself if printable and `.`
  if not, for an `ascii_string` and for a whole segment that is text (the
  segment's text test, whatever its kind); each byte as two lowercase hex
  digits for everything else, embedded files included.
