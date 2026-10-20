#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    // A saved point in the recording. The position is the real identity; the
    // address and thread are captured alongside it so the list can be read
    // without seeking the cursor to every row.
    struct Bookmark
    {
        Position pos{};
        ea_t                  ea  = BADADDR;
        uint32_t              tid = 0;
        qstring               name;
        qstring               comment;
        // The recording it was made in (trace_store's fingerprint), so a mark
        // left in a recording that has since been re-recorded, or in a fork
        // opened in the same database, is not taken for a position in this
        // one. Zero: not known (saved before marks carried it, or made with
        // no fingerprint), and then it is trusted, as trace_store does.
        uint64_t              trace = 0;

        // Made in a different recording from the one open now.
        bool from_other_recording() const;
    };

    // Bookmarks live in the IDB, not in the trace: they are the analyst's notes
    // about a recording they keep coming back to, and they must survive closing
    // IDA. Storage is one netnode blob rewritten on every change -- bookmark
    // lists are tens of entries, so there is nothing to gain from a per-item
    // layout, and a single blob cannot end up half-updated.
    class BookmarkStore
    {
    public:
        size_t          size();
        const Bookmark *at(size_t i);
        // Insert keeping the list ordered by trace position, and return the index
        // the new entry landed on so a chooser can select it.
        size_t          add(const Bookmark &b);
        void            update(size_t i, const Bookmark &b);
        void            remove(size_t i);

        // Drop the in-memory copy so the next access re-reads the IDB. Called
        // when a trace session ends: the next one may be a different database.
        void            invalidate() { m_loaded = false; m_foreign = false; m_items.clear(); }

    private:
        void            load();
        void            save() const;

        std::vector<Bookmark> m_items;
        bool                  m_loaded = false;
        // The database holds a record this build cannot read (a newer
        // plugin's, say). It is never written over: that would lose it.
        bool                  m_foreign = false;
    };
}
