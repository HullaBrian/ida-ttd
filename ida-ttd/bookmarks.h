#pragma once

#include "pch.h"

namespace idattd
{
    // A saved point in the recording. The position is the real identity; the
    // address and thread are captured alongside it so the list can be read
    // without seeking the cursor to every row.
    struct Bookmark
    {
        TTD::Replay::Position pos{};
        ea_t                  ea  = BADADDR;
        uint32_t              tid = 0;
        qstring               name;
        qstring               comment;
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
        void            invalidate() { m_loaded = false; m_items.clear(); }

    private:
        void            load();
        void            save() const;

        std::vector<Bookmark> m_items;
        bool                  m_loaded = false;
    };
}
