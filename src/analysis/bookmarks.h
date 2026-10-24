#pragma once

#include "common/pch.h"
#include "core/position.h"

namespace idattd
{
    // A saved point in the recording. The position is its identity; address
    // and thread are kept so the list shows without seeking to every row.
    struct Bookmark
    {
        Position pos{};
        ea_t                  ea  = BADADDR;
        uint32_t              tid = 0;
        qstring               name;
        qstring               comment;
        // The recording it was made in (trace_store's fingerprint), so a mark
        // from an older recording, or from a fork opened in the same database,
        // is not taken for a position in this one. Zero means unknown (an old
        // mark, or no fingerprint) and is trusted, as trace_store does.
        uint64_t              trace = 0;

        // Made in a different recording from the one open now.
        bool from_other_recording() const;
    };

    // Bookmarks live in the IDB so they survive closing IDA. Storage is one
    // netnode blob rewritten on every change: lists are tens of entries, and a
    // single blob cannot end up half-updated.
    class BookmarkStore
    {
    public:
        size_t          size();
        const Bookmark *at(size_t i);
        // Insert in position order; returns the new entry's index so a chooser
        // can select it.
        size_t          add(const Bookmark &b);
        // Replace entry 'i', keeping position order; returns its new index
        // ('i' itself when out of range).
        size_t          update(size_t i, const Bookmark &b);
        void            remove(size_t i);

        // Drop the in-memory copy so the next access re-reads the IDB. Called
        // when a session ends, since the next may use a different database.
        void            invalidate() { m_loaded = false; m_foreign = false; m_items.clear(); }

    private:
        void            load();
        void            save() const;

        std::vector<Bookmark> m_items;
        bool                  m_loaded = false;
        // The database holds a record this build cannot read (e.g. a newer
        // plugin's). It is never overwritten.
        bool                  m_foreign = false;
    };
}
