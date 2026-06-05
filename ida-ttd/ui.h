#pragma once

#include "pch.h"
#include "trace_manager.h"

namespace idattd
{
    // A non-modal "Timeline" chooser listing notable trace positions
    // (thread create/exit, module load/unload, exceptions). Double-clicking a
    // row moves the cursor to that position.
    class PositionChooser : public chooser_t
    {
    public:
        explicit PositionChooser(TraceManager *mgr);

        size_t idaapi get_count() const override;
        void   idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
        ea_t   idaapi get_ea(size_t n) const override;

    private:
        TraceManager                            *m_mgr;
        std::vector<TraceManager::NamedPosition> m_positions;
    };

    // ---- Action handlers ---------------------------------------------------
    struct StepBackHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override { return AST_ENABLE_ALWAYS; }
    };

    struct OpenTimelineHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override { return AST_ENABLE_ALWAYS; }
    };

    struct GotoPositionHandler : public action_handler_t
    {
        TraceManager *mgr = nullptr;
        int           idaapi activate(action_activation_ctx_t *) override;
        action_state_t idaapi update(action_update_ctx_t *) override { return AST_ENABLE_ALWAYS; }
    };

    // Action identifiers (used for registration + toolbar attach/detach).
    namespace actions
    {
        constexpr const char *STEP_BACK   = "idattd:step_back";
        constexpr const char *TIMELINE    = "idattd:timeline";
        constexpr const char *GOTO_POS    = "idattd:goto_position";
    }
}
