// calltree_py.hh: the call tree window, as IDAPython runs it.
//
// A real tree control (columns, expand arrows, theme colours) is a Qt widget,
// and Hex-Rays steer plugins away from Qt in C++ (it ties the binary to IDA's
// exact Qt build) towards PySide6 in IDAPython. The plugin builds the tree;
// this draws it, fetching it with ttd("ui.calltree") and travelling with
// ttd("ui.travel POS"), the same commands a test uses. Without IDAPython,
// ui_calltree.cpp falls back to a text view.
#pragma once

namespace idattd
{
    static const char CALL_TREE_PY[] = R"PY(
def _ida_ttd_call_tree():
    import json
    import ida_kernwin
    import idc
    from PySide6 import QtCore, QtGui, QtWidgets

    def ttd(cmd):
        # cmd becomes an IDC string literal: escape what would end it early.
        cmd = cmd.replace("\\", "\\\\").replace('"', '\\"')
        return json.loads(idc.eval_idc('ttd("%s")' % cmd))

    data = ttd("ui.calltree")
    if not data.get("ok"):
        raise RuntimeError(data.get("error", "no call tree"))
    tree = data["tree"]

    POS_ROLE = QtCore.Qt.UserRole
    SITE_ROLE = QtCore.Qt.UserRole + 1
    TARGET_ROLE = QtCore.Qt.UserRole + 2
    COLUMNS = ["Call", "Position", "Called from", "Returns at", "Calls"]

    class CallTreeForm(ida_kernwin.PluginForm):
        def OnCreate(self, form):
            self.parent = self.FormToPyQtWidget(form)
            self.view = QtWidgets.QTreeWidget()
            self.view.setColumnCount(len(COLUMNS))
            self.view.setHeaderLabels(COLUMNS)
            self.view.setUniformRowHeights(True)
            # Alternate rows a shade off the background: IDA's dark theme
            # leaves AlternateBase near white, under light text.
            pal = self.view.palette()
            base = pal.color(QtGui.QPalette.Base)
            alt = base.lighter(118) if base.lightness() < 128 else base.darker(104)
            pal.setColor(QtGui.QPalette.AlternateBase, alt)
            self.view.setPalette(pal)
            self.view.setAlternatingRowColors(True)
            self.view.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
            self.view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
            self.view.customContextMenuRequested.connect(self.menu)
            self.view.itemActivated.connect(lambda item, col: self.travel(item))

            self.filter = QtWidgets.QLineEdit()
            self.filter.setPlaceholderText("Filter by function name")
            self.filter.setClearButtonEnabled(True)
            self.filter.textChanged.connect(self.apply_filter)

            self.status = QtWidgets.QLabel()
            self.status.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(2, 2, 2, 2)
            layout.addWidget(self.filter)
            layout.addWidget(self.view)
            layout.addWidget(self.status)
            self.parent.setLayout(layout)
            self.populate()

        def populate(self):
            rows = tree["rows"]
            self.view.setUpdatesEnabled(False)
            root = QtWidgets.QTreeWidgetItem([tree["name"], tree["from"], "", tree["to"], str(len(rows))])
            font = root.font(0)
            font.setBold(True)
            root.setFont(0, font)
            root.setData(0, POS_ROLE, tree["from"])
            root.setData(0, TARGET_ROLE, tree["root"])
            self.view.addTopLevelItem(root)
            # Rows are in call order, each one level deeper than its caller,
            # so a row's parent is the nearest row above it one level up.
            stack = [root]
            items = [root]
            depths = [0]
            for r in rows:
                depth = r["depth"] + 1
                del stack[depth:]
                parent = stack[-1]
                name = r["name"] + ("  (jump)" if r.get("jump") else "")
                item = QtWidgets.QTreeWidgetItem(parent, [name, r["pos"], r["from"], r["ret"], ""])
                item.setData(0, POS_ROLE, r["pos"])
                item.setData(0, SITE_ROLE, r["site"])
                item.setData(0, TARGET_ROLE, r["target"])
                if r.get("jump"):
                    f = item.font(0)
                    f.setItalic(True)
                    item.setFont(0, f)
                stack.append(item)
                items.append(item)
                depths.append(len(stack) - 1)
            self.count_below(items, depths)
            if len(rows) <= 300:
                self.view.expandAll()
            else:
                self.view.expandToDepth(0)
            for c in range(1, len(COLUMNS)):
                self.view.resizeColumnToContents(c)
            self.view.setColumnWidth(0, max(self.view.columnWidth(0), 360))
            self.view.setUpdatesEnabled(True)
            self.view.setCurrentItem(root)
            note = "%d call(s) from %s to %s, thread %s" % (len(rows), tree["from"], tree["to"], tree["tid"])
            if tree.get("from_cursor"):
                note += "; the function's entry was not found, so this starts at the cursor"
            if tree.get("truncated"):
                note += "; cut short"
            self.status.setText(note + ".  Double-click or Enter to go there.")

        def count_below(self, items, depths):
            # Subtree sizes from the items in tree order (what follows an item
            # at greater depth is below it). Walked from the end so a child's
            # size is known when its parent skips over it; no recursion, which
            # a deep tree would take past Python's limit.
            below = [0] * len(items)
            for i in range(len(items) - 1, -1, -1):
                end = i + 1
                while end < len(items) and depths[end] > depths[i]:
                    end += 1 + below[end]
                below[i] = end - i - 1
                if i != 0 and below[i]:
                    items[i].setText(4, str(below[i]))

        def travel(self, item):
            pos = item.data(0, POS_ROLE)
            if pos:
                # With the tree's recording, so a tree left open across a
                # switch to a fork does not travel into the fork.
                ttd("ui.travel %s %s" % (pos, tree.get("recording", "")))

        def menu(self, point):
            item = self.view.itemAt(point)
            if item is None:
                return
            m = QtWidgets.QMenu(self.view)
            m.addAction("Go to this call", lambda: self.travel(item))
            site = item.data(0, SITE_ROLE)
            target = item.data(0, TARGET_ROLE)
            if site:
                m.addAction("Show the call site", lambda: ida_kernwin.jumpto(int(site, 16)))
            if target:
                m.addAction("Show the function called", lambda: ida_kernwin.jumpto(int(target, 16)))
            m.addSeparator()
            m.addAction("Expand everything below", lambda: self.expand_below(item))
            m.addAction("Collapse everything", self.view.collapseAll)
            m.exec(self.view.viewport().mapToGlobal(point))

        def expand_below(self, item):
            # Iterative: a deep tree would pass Python's recursion limit, and
            # updates stay off until the whole subtree is open.
            self.view.setUpdatesEnabled(False)
            todo = [item]
            while todo:
                it = todo.pop()
                it.setExpanded(True)
                todo.extend(it.child(i) for i in range(it.childCount()))
            self.view.setUpdatesEnabled(True)

        def apply_filter(self, text):
            text = text.strip().lower()
            # Every item with its parent's index, parents first; then walked
            # from the end so children are settled first. A row stays when it
            # or something below it matches.
            order = []
            todo = [(self.view.topLevelItem(i), -1) for i in range(self.view.topLevelItemCount())]
            while todo:
                item, parent = todo.pop()
                order.append((item, parent))
                todo.extend((item.child(i), len(order) - 1) for i in range(item.childCount()))
            below = [False] * len(order)
            self.view.setUpdatesEnabled(False)
            for i in range(len(order) - 1, -1, -1):
                item, parent = order[i]
                keep = below[i] or not text or text in item.text(0).lower()
                item.setHidden(not keep)
                if text and below[i]:
                    item.setExpanded(True)
                if keep and parent >= 0:
                    below[parent] = True
            self.view.setUpdatesEnabled(True)

        def OnClose(self, form):
            _forms.pop(title, None)

    global _ida_ttd_call_tree_forms
    try:
        _forms = _ida_ttd_call_tree_forms
    except NameError:
        _forms = _ida_ttd_call_tree_forms = {}

    title = "TTD call tree: " + tree["name"]
    old = ida_kernwin.find_widget(title)
    if old is not None:
        ida_kernwin.close_widget(old, 0)
    form = CallTreeForm()
    _forms[title] = form
    form.Show(title, options=ida_kernwin.PluginForm.WOPN_DP_TAB | ida_kernwin.PluginForm.WOPN_RESTORE)

_ida_ttd_call_tree()
)PY";
}
