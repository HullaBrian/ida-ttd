"""The plugin's graph window, drawn with PySide6.

One window per kind of graph ("forks", "origin"). The plugin builds the model
(src/ui/graph_view.cpp) and this draws it: ttd("ui.graph KIND") hands over the
nodes and edges, ttd("ui.graphact KIND NODE ACTION") runs a node's action. It
is drawn as IDA draws its own graphs: plain boxes with a shadow, text in the
disassembly font and colours (the node's kind as a comment), right-angled
edges, in a top-down tree. Colours are read from IDA's theme, so light and
dark themes both work.

Mouse and keys as in IDA's graphs: drag to pan, wheel to scroll, Ctrl+wheel
to zoom; F (or Home) fits the graph, Ctrl+0 shows it at 100%.

The plugin calls show() through ida_ttd_qt.fresh_module("ida_ttd_graph").
"""
import json
import re
import ida_kernwin
import idc
from PySide6 import QtCore, QtGui, QtWidgets


def ttd(cmd):
    # cmd becomes an IDC string literal: escape what would end it early.
    cmd = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return json.loads(idc.eval_idc('ttd("%s")' % cmd))


# The open windows' forms, by kind or title. Kept across importlib.reload
# (ida_ttd_qt.fresh_module), which runs this file again in the same
# namespace: a window opened before a reinstall is still found and reused.
try:
    _forms
except NameError:
    _forms = {}


def show(kind, first):
    """Open the graph of 'kind', or redraw its open window with the model
    the plugin holds now ('first': also bring the window to the front)."""
    forms = _forms

    def fetch():
        r = ttd("ui.graph " + kind)
        if not r.get("ok"):
            raise RuntimeError(r.get("error", "no graph"))
        return r["graph"]

    def mix(a, b, t):
        return QtGui.QColor(int(a.red() + (b.red() - a.red()) * t),
                            int(a.green() + (b.green() - a.green()) * t),
                            int(a.blue() + (b.blue() - a.blue()) * t))

    # IDA's theme colours, read from a disassembly view (CustomIDAMemo).
    # Fallbacks: IDA's shipped light and dark values.
    LIGHT = {
        "line-bg-default": "#ffffff", "line-fg-insn": "#000080", "line-fg-default": "#000080",
        "line-fg-automatic-comment": "#808080", "line-fg-regular-comment": "#0000ff",
        "line-fg-numlit-in-insn": "#008000", "line-fg-register-name": "#000080",
        "line-fg-keyword": "#000080", "line-fg-punctuation": "#000080",
        "graph-bg-top": "#ffffff", "graph-bg-bottom": "#e0f8ff",
        "graph-node-shadow": "#000000", "graph-node-high1": "#ccffff",
        "graph-edge-normal": "#0000ff", "graph-node-frame-selected": "#aa5500",
    }
    DARK = {
        "line-bg-default": "#2d2d2d", "line-fg-insn": "#ffffff", "line-fg-default": "#aaaaaa",
        "line-fg-automatic-comment": "#808080", "line-fg-regular-comment": "#ffc5f3",
        "line-fg-numlit-in-insn": "#d25032", "line-fg-register-name": "#73adad",
        "line-fg-keyword": "#ababab", "line-fg-punctuation": "#c0c0c0",
        "graph-bg-top": "#b2b2b2", "graph-bg-bottom": "#b2b2b2",
        "graph-node-shadow": "#242424", "graph-node-high1": "#003900",
        "graph-edge-normal": "#0043cb", "graph-node-frame-selected": "#c68e00",
    }

    def theme_colours(dark):
        out = dict(DARK if dark else LIGHT)
        memo = None
        for w in QtWidgets.QApplication.allWidgets():
            if w.metaObject().className() == "CustomIDAMemo":
                memo = w
                break
        if memo is None:
            return out
        for key in list(out):
            for name in (key, key.replace("-", "_")):
                v = memo.property(name)
                if isinstance(v, QtGui.QColor) and v.isValid():
                    out[key] = v.name()
                    break
        return out

    class Theme(object):
        def __init__(self, widget):
            pal = widget.palette()
            self.dark = pal.color(QtGui.QPalette.Base).lightness() < 128
            c = dict((k, QtGui.QColor(v)) for k, v in theme_colours(self.dark).items())
            self.canvas_top = c["graph-bg-top"]
            self.canvas_bottom = c["graph-bg-bottom"]
            self.canvas = mix(self.canvas_top, self.canvas_bottom, 0.5)
            self.node = c["line-bg-default"]
            self.root = c["graph-node-high1"]
            self.text = c["line-fg-insn"]
            self.plain = c["line-fg-default"]
            self.comment = c["line-fg-automatic-comment"]
            self.number = c["line-fg-numlit-in-insn"]
            self.register = c["line-fg-register-name"]
            self.punct = c["line-fg-punctuation"]
            self.frame = mix(self.node, self.text, 0.55)
            self.shadow = c["graph-node-shadow"]
            self.edge = c["graph-edge-normal"]
            self.select = c["graph-node-frame-selected"]
            # Edge labels sit on the background, not in a node.
            ink = QtGui.QColor("#000000" if self.canvas.lightness() > 128 else "#ffffff")
            self.label = mix(ink, self.canvas, 0.3)

    PAD_X = 6
    PAD_Y = 4
    SHADOW = 4
    MAX_W = 520
    HGAP = 32
    VGAP = 48

    class Fonts(object):
        def __init__(self, widget):
            # The disassembly's font, else any fixed font.
            font = None
            for w in QtWidgets.QApplication.allWidgets():
                if w.metaObject().className() == "CustomIDAMemo":
                    font = QtGui.QFont(w.font())
                    break
            if font is None:
                font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
            self.code = font
            self.fm = QtGui.QFontMetrics(font)
            self.line = self.fm.height()

    REGS = set(
        "rax rbx rcx rdx rsi rdi rbp rsp rip eax ebx ecx edx esi edi ebp esp eip "
        "ax bx cx dx si di bp sp al bl cl dl ah bh ch dh sil dil bpl spl".split()
        + ["r%d%s" % (i, s) for i in range(8, 16) for s in ("", "d", "w", "b")]
        + ["%smm%d" % (p, i) for p in "xyz" for i in range(32)])
    TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9A-Fa-f]+|[0-9][0-9A-Fa-f]*h?|\s+|.")
    NUMBER = re.compile(r"^(0x[0-9A-Fa-f]+|[0-9][0-9A-Fa-f]*h?)$")

    def insn_runs(theme, text):
        # Mnemonic, registers, numbers and punctuation, coloured as IDA does.
        runs = []
        first = True
        for tok in TOKEN.findall(text):
            if tok.isspace():
                colour = theme.text
            elif first:
                colour = theme.text
                first = False
            elif tok.lower() in REGS:
                colour = theme.register
            elif NUMBER.match(tok):
                colour = theme.number
            elif tok.isalnum() or tok[0] == "_":
                colour = theme.text
            else:
                colour = theme.punct
            runs.append((tok, colour))
        return runs

    class Card(QtWidgets.QGraphicsItem):
        def __init__(self, form, node):
            super().__init__()
            self.form = form
            self.node = node
            self.setFlag(QtWidgets.QGraphicsItem.ItemIsSelectable, True)
            if node.get("tooltip"):
                self.setToolTip(node["tooltip"])
            self.measure()

        def measure(self):
            f = self.form.fonts
            n = self.node
            badge = n.get("badge") or ""
            # Title with its kind as a comment, the instruction, comment lines.
            self.rows = [("title", n["title"], badge)]
            if n.get("code"):
                self.rows.append(("code", n["code"], ""))
            for line in n.get("lines", []):
                self.rows.append(("comment", "; " + line, ""))
            want = 0
            for kind_, text, extra in self.rows:
                w = f.fm.horizontalAdvance(text)
                if extra:
                    w += f.fm.horizontalAdvance("  ; " + extra)
                want = max(want, w)
            self.w = int(min(want + 2 * PAD_X, MAX_W))
            self.h = int(len(self.rows) * f.line + 2 * PAD_Y)

        def boundingRect(self):
            return QtCore.QRectF(-2, -2, self.w + SHADOW + 4, self.h + SHADOW + 4)

        def paint(self, painter, option, widget=None):
            t = self.form.theme
            f = self.form.fonts
            n = self.node
            rect = QtCore.QRectF(0, 0, self.w, self.h)
            painter.setRenderHint(QtGui.QPainter.Antialiasing, False)
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(t.shadow)
            painter.drawRect(rect.translated(SHADOW, SHADOW))
            painter.setBrush(t.root if n.get("emphasis") else t.node)
            if self.isSelected():
                pen = QtGui.QPen(t.select, 2)
            else:
                pen = QtGui.QPen(t.frame, 1)
            if n.get("dashed"):
                pen.setStyle(QtCore.Qt.DashLine)
            pen.setJoinStyle(QtCore.Qt.MiterJoin)
            painter.setPen(pen)
            painter.drawRect(rect)

            painter.setRenderHint(QtGui.QPainter.TextAntialiasing, True)
            painter.setFont(f.code)
            limit = self.w - 2 * PAD_X
            y = PAD_Y
            for kind_, text, extra in self.rows:
                x = PAD_X
                base = y + f.fm.ascent()
                if kind_ == "code":
                    runs = insn_runs(t, text)
                elif kind_ == "comment":
                    runs = [(text, t.comment)]
                else:
                    runs = [(text, t.text)]
                    if extra:
                        runs.append(("  ; " + extra, t.comment))
                for tok, colour in runs:
                    room = limit - (x - PAD_X)
                    if room <= 0:
                        break
                    w = f.fm.horizontalAdvance(tok)
                    if w > room:
                        tok = f.fm.elidedText(tok, QtCore.Qt.ElideRight, int(room))
                        w = room
                    painter.setPen(colour)
                    painter.drawText(QtCore.QPointF(x, base), tok)
                    x += w
                y += f.line

        def mouseDoubleClickEvent(self, e):
            self.form.act(self.node, None)

        def contextMenuEvent(self, e):
            self.scene().clearSelection()
            self.setSelected(True)
            m = QtWidgets.QMenu()
            for label, action in self.node.get("menu", []):
                if not label:
                    m.addSeparator()
                else:
                    m.addAction(label, lambda a=action: self.form.act(self.node, a))
            if not m.isEmpty():
                m.exec(e.screenPos())

    class Edge(QtWidgets.QGraphicsItem):
        # Right-angled, as IDA routes edges. An edge to a node on its own row
        # or above goes round the right side.
        def __init__(self, form, a, b, edge, up, port):
            super().__init__()
            self.form = form
            self.edge = edge
            self.setZValue(-1)
            p0 = a.pos() + QtCore.QPointF(a.w / 2 + port, a.h)
            p1 = b.pos() + QtCore.QPointF(b.w / 2, 0)
            if p1.y() - p0.y() >= 2 * 8:
                mid = p1.y() - VGAP / 2
                pts = [p0, QtCore.QPointF(p0.x(), mid), QtCore.QPointF(p1.x(), mid), p1]
            else:
                side = max(a.pos().x() + a.w, b.pos().x() + b.w) + HGAP / 2
                pts = [p0, QtCore.QPointF(p0.x(), p0.y() + 12), QtCore.QPointF(side, p0.y() + 12),
                       QtCore.QPointF(side, p1.y() - 12), QtCore.QPointF(p1.x(), p1.y() - 12), p1]
            self.pts = pts
            self.poly = QtGui.QPolygonF(pts)
            # The arrowhead, where the flow arrives.
            self.tip = pts[0] if up else pts[-1]
            self.tip_dir = -1 if up else 1
            # Beside the line into the target, which no other edge shares.
            self.label = edge.get("label") or ""
            self.label_at = QtCore.QPointF(p1.x() + 5, (pts[-2].y() + p1.y()) / 2)

        def boundingRect(self):
            return self.poly.boundingRect().adjusted(-80, -14, 80, 14)

        def paint(self, painter, option, widget=None):
            t = self.form.theme
            f = self.form.fonts
            painter.setRenderHint(QtGui.QPainter.Antialiasing, False)
            pen = QtGui.QPen(t.edge, 1)
            if self.edge.get("dashed"):
                pen.setStyle(QtCore.Qt.DashLine)
            painter.setPen(pen)
            painter.drawPolyline(self.poly)
            painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
            d = self.tip_dir
            tip = self.tip
            head = QtGui.QPolygonF([tip, tip + QtCore.QPointF(-4, -8 * d), tip + QtCore.QPointF(4, -8 * d)])
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(t.edge)
            painter.drawPolygon(head)
            if self.label:
                painter.setFont(f.code)
                painter.setPen(t.label)
                painter.drawText(QtCore.QPointF(self.label_at.x(), self.label_at.y() + f.fm.ascent() / 2 - 1),
                                 self.label)

    class View(QtWidgets.QGraphicsView):
        def __init__(self, form):
            super().__init__()
            self.form = form
            # Scoped enum names: IDA's PyQt5 shim warns on '|' and '&' over
            # the unscoped ones (QtGui.QPainter.Antialiasing).
            self.setRenderHints(QtGui.QPainter.RenderHint.Antialiasing
                                | QtGui.QPainter.RenderHint.TextAntialiasing)
            self.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
            self.setTransformationAnchor(QtWidgets.QGraphicsView.AnchorUnderMouse)
            self.setViewportUpdateMode(QtWidgets.QGraphicsView.SmartViewportUpdate)
            self.setFrameShape(QtWidgets.QFrame.NoFrame)

        def wheelEvent(self, e):
            if e.modifiers() & QtCore.Qt.KeyboardModifier.ControlModifier:
                self.zoom(1.15 if e.angleDelta().y() > 0 else 1 / 1.15)
                e.accept()
            else:
                super().wheelEvent(e)

        def zoom(self, k):
            s = self.transform().m11() * k
            if 0.1 <= s <= 3.0:
                self.scale(k, k)

        def keyPressEvent(self, e):
            k = e.key()
            if k in (QtCore.Qt.Key_F, QtCore.Qt.Key_Home):
                self.form.fit()
            elif k == QtCore.Qt.Key_0 and e.modifiers() & QtCore.Qt.KeyboardModifier.ControlModifier:
                self.resetTransform()
            elif k in (QtCore.Qt.Key_Plus, QtCore.Qt.Key_Equal):
                self.zoom(1.15)
            elif k == QtCore.Qt.Key_Minus:
                self.zoom(1 / 1.15)
            elif k in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                sel = [i for i in self.scene().selectedItems() if isinstance(i, Card)]
                if sel:
                    self.form.act(sel[0].node, None)
            else:
                super().keyPressEvent(e)

        def drawBackground(self, painter, rect):
            # IDA's graph background: a gradient down the visible area.
            t = getattr(self.form, "theme", None)
            if t is None:
                return super().drawBackground(painter, rect)
            vr = self.mapToScene(self.viewport().rect()).boundingRect()
            g = QtGui.QLinearGradient(vr.topLeft(), vr.bottomLeft())
            g.setColorAt(0, t.canvas_top)
            g.setColorAt(1, t.canvas_bottom)
            painter.fillRect(rect, g)

        def contextMenuEvent(self, e):
            if self.itemAt(e.pos()) is not None:
                return super().contextMenuEvent(e)
            m = QtWidgets.QMenu(self)
            m.addAction("Fit the graph (F)", self.form.fit)
            m.addAction("Actual size (Ctrl+0)", self.resetTransform)
            m.addSeparator()
            m.addAction("Copy as an image", self.form.copy_image)
            m.exec(e.globalPos())

    def layout(cards, edges):
        # A top-down tree: each node goes under the first node, breadth first
        # from the roots, with an edge to it; children in edge order. Other
        # edges are drawn but do not affect the layout.
        n = len(cards)
        kids = [[] for _ in range(n)]
        has_parent = [False] * n
        for e in edges:
            if 0 <= e["src"] < n and 0 <= e["dst"] < n:
                has_parent[e["dst"]] = True
        roots = [i for i in range(n) if not has_parent[i]] or ([0] if n else [])
        placed = [False] * n
        depth = [0] * n
        order = []
        queue = list(roots)
        for r in roots:
            placed[r] = True
        out = [[] for _ in range(n)]
        for e in edges:
            if 0 <= e["src"] < n and 0 <= e["dst"] < n:
                out[e["src"]].append(e["dst"])
        while queue:
            v = queue.pop(0)
            order.append(v)
            for c in out[v]:
                if not placed[c]:
                    placed[c] = True
                    depth[c] = depth[v] + 1
                    kids[v].append(c)
                    queue.append(c)
        for i in range(n):
            if not placed[i]:
                roots.append(i)
                placed[i] = True

        rows = {}
        for i in range(n):
            rows[depth[i]] = max(rows.get(depth[i], 0), cards[i].h)
        tops = {}
        y = 0
        for d in sorted(rows):
            tops[d] = y
            y += rows[d] + VGAP

        width = [0] * n

        def measure(v):
            s = sum(measure(c) for c in kids[v]) + HGAP * max(len(kids[v]) - 1, 0)
            width[v] = max(cards[v].w, s)
            return width[v]

        def place(v, left):
            span = sum(width[c] for c in kids[v]) + HGAP * max(len(kids[v]) - 1, 0)
            x = left + (width[v] - span) / 2
            for c in kids[v]:
                place(c, x)
                x += width[c] + HGAP
            if kids[v]:
                a = cards[kids[v][0]]
                b = cards[kids[v][-1]]
                centre = (a.pos().x() + a.w / 2 + b.pos().x() + b.w / 2) / 2
            else:
                centre = left + width[v] / 2
            cards[v].setPos(centre - cards[v].w / 2, tops[depth[v]])

        left = 0
        for r in roots:
            measure(r)
            place(r, left)
            left += width[r] + HGAP * 2

    class GraphForm(ida_kernwin.PluginForm):
        def __init__(self, graph):
            super().__init__()
            self.graph = graph

        def OnCreate(self, form):
            self.parent = self.FormToPyQtWidget(form)
            self.view = View(self)
            self.scene = QtWidgets.QGraphicsScene(self.view)
            self.view.setScene(self.scene)
            self.status = QtWidgets.QLabel()
            self.status.setWordWrap(True)
            self.status.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            box = QtWidgets.QVBoxLayout()
            box.setContentsMargins(0, 0, 0, 0)
            box.setSpacing(0)
            self.status.setContentsMargins(8, 4, 8, 4)
            box.addWidget(self.view)
            box.addWidget(self.status)
            self.parent.setLayout(box)
            self.load(self.graph, True)

        def load(self, graph, first=False):
            self.graph = graph
            self.theme = Theme(self.view)
            self.fonts = Fonts(self.view)
            self.scene.clear()
            cards = []
            for node in graph["nodes"]:
                c = Card(self, node)
                self.scene.addItem(c)
                cards.append(c)
            layout(cards, graph["edges"])
            up = bool(graph.get("arrows_up"))
            # Edges leaving a card spread across its bottom, ordered by the
            # cards they reach, rather than all leaving from one point.
            leaving = {}
            for e in graph["edges"]:
                if 0 <= e["src"] < len(cards) and 0 <= e["dst"] < len(cards):
                    leaving.setdefault(e["src"], []).append(e)
            for src, out in leaving.items():
                a = cards[src]
                out.sort(key=lambda e: cards[e["dst"]].pos().x())
                spread = min(a.w * 0.5, 24 * (len(out) - 1))
                for k, e in enumerate(out):
                    port = 0 if len(out) == 1 else -spread / 2 + spread * k / (len(out) - 1)
                    self.scene.addItem(Edge(self, a, cards[e["dst"]], e, up, port))
            r = self.scene.itemsBoundingRect().adjusted(-40, -40, 40, 40)
            self.scene.setSceneRect(r)
            self.status.setText(graph.get("status") or "")
            if first:
                QtCore.QTimer.singleShot(0, self.fit_or_actual)

        def fit_or_actual(self):
            # Actual size when it fits, else the whole graph; either way,
            # scrolled to the top, where it starts.
            r = self.scene.sceneRect()
            vp = self.view.viewport().rect()
            self.view.resetTransform()
            if r.width() > vp.width() or r.height() > vp.height():
                k = min(vp.width() / r.width(), vp.height() / r.height())
                k = max(k, 0.45)
                self.view.scale(k, k)
            self.view.centerOn(r.center().x(), r.top() + self.view.viewport().height() / 2 / self.view.transform().m11())

        def fit(self):
            self.view.fitInView(self.scene.sceneRect(), QtCore.Qt.KeepAspectRatio)
            if self.view.transform().m11() > 1.0:
                self.view.resetTransform()

        def copy_image(self):
            r = self.scene.sceneRect()
            img = QtGui.QImage(int(r.width()), int(r.height()), QtGui.QImage.Format_ARGB32)
            img.fill(self.theme.canvas)
            p = QtGui.QPainter(img)
            self.scene.render(p, QtCore.QRectF(img.rect()), r)
            p.end()
            QtWidgets.QApplication.clipboard().setImage(img)

        def act(self, node, action):
            if action is None:
                menu = [a for l, a in node.get("menu", []) if l]
                if not menu:
                    return
                action = menu[0]
            # Deferred out of this item's own event: the action may redraw
            # the graph, which deletes the item.
            def run():
                r = ttd("ui.graphact %s %x %s" % (kind, node["id"], action))
                if not r.get("ok"):
                    ida_kernwin.warning(r.get("error", "That did not work."))
            QtCore.QTimer.singleShot(0, run)

        def OnClose(self, form):
            if forms.get(kind) is self:
                forms.pop(kind, None)

    graph = fetch()
    form = forms.get(kind)
    if form is not None and ida_kernwin.find_widget(graph["title"]) is not None:
        # Skipped if the window closed meanwhile, deleting what load() draws on.
        QtCore.QTimer.singleShot(0, lambda: form.load(graph) if forms.get(kind) is form else None)
        if first:
            ida_kernwin.activate_widget(ida_kernwin.find_widget(graph["title"]), True)
        return
    form = GraphForm(graph)
    forms[kind] = form
    form.Show(graph["title"], options=ida_kernwin.PluginForm.WOPN_DP_TAB | ida_kernwin.PluginForm.WOPN_RESTORE)
