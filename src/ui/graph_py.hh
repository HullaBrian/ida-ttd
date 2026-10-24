// graph_py.hh: the plugin's graph window, as IDAPython runs it.
//
// One window per kind of graph ("forks", "origin"). The plugin builds the
// model (graph_view.cpp) and this draws it: ttd("ui.graph KIND") hands over
// the nodes and edges, ttd("ui.graphact KIND NODE ACTION") runs a node's
// action. Nodes are cards (bold title, an instruction in the code font, dimmer
// lines, a coloured badge) laid out as a top-down tree with curved edges.
// Colours come from IDA's theme palette, so light and dark themes both work.
//
// Mouse and keys as in IDA's graphs: drag to pan, wheel to scroll,
// Ctrl+wheel to zoom; F (or Home) fits the graph, Ctrl+0 shows it at 100%.
#pragma once

namespace idattd
{
    static const char GRAPH_PY[] = R"PY(
def _ida_ttd_graph_show(kind, first):
    import json
    import ida_kernwin
    import idc
    from PySide6 import QtCore, QtGui, QtWidgets

    forms = globals().setdefault("_ida_ttd_graph_forms", {})

    def ttd(cmd):
        # cmd becomes an IDC string literal: escape what would end it early.
        cmd = cmd.replace("\\", "\\\\").replace('"', '\\"')
        return json.loads(idc.eval_idc('ttd("%s")' % cmd))

    def fetch():
        r = ttd("ui.graph " + kind)
        if not r.get("ok"):
            raise RuntimeError(r.get("error", "no graph"))
        return r["graph"]

    def mix(a, b, t):
        return QtGui.QColor(int(a.red() + (b.red() - a.red()) * t),
                            int(a.green() + (b.green() - a.green()) * t),
                            int(a.blue() + (b.blue() - a.blue()) * t))

    class Theme(object):
        def __init__(self, widget):
            pal = widget.palette()
            base = pal.color(QtGui.QPalette.Base)
            text = pal.color(QtGui.QPalette.Text)
            self.dark = base.lightness() < 128
            self.canvas = base.darker(112) if self.dark else mix(base, text, 0.035)
            self.card = mix(base, text, 0.06) if self.dark else base
            self.border = mix(base, text, 0.28)
            self.text = text
            self.dim = mix(text, base, 0.42)
            self.code_bg = mix(self.card, text, 0.07)
            self.edge = mix(base, text, 0.45)
            self.select = pal.color(QtGui.QPalette.Highlight)
            hues = {
                "accent": QtGui.QColor(66, 133, 244),
                "good": QtGui.QColor(52, 168, 83),
                "warn": QtGui.QColor(230, 145, 30),
                "bad": QtGui.QColor(220, 70, 70),
                "muted": self.dim,
            }
            if self.dark:
                hues = dict((k, v.lighter(125)) for k, v in hues.items())
            self.tones = hues

        def tone(self, name):
            return self.tones.get(name)

    PAD = 10
    STRIPE = 4
    RADIUS = 8
    MIN_W = 190
    MAX_W = 460
    HGAP = 28
    VGAP = 56

    class Fonts(object):
        def __init__(self, widget):
            base = QtGui.QFont(widget.font())
            self.title = QtGui.QFont(base)
            self.title.setBold(True)
            self.code = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
            self.code.setPointSizeF(max(base.pointSizeF() - 0.5, 7.0))
            self.small = QtGui.QFont(base)
            self.small.setPointSizeF(max(base.pointSizeF() - 1.0, 7.0))
            self.fm_title = QtGui.QFontMetrics(self.title)
            self.fm_code = QtGui.QFontMetrics(self.code)
            self.fm_small = QtGui.QFontMetrics(self.small)

    class Card(QtWidgets.QGraphicsItem):
        def __init__(self, form, node):
            super().__init__()
            self.form = form
            self.node = node
            self.hover = False
            self.setFlag(QtWidgets.QGraphicsItem.ItemIsSelectable, True)
            self.setAcceptHoverEvents(True)
            self.setCursor(QtCore.Qt.PointingHandCursor)
            if node.get("tooltip"):
                self.setToolTip(node["tooltip"])
            self.measure()

        def measure(self):
            f = self.form.fonts
            n = self.node
            badge = n.get("badge") or ""
            self.badge_w = f.fm_small.horizontalAdvance(badge) + 14 if badge else 0
            want = f.fm_title.horizontalAdvance(n["title"]) + (self.badge_w + 10 if badge else 0)
            if n.get("code"):
                want = max(want, f.fm_code.horizontalAdvance(n["code"]) + 14)
            for line in n.get("lines", []):
                want = max(want, f.fm_small.horizontalAdvance(line))
            self.w = int(min(max(want + 2 * PAD + STRIPE, MIN_W), MAX_W))
            inner = self.w - 2 * PAD - STRIPE
            self.title_text = f.fm_title.elidedText(n["title"], QtCore.Qt.ElideRight,
                                                    inner - (self.badge_w + 10 if badge else 0))
            self.code_text = f.fm_code.elidedText(n.get("code") or "", QtCore.Qt.ElideRight, inner - 14)
            self.line_texts = [f.fm_small.elidedText(l, QtCore.Qt.ElideRight, inner) for l in n.get("lines", [])]
            h = PAD + f.fm_title.height()
            if self.code_text:
                h += 6 + f.fm_code.height() + 8
            if self.line_texts:
                h += 4 + len(self.line_texts) * (f.fm_small.height() + 1)
            self.h = int(h + PAD)

        def boundingRect(self):
            return QtCore.QRectF(-2, -2, self.w + 4, self.h + 6)

        def paint(self, painter, option, widget=None):
            t = self.form.theme
            f = self.form.fonts
            n = self.node
            painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
            rect = QtCore.QRectF(0, 0, self.w, self.h)
            tone = t.tone(n.get("tone") or "")

            # A soft shadow, then the card.
            shadow = QtGui.QColor(0, 0, 0, 90 if t.dark else 28)
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(shadow)
            painter.drawRoundedRect(rect.translated(0, 2), RADIUS, RADIUS)
            painter.setBrush(t.card)
            painter.drawRoundedRect(rect, RADIUS, RADIUS)

            # The stripe down the left edge, in the node's colour.
            if tone is not None:
                clip = QtGui.QPainterPath()
                clip.addRoundedRect(rect, RADIUS, RADIUS)
                painter.save()
                painter.setClipPath(clip)
                painter.fillRect(QtCore.QRectF(0, 0, STRIPE, self.h), tone)
                painter.restore()

            if self.isSelected():
                pen = QtGui.QPen(t.select, 2.2)
            elif n.get("emphasis"):
                pen = QtGui.QPen(tone if tone is not None else t.text, 1.8)
            else:
                pen = QtGui.QPen(t.text if self.hover else t.border, 1.0)
            if n.get("dashed"):
                pen.setStyle(QtCore.Qt.DashLine)
            painter.setPen(pen)
            painter.setBrush(QtCore.Qt.NoBrush)
            painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), RADIUS, RADIUS)

            x = PAD + STRIPE
            y = PAD
            inner = self.w - 2 * PAD - STRIPE
            painter.setFont(f.title)
            painter.setPen(t.text)
            painter.drawText(QtCore.QRectF(x, y, inner, f.fm_title.height()),
                             QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, self.title_text)

            badge = n.get("badge") or ""
            if badge:
                bh = f.fm_small.height() + 2
                br = QtCore.QRectF(self.w - PAD - self.badge_w, y + (f.fm_title.height() - bh) / 2,
                                   self.badge_w, bh)
                c = tone if tone is not None else t.dim
                fill = QtGui.QColor(c)
                fill.setAlpha(60 if t.dark else 38)
                painter.setPen(QtCore.Qt.NoPen)
                painter.setBrush(fill)
                painter.drawRoundedRect(br, bh / 2, bh / 2)
                painter.setFont(f.small)
                painter.setPen(c if t.dark else c.darker(135))
                painter.drawText(br, QtCore.Qt.AlignCenter, badge)
            y += f.fm_title.height()

            if self.code_text:
                y += 6
                cr = QtCore.QRectF(x, y, inner, f.fm_code.height() + 6)
                painter.setPen(QtCore.Qt.NoPen)
                painter.setBrush(t.code_bg)
                painter.drawRoundedRect(cr, 4, 4)
                painter.setFont(f.code)
                painter.setPen(t.text)
                painter.drawText(cr.adjusted(7, 0, -7, 0), QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter,
                                 self.code_text)
                y += cr.height() + 2

            if self.line_texts:
                y += 4
                painter.setFont(f.small)
                painter.setPen(t.dim)
                for line in self.line_texts:
                    painter.drawText(QtCore.QRectF(x, y, inner, f.fm_small.height()),
                                     QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, line)
                    y += f.fm_small.height() + 1

        def hoverEnterEvent(self, e):
            self.hover = True
            self.update()

        def hoverLeaveEvent(self, e):
            self.hover = False
            self.update()

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
        def __init__(self, form, a, b, edge, up, port):
            super().__init__()
            self.form = form
            self.a = a
            self.b = b
            self.edge = edge
            self.up = up
            self.setZValue(-1)
            p0 = a.pos() + QtCore.QPointF(a.w / 2 + port, a.h)
            p1 = b.pos() + QtCore.QPointF(b.w / 2, 0)
            dy = max((p1.y() - p0.y()) / 2, 20)
            path = QtGui.QPainterPath(p0)
            path.cubicTo(p0 + QtCore.QPointF(0, dy), p1 - QtCore.QPointF(0, dy), p1)
            self.path = path
            self.tip = p0 if up else p1
            self.tip_dir = -1 if up else 1
            self.label = edge.get("label") or ""
            self.mid = path.pointAtPercent(0.5)

        def boundingRect(self):
            return self.path.boundingRect().adjusted(-60, -12, 60, 12)

        def paint(self, painter, option, widget=None):
            t = self.form.theme
            f = self.form.fonts
            painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
            pen = QtGui.QPen(t.edge, 1.4)
            if self.edge.get("dashed"):
                pen.setStyle(QtCore.Qt.DashLine)
            painter.setPen(pen)
            painter.setBrush(QtCore.Qt.NoBrush)
            painter.drawPath(self.path)
            # The arrowhead, at the end the flow arrives at, pointing along it.
            d = self.tip_dir
            tip = self.tip
            head = QtGui.QPolygonF([tip, tip + QtCore.QPointF(-5, -9 * d), tip + QtCore.QPointF(5, -9 * d)])
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(t.edge)
            painter.drawPolygon(head)
            if self.label:
                painter.setFont(f.small)
                w = f.fm_small.horizontalAdvance(self.label) + 10
                h = f.fm_small.height() + 2
                r = QtCore.QRectF(self.mid.x() - w / 2, self.mid.y() - h / 2, w, h)
                painter.setBrush(t.canvas)
                painter.drawRoundedRect(r, h / 2, h / 2)
                painter.setPen(t.dim)
                painter.drawText(r, QtCore.Qt.AlignCenter, self.label)

    class View(QtWidgets.QGraphicsView):
        def __init__(self, form):
            super().__init__()
            self.form = form
            self.setRenderHints(QtGui.QPainter.Antialiasing | QtGui.QPainter.TextAntialiasing)
            self.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
            self.setTransformationAnchor(QtWidgets.QGraphicsView.AnchorUnderMouse)
            self.setViewportUpdateMode(QtWidgets.QGraphicsView.SmartViewportUpdate)
            self.setFrameShape(QtWidgets.QFrame.NoFrame)

        def wheelEvent(self, e):
            if e.modifiers() & QtCore.Qt.ControlModifier:
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
            elif k == QtCore.Qt.Key_0 and e.modifiers() & QtCore.Qt.ControlModifier:
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
            self.view.setBackgroundBrush(self.theme.canvas)
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
                spread = min(a.w * 0.5, 36 * (len(out) - 1))
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
)PY";
}
