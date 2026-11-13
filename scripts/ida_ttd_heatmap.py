"""The memory heatmap window, drawn with PySide6.

One row per page the recording touched, in address order; one column per
slice of time. A cell's colour is the page's access count in that slice, on a
log scale; in "All", writes are red, reads green and executes blue, so a mix
blends. The plugin counts (ttd("ui.heat")); a double-click travels to the
slice and shows the page in the hex view (ttd("ui.showbytes POS EA")).

Drag across the columns, or type a start and end position, to zoom. Each
zoom recounts that span alone (ttd("ui.heatzoom FROM TO")), so it keeps the
full number of slices; Back and Whole recording zoom out. A vertical line
marks the debugger's slice (ttd("ui.heatnow"), polled by a QTimer on the UI
thread, never from another thread).

The plugin calls show() through ida_ttd_qt.fresh_module("ida_ttd_heatmap").
"""
import json
import math
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


def show():
    """Open the heatmap of the counts the plugin holds, replacing an open one."""

    # What a typed span end may look like: Microsoft's Sequence:Steps in hex,
    # Sogen's decimal instruction number, or "end". The backend parses it
    # properly; this only keeps spaces and other words out of the command.
    POSITION_RE = re.compile(r"[0-9A-Fa-f]+(?::[0-9A-Fa-f]+)?|end")

    data = ttd("ui.heat")
    if not data.get("ok"):
        raise RuntimeError(data.get("error", "no heatmap"))

    # The counts shown. A zoom replaces them whole, so everything reads them
    # from here instead of keeping a copy.
    H = {}

    def load(heat):
        H["shift"] = heat["page_shift"]
        H["slices"] = heat["slices"]
        H["starts"] = heat["starts"]
        H["end"] = heat.get("end", "")
        H["whole"] = heat.get("whole", True)
        H["can_zoom"] = heat.get("can_zoom", False)
        H["pages"] = heat["pages"]

    load(data["heat"])

    def slice_end(s):
        # Where slice s ends: the next one's start, or the span's end.
        return H["starts"][s + 1] if s + 1 < H["slices"] else H["end"]

    MODES = ["All (writes red, reads green, executes blue)", "Reads", "Writes", "Executes"]
    ROW = 6
    GUTTER = 250

    def ramp(t):
        # Dark violet -> red -> orange -> pale yellow, for one kind of access.
        stops = [(0.0, (40, 10, 70)), (0.35, (170, 30, 80)), (0.7, (245, 130, 30)), (1.0, (255, 245, 170))]
        for (a, ca), (b, cb) in zip(stops, stops[1:]):
            if t <= b:
                f = (t - a) / (b - a) if b > a else 0.0
                return tuple(int(ca[i] + (cb[i] - ca[i]) * f) for i in range(3))
        return stops[-1][1]

    class Canvas(QtWidgets.QWidget):
        def __init__(self, owner):
            super().__init__()
            self.owner = owner
            self.mode = 0
            self.rows = H["pages"]
            self.runs = []
            self.image = None
            # [first slice, last slice] while a span is being dragged out.
            self.drag = None
            # The slice the current position is in, or -1.
            self.now = -1
            self.setMouseTracking(True)

        def set_rows(self, rows, mode):
            self.rows = rows
            self.mode = mode
            self.image = None
            # Runs of neighbouring pages of one module: [first row, end row).
            self.runs = []
            for y, r in enumerate(rows):
                if (y == 0 or r["page"] != rows[y - 1]["page"] + 1
                        or r["label"] != rows[y - 1]["label"]):
                    self.runs.append([y, y + 1])
                else:
                    self.runs[-1][1] = y + 1
            self.setMinimumHeight(max(len(rows) * ROW, 50))
            self.updateGeometry()
            self.update()

        def build_image(self):
            n = max(len(self.rows), 1)
            img = QtGui.QImage(H["slices"], n, QtGui.QImage.Format_RGB32)
            img.fill(self.palette().color(QtGui.QPalette.Base))
            mx = [1, 1, 1]
            for r in self.rows:
                for c in r["cells"]:
                    for k in range(3):
                        if c[1 + k] > mx[k]:
                            mx[k] = c[1 + k]
            lm = [math.log1p(m) for m in mx]
            for y, r in enumerate(self.rows):
                for s, rd, wr, ex in r["cells"]:
                    if self.mode == 0:
                        g = rd and int(60 + 195 * math.log1p(rd) / lm[0])
                        red = wr and int(60 + 195 * math.log1p(wr) / lm[1])
                        b = ex and int(60 + 195 * math.log1p(ex) / lm[2])
                        col = QtGui.QColor(red, g, b)
                    else:
                        v = (rd, wr, ex)[self.mode - 1]
                        if not v:
                            continue
                        col = QtGui.QColor(*ramp(math.log1p(v) / lm[self.mode - 1]))
                    img.setPixelColor(s, y, col)
            self.image = img

        def slice_at(self, x):
            w = max(self.width() - GUTTER, 1)
            s = int((x - GUTTER) * H["slices"] // w)
            return min(max(s, 0), H["slices"] - 1)

        def cell_at(self, pos):
            y = int(pos.y() // ROW)
            if y < 0 or y >= len(self.rows) or pos.x() < GUTTER:
                return None, None
            return y, self.slice_at(pos.x())

        def paintEvent(self, ev):
            p = QtGui.QPainter(self)
            if self.image is None:
                self.build_image()
            w = max(self.width() - GUTTER, 1)
            # Only the rows in view: the image can be thousands of rows tall.
            top = max(int(ev.rect().top() // ROW), 0)
            bottom = min(int(ev.rect().bottom() // ROW) + 1, len(self.rows))
            if bottom > top:
                src = QtCore.QRect(0, top, H["slices"], bottom - top)
                dst = QtCore.QRect(GUTTER, top * ROW, w, (bottom - top) * ROW)
                p.drawImage(dst, self.image, src)
            # A rule above each run of neighbouring pages, labelled inside when
            # the run is tall enough (a label never crosses the next rule);
            # shorter runs are named by the tooltip.
            fg = self.palette().color(QtGui.QPalette.Text)
            rule = self.palette().color(QtGui.QPalette.Mid)
            font = p.font()
            font.setPointSizeF(max(font.pointSizeF() - 1.5, 6.0))
            p.setFont(font)
            text_h = QtGui.QFontMetrics(font).height()
            for first, end in self.runs:
                if end <= top or first >= bottom:
                    continue
                y0 = first * ROW
                h = (end - first) * ROW
                if first > 0:
                    p.setPen(rule)
                    p.drawLine(0, y0, self.width(), y0)
                if h >= text_h + 2:
                    r = self.rows[first]
                    p.setPen(fg)
                    p.drawText(QtCore.QRect(4, y0 + 1, GUTTER - 8, h - 1),
                               QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop | QtCore.Qt.TextSingleLine,
                               "0x%X  %s" % (r["page"] << H["shift"], r["label"]))
            # The debugger's slice: a line down its middle, dark-edged to show
            # on any cell colour.
            if 0 <= self.now < H["slices"]:
                x = GUTTER + (2 * self.now + 1) * w // (2 * H["slices"])
                y0, y1 = ev.rect().top(), ev.rect().bottom()
                p.setPen(QtGui.QPen(QtGui.QColor(0, 0, 0), 3))
                p.drawLine(x, y0, x, y1)
                p.setPen(QtGui.QPen(QtGui.QColor(255, 255, 255), 1))
                p.drawLine(x, y0, x, y1)
            # The span being dragged out, over every row in view.
            if self.drag is not None:
                a, b = sorted(self.drag)
                x0 = GUTTER + a * w // H["slices"]
                x1 = GUTTER + (b + 1) * w // H["slices"]
                hl = QtGui.QColor(self.palette().color(QtGui.QPalette.Highlight))
                hl.setAlpha(70)
                p.fillRect(QtCore.QRect(x0, ev.rect().top(), max(x1 - x0, 1), ev.rect().height()), hl)
            p.end()

        def resizeEvent(self, ev):
            self.update()

        def mousePressEvent(self, ev):
            if (ev.button() == QtCore.Qt.LeftButton and H["can_zoom"]
                    and ev.position().x() >= GUTTER):
                s = self.slice_at(ev.position().x())
                self.drag = [s, s]

        def mouseReleaseEvent(self, ev):
            if self.drag is None:
                return
            a, b = sorted(self.drag)
            self.drag = None
            self.update()
            # A click is not a span: a double-click's press and release also
            # land here before it travels.
            if b > a:
                self.owner.zoom(H["starts"][a], slice_end(b))

        def mouseMoveEvent(self, ev):
            if self.drag is not None:
                s = self.slice_at(ev.position().x())
                if s != self.drag[1]:
                    self.drag[1] = s
                    self.update()
                a, b = sorted(self.drag)
                QtWidgets.QToolTip.showText(ev.globalPosition().toPoint(),
                                            "Zoom to %s .. %s" % (H["starts"][a], slice_end(b)), self)
                return
            y, s = self.cell_at(ev.position())
            if y is None:
                QtWidgets.QToolTip.hideText()
                return
            r = self.rows[y]
            counts = [0, 0, 0]
            for c in r["cells"]:
                if c[0] == s:
                    counts = c[1:]
                    break
            tip = "0x%X%s\nslice %d of %d, %s .. %s\n%d reads, %d writes, %d executes\nDouble-click: go there%s" % (
                r["page"] << H["shift"], ("  (" + r["label"] + ")") if r["label"] else "",
                s + 1, H["slices"], H["starts"][s], slice_end(s), counts[0], counts[1], counts[2],
                "\nDrag across the columns: zoom in" if H["can_zoom"] else "")
            QtWidgets.QToolTip.showText(ev.globalPosition().toPoint(), tip, self)

        def mouseDoubleClickEvent(self, ev):
            self.drag = None
            y, s = self.cell_at(ev.position())
            if y is None:
                return
            r = self.rows[y]
            # The first slice from here on that touched the page, else this one.
            target = s
            for c in r["cells"]:
                if c[0] >= s:
                    target = c[0]
                    break
            if H["starts"][target]:
                ttd("ui.showbytes %s %X" % (H["starts"][target], r["page"] << H["shift"]))

    class HeatmapForm(ida_kernwin.PluginForm):
        def OnCreate(self, form):
            self.parent = self.FormToPyQtWidget(form)
            # Spans zoomed out of, most recent last, for Back.
            self.history = []
            self.mode = QtWidgets.QComboBox()
            self.mode.addItems(MODES)
            self.mode.currentIndexChanged.connect(self.refresh)
            self.filter = QtWidgets.QLineEdit()
            self.filter.setPlaceholderText("Filter by module or address")
            self.filter.setClearButtonEnabled(True)
            self.filter.textChanged.connect(self.refresh)
            self.status = QtWidgets.QLabel()
            bar = QtWidgets.QHBoxLayout()
            bar.addWidget(self.mode)
            bar.addWidget(self.filter, 1)
            bar.addWidget(self.status)

            # The span: typed, or dragged out on the columns.
            self.span_from = QtWidgets.QLineEdit()
            self.span_to = QtWidgets.QLineEdit()
            for e in (self.span_from, self.span_to):
                e.setPlaceholderText("position")
                e.returnPressed.connect(self.apply_span)
            self.apply_btn = QtWidgets.QPushButton("Zoom")
            self.apply_btn.clicked.connect(self.apply_span)
            self.back_btn = QtWidgets.QPushButton("Back")
            self.back_btn.clicked.connect(self.back)
            self.whole_btn = QtWidgets.QPushButton("Whole recording")
            self.whole_btn.clicked.connect(self.whole)
            span = QtWidgets.QHBoxLayout()
            span.addWidget(QtWidgets.QLabel("Span"))
            span.addWidget(self.span_from, 1)
            span.addWidget(QtWidgets.QLabel("to"))
            span.addWidget(self.span_to, 1)
            span.addWidget(self.apply_btn)
            span.addWidget(self.back_btn)
            span.addWidget(self.whole_btn)

            self.canvas = Canvas(self)
            scroll = QtWidgets.QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(self.canvas)
            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(2, 2, 2, 2)
            layout.addLayout(bar)
            layout.addLayout(span)
            layout.addWidget(scroll, 1)
            self.parent.setLayout(layout)
            self.show_span()
            self.refresh()
            self.timer = QtCore.QTimer(self.parent)
            self.timer.timeout.connect(self.poll_now)
            self.timer.start(500)
            self.poll_now()

        def poll_now(self):
            try:
                r = ttd("ui.heatnow")
            except Exception:
                return
            if not r.get("ok") or r.get("busy"):
                return              # moving, or no session: keep the last mark
            s = r.get("slice", -1)
            if s != self.canvas.now:
                self.canvas.now = s
                self.canvas.update()

        def show_span(self):
            self.span_from.setText(H["starts"][0] if H["starts"] else "")
            self.span_to.setText(H["end"])
            zoomable = H["can_zoom"]
            for w in (self.span_from, self.span_to, self.apply_btn):
                w.setEnabled(zoomable)
                w.setToolTip("" if zoomable else
                             "This recording's backend can only count the whole recording.")
            self.back_btn.setEnabled(zoomable and bool(self.history))
            self.whole_btn.setEnabled(zoomable and not H["whole"])

        def recount(self, cmd):
            # A fresh count, behind the plugin's wait box. On failure the
            # counts shown are kept.
            r = ttd(cmd)
            if not r.get("ok"):
                ida_kernwin.warning("The heatmap could not be counted over that span: %s"
                                    % r.get("error", "unknown error"))
                return False
            load(r["heat"])
            self.show_span()
            self.refresh()
            self.poll_now()
            return True

        def zoom(self, first, last):
            if not first or not last:
                return
            here = (H["starts"][0], H["end"], H["whole"])
            if self.recount("ui.heatzoom %s %s" % (first, last)):
                self.history.append(here)
                self.show_span()

        def apply_span(self):
            first = self.span_from.text().strip()
            last = self.span_to.text().strip()
            if not first or not last:
                return
            for text in (first, last):
                if not POSITION_RE.fullmatch(text):
                    ida_kernwin.warning("'%s' is not a position." % text)
                    return
            self.zoom(first, last)

        def back(self):
            if not self.history:
                return
            first, last, whole = self.history.pop()
            if not self.recount("ui.heatzoom" if whole else "ui.heatzoom %s %s" % (first, last)):
                self.history.append((first, last, whole))
            self.show_span()

        def whole(self):
            here = (H["starts"][0], H["end"], H["whole"])
            if self.recount("ui.heatzoom"):
                self.history.append(here)
                self.show_span()

        def refresh(self, *args):
            text = self.filter.text().strip().lower()
            mode = self.mode.currentIndex()
            pages = H["pages"]
            rows = pages
            if text:
                rows = [r for r in pages if text in r["label"].lower() or text in ("%x" % (r["page"] << H["shift"]))]
            if mode != 0:
                rows = [r for r in rows if any(c[mode] for c in r["cells"])]
            self.canvas.set_rows(rows, mode)
            self.status.setText("%d of %d pages, %d slices of %s" % (
                len(rows), len(pages), H["slices"], "the recording" if H["whole"] else "this span"))

        def OnClose(self, form):
            self.timer.stop()
            _forms.pop(title, None)

    title = "TTD memory heatmap"
    old = ida_kernwin.find_widget(title)
    if old is not None:
        ida_kernwin.close_widget(old, 0)
    form = HeatmapForm()
    _forms[title] = form
    form.Show(title, options=ida_kernwin.PluginForm.WOPN_DP_TAB | ida_kernwin.PluginForm.WOPN_RESTORE)

