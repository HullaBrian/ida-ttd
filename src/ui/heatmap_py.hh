// heatmap_py.hh: the memory heatmap window, as IDAPython runs it.
//
// One row per page the recording touched, in address order; one column per
// slice of the recording's time. A cell's colour is how often the page was
// read, written or run from in that slice, on a log scale: in "All", writes
// are red, reads green and executes blue, so a mix shows as its blend. The
// plugin counts (ttd("ui.heat")); a double-click travels to the slice and
// shows the page in the hex view (ttd("ui.showbytes POS EA")).
#pragma once

namespace idattd
{
    static const char HEATMAP_PY[] = R"PY(
def _ida_ttd_heatmap():
    import json
    import math
    import ida_kernwin
    import idc
    from PySide6 import QtCore, QtGui, QtWidgets

    def ttd(cmd):
        return json.loads(idc.eval_idc('ttd("%s")' % cmd))

    data = ttd("ui.heat")
    if not data.get("ok"):
        raise RuntimeError(data.get("error", "no heatmap"))
    heat = data["heat"]
    SHIFT = heat["page_shift"]
    SLICES = heat["slices"]
    STARTS = heat["starts"]
    PAGES = heat["pages"]

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
            self.rows = PAGES
            self.runs = []
            self.image = None
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
            img = QtGui.QImage(SLICES, n, QtGui.QImage.Format_RGB32)
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

        def cell_at(self, pos):
            y = int(pos.y() // ROW)
            if y < 0 or y >= len(self.rows) or pos.x() < GUTTER:
                return None, None
            w = max(self.width() - GUTTER, 1)
            s = int((pos.x() - GUTTER) * SLICES // w)
            return y, min(max(s, 0), SLICES - 1)

        def paintEvent(self, ev):
            p = QtGui.QPainter(self)
            if self.image is None:
                self.build_image()
            w = max(self.width() - GUTTER, 1)
            # Only the rows in view: the image can be thousands of rows tall.
            top = max(int(ev.rect().top() // ROW), 0)
            bottom = min(int(ev.rect().bottom() // ROW) + 1, len(self.rows))
            if bottom > top:
                src = QtCore.QRect(0, top, SLICES, bottom - top)
                dst = QtCore.QRect(GUTTER, top * ROW, w, (bottom - top) * ROW)
                p.drawImage(dst, self.image, src)
            # A rule above each run of neighbouring pages, and its label inside
            # it when the run is tall enough to hold one: a label never runs
            # over the next rule. Shorter runs are named by the tooltip.
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
                               "0x%X  %s" % (r["page"] << SHIFT, r["label"]))
            p.end()

        def resizeEvent(self, ev):
            self.update()

        def mouseMoveEvent(self, ev):
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
            tip = "0x%X%s\nslice %d of %d, from %s\n%d reads, %d writes, %d executes\nDouble-click: go there" % (
                r["page"] << SHIFT, ("  (" + r["label"] + ")") if r["label"] else "",
                s + 1, SLICES, STARTS[s], counts[0], counts[1], counts[2])
            QtWidgets.QToolTip.showText(ev.globalPosition().toPoint(), tip, self)

        def mouseDoubleClickEvent(self, ev):
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
            if STARTS[target]:
                ttd("ui.showbytes %s %X" % (STARTS[target], r["page"] << SHIFT))

    class HeatmapForm(ida_kernwin.PluginForm):
        def OnCreate(self, form):
            self.parent = self.FormToPyQtWidget(form)
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
            self.canvas = Canvas(self)
            scroll = QtWidgets.QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(self.canvas)
            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(2, 2, 2, 2)
            layout.addLayout(bar)
            layout.addWidget(scroll, 1)
            self.parent.setLayout(layout)
            self.refresh()

        def refresh(self, *args):
            text = self.filter.text().strip().lower()
            mode = self.mode.currentIndex()
            rows = PAGES
            if text:
                rows = [r for r in PAGES if text in r["label"].lower() or text in ("%x" % (r["page"] << SHIFT))]
            if mode != 0:
                rows = [r for r in rows if any(c[mode] for c in r["cells"])]
            self.canvas.set_rows(rows, mode)
            self.status.setText("%d of %d pages, %d slices of time" % (len(rows), len(PAGES), SLICES))

        def OnClose(self, form):
            _forms.pop(title, None)

    global _ida_ttd_heatmap_forms
    try:
        _forms = _ida_ttd_heatmap_forms
    except NameError:
        _forms = _ida_ttd_heatmap_forms = {}

    title = "TTD memory heatmap"
    old = ida_kernwin.find_widget(title)
    if old is not None:
        ida_kernwin.close_widget(old, 0)
    form = HeatmapForm()
    _forms[title] = form
    form.Show(title, options=ida_kernwin.PluginForm.WOPN_DP_TAB | ida_kernwin.PluginForm.WOPN_RESTORE)

_ida_ttd_heatmap()
)PY";
}
