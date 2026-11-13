"""Qt touches the plugin cannot make from C++.

IDA's SDK has no call for a toolbar button's width or a submenu's icon, and
reaching IDA's Qt from C++ means building against its exact Qt version. The
plugin calls these through IDAPython's PySide instead. Each is a no-op
without Qt (an idalib worker).
"""

try:
    from PySide6 import QtGui, QtWidgets
    import shiboken6
except ImportError:
    QtWidgets = None

_pos_button = None


def _widgets():
    app = QtWidgets.QApplication.instance() if QtWidgets is not None else None
    return app.allWidgets() if app is not None else []


def pin_position_width(tooltip, sample):
    """Give the toolbar's position button a fixed minimum width, wide enough
    for 'sample' (the recording's last position) with every digit as wide as
    the widest, so the toolbar does not shift as the position changes. The
    button is found by its tooltip once, then kept."""
    global _pos_button
    if QtWidgets is None:
        return
    b = _pos_button
    if b is None or not shiboken6.isValid(b):
        b = None
        for w in _widgets():
            a = w.defaultAction() if isinstance(w, QtWidgets.QToolButton) else None
            if a is not None and a.toolTip() == tooltip:
                b = w
                break
        _pos_button = b
        if b is None:
            return
    fm = b.fontMetrics()
    digit = max(fm.horizontalAdvance(c) for c in "0123456789ABCDEF")
    want = fm.horizontalAdvance("Position ") + 16 + sum(
        digit if c.isalnum() else fm.horizontalAdvance(c) for c in sample)
    if b.minimumWidth() != want:
        b.setMinimumWidth(want)


def set_submenu_icon(menu, label, svg):
    """Set the icon of submenu 'label' of menu 'menu' (create_menu takes none)."""
    if QtWidgets is None:
        return
    pix = QtGui.QPixmap()
    pix.loadFromData(svg.encode(), "SVG")
    for m in _widgets():
        if not isinstance(m, QtWidgets.QMenu) or not shiboken6.isValid(m) \
                or m.title().replace("&", "") != menu:
            continue
        for a in m.actions():
            sub = a.menu()
            if sub is not None and shiboken6.isValid(sub) and a.text().replace("&", "") == label:
                a.setIcon(QtGui.QIcon(pix))


def chooser_current_column(title):
    """The column of the current cell in the chooser titled 'title', -1 when
    unknown. A double-click makes the clicked cell current before IDA calls
    the chooser's enter(), which is told the row only."""
    if QtWidgets is None:
        return -1
    import ida_kernwin
    tw = ida_kernwin.find_widget(title)
    if tw is None:
        return -1
    w = ida_kernwin.PluginForm.TWidgetToPySideWidget(tw)
    if w is None:
        return -1
    for v in w.findChildren(QtWidgets.QAbstractItemView):
        if shiboken6.isValid(v) and v.currentIndex().isValid():
            return v.currentIndex().column()
    return -1


def theme_is_dark():
    """1 when IDA's theme is dark (Qt's palette), 0 when light or unknown."""
    app = QtWidgets.QApplication.instance() if QtWidgets is not None else None
    return int(app is not None and app.palette().base().color().lightness() < 128)


def fresh_module(name):
    """The module 'name' (one of the windows: ida_ttd_graph, ida_ttd_heatmap,
    ida_ttd_calltree), imported, and reloaded when its file changed since:
    a reinstall while IDA runs then shows the installed window code, as
    when the plugin ran it from a string on every call, without compiling
    it again on every show and refresh. The modules keep their open windows
    across a reload."""
    import importlib
    import os
    import sys

    def stamp(m):
        try:
            st = os.stat(m.__file__)
            return (st.st_mtime_ns, st.st_size)
        except (OSError, TypeError, AttributeError):
            return None

    mod = sys.modules.get(name)
    if mod is None:
        mod = importlib.import_module(name)
    elif stamp(mod) != getattr(mod, "_ida_ttd_stamp", None):
        mod = importlib.reload(mod)
    mod._ida_ttd_stamp = stamp(mod)
    return mod


# The window a recording runs behind (run_query in query_runner.cpp): what
# is running, for how long, Sogen's log as it comes, and Pause and Stop.
# IDA's wait box shows a few lines of text and offers only Cancel, which for
# a recording means "stop and keep what ran". The plugin drives the window
# from its wait loop: recording_window_update() ten times a second, which
# also runs Qt's events, since the plugin's loop is all that runs while the
# recording does.
_rec = None


def _main_window():
    app = QtWidgets.QApplication.instance()
    for w in app.topLevelWidgets() if app is not None else []:
        if isinstance(w, QtWidgets.QMainWindow):
            return w
    return None


def recording_window_open(title, what, can_pause):
    """Show the window. 1 when it is up, 0 without Qt."""
    global _rec
    if QtWidgets is None or QtWidgets.QApplication.instance() is None:
        return 0
    from PySide6 import QtCore
    recording_window_close()

    class RecordingWindow(QtWidgets.QDialog):
        def __init__(self):
            super().__init__(_main_window())
            self.request = ""
            self.paused = False
            self.stopping = False
            self.setWindowTitle(title)
            self.setWindowModality(QtCore.Qt.ApplicationModal)
            self.setWindowFlag(QtCore.Qt.WindowContextHelpButtonHint, False)
            lay = QtWidgets.QVBoxLayout(self)
            self.what = QtWidgets.QLabel(what)
            self.status = QtWidgets.QLabel("Starting...")
            lay.addWidget(self.what)
            lay.addWidget(self.status)
            lay.addWidget(QtWidgets.QLabel("Sogen's log"))
            self.log = QtWidgets.QPlainTextEdit()
            self.log.setReadOnly(True)
            self.log.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
            self.log.setMaximumBlockCount(20000)
            self.log.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
            self.log.setPlaceholderText("Nothing logged yet.")
            lay.addWidget(self.log, 1)
            row = QtWidgets.QHBoxLayout()
            row.addStretch(1)
            self.pause = None
            if can_pause:
                self.pause = QtWidgets.QPushButton("&Pause")
                self.pause.setToolTip("Hold the program where it is; Resume carries on")
                self.pause.clicked.connect(self._pause)
                row.addWidget(self.pause)
            self.stop = QtWidgets.QPushButton("&Stop recording")
            self.stop.setToolTip("End the recording here and keep what ran")
            self.stop.clicked.connect(self._stop)
            row.addWidget(self.stop)
            lay.addLayout(row)
            self.resize(780, 380)

        def _pause(self):
            if self.stopping:
                return
            self.paused = not self.paused
            self.request = "pause" if self.paused else "resume"
            self.pause.setText("&Resume" if self.paused else "&Pause")

        def _stop(self):
            if self.stopping:
                return
            self.stopping = True
            self.request = "stop"
            self.stop.setEnabled(False)
            if self.pause is not None:
                self.pause.setEnabled(False)

        # Escape and the close box stop the recording, as Cancel did; the
        # window itself goes only when the plugin closes it.
        def reject(self):
            self._stop()

        def closeEvent(self, e):
            e.ignore()
            self._stop()

    _rec = RecordingWindow()
    _rec.show()
    QtWidgets.QApplication.processEvents()
    return 1


def recording_window_update(status, lines):
    """Show 'status', append 'lines' (newline-separated, may be empty) to the
    log, run Qt's events, and return what was asked since the last call:
    "stop", "pause", "resume", "" for nothing, or "gone" when the window is
    not there."""
    w = _rec
    if w is None or not shiboken6.isValid(w):
        return "gone"
    if status and w.status.text() != status:
        w.status.setText(status)
    if lines:
        bar = w.log.verticalScrollBar()
        follow = bar.value() >= bar.maximum() - 2
        w.log.appendPlainText(lines)
        if follow:
            bar.setValue(bar.maximum())
    QtWidgets.QApplication.processEvents()
    r, w.request = w.request, ""
    return r


def recording_window_close():
    global _rec
    w, _rec = _rec, None
    if w is not None and shiboken6.isValid(w):
        w.hide()
        w.deleteLater()
