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


def theme_is_dark():
    """1 when IDA's theme is dark (Qt's palette), 0 when light or unknown."""
    app = QtWidgets.QApplication.instance() if QtWidgets is not None else None
    return int(app is not None and app.palette().base().color().lightness() < 128)
