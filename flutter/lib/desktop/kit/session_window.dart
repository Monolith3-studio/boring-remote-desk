import 'dart:convert';
import 'dart:ui';

/// The frame to remember for one Target while its window is full screen or maximized.
///
/// A full-screen window's own frame is the whole screen, so upstream keeps the Target's
/// last windowed frame instead, falling back to the last frame any window saved. With
/// several sessions full screen on different monitors that fallback is often another
/// monitor, and reopening the Target went full screen in the wrong place. Here the
/// remembered frame always sits on the monitor the window is full screen on ([live]),
/// so reopening the Target restores that monitor before going full screen again.
///
/// [peerSaved] is the Target's saved frame JSON (may be empty), [fallback] the global
/// one. Returns the JSON upstream's LastWindowPosition reads.
String peerFrameWhileFull({
  required String peerSaved,
  required Rect? live,
  required List<Rect> screens,
  required Map<String, dynamic> fallback,
  required bool fullscreen,
  required bool maximized,
}) {
  Rect? frame = _frame(_decode(peerSaved)) ?? _frame(fallback);
  final here = live == null ? null : _screenOf(live.center, screens);
  if (here != null &&
      (frame == null || _screenOf(frame.center, screens) != here)) {
    var w = frame?.width ?? 1280, h = frame?.height ?? 720;
    if (w > here.width) w = here.width;
    if (h > here.height) h = here.height;
    frame = Rect.fromLTWH(here.left + (here.width - w) / 2,
        here.top + (here.height - h) / 2, w, h);
  }
  return jsonEncode({
    'width': frame?.width,
    'height': frame?.height,
    'offsetWidth': frame?.left,
    'offsetHeight': frame?.top,
    'isMaximized': maximized,
    'isFullscreen': fullscreen,
  });
}

Map<String, dynamic> _decode(String s) {
  try {
    final m = jsonDecode(s);
    return m is Map<String, dynamic> ? m : const {};
  } catch (_) {
    return const {};
  }
}

Rect? _frame(Map<String, dynamic> m) {
  final x = m['offsetWidth'], y = m['offsetHeight'];
  final w = m['width'], h = m['height'];
  if (x is! num || y is! num || w is! num || h is! num) return null;
  return Rect.fromLTWH(x.toDouble(), y.toDouble(), w.toDouble(), h.toDouble());
}

Rect? _screenOf(Offset p, List<Rect> screens) {
  for (final s in screens) {
    if (s.contains(p)) return s;
  }
  return null;
}
