import 'dart:convert';
import 'dart:ui';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/session_window.dart';

// Two monitors side by side: a laptop panel and a 1080p screen to its right.
const left = Rect.fromLTWH(0, 0, 1512, 982);
const right = Rect.fromLTWH(1512, 0, 1920, 1080);
const screens = [left, right];

String saved(double x, double y, double w, double h) => jsonEncode(
    {'width': w, 'height': h, 'offsetWidth': x, 'offsetHeight': y});

Map<String, dynamic> remember({
  String peerSaved = '',
  Rect? live,
  Map<String, dynamic> fallback = const {},
  bool fullscreen = true,
  bool maximized = false,
}) =>
    jsonDecode(peerFrameWhileFull(
        peerSaved: peerSaved,
        live: live,
        screens: screens,
        fallback: fallback,
        fullscreen: fullscreen,
        maximized: maximized));

void main() {
  test('full screen on the monitor the Target was last on keeps its windowed frame', () {
    final m = remember(peerSaved: saved(1700, 100, 1200, 800), live: right);
    expect(m, {
      'width': 1200.0, 'height': 800.0, 'offsetWidth': 1700.0, 'offsetHeight': 100.0,
      'isMaximized': false, 'isFullscreen': true,
    });
  });

  test('full screen on another monitor moves the remembered frame onto that monitor', () {
    // Last seen windowed on the left panel, now full screen on the right screen.
    final m = remember(peerSaved: saved(100, 100, 1200, 800), live: right);
    expect(m['offsetWidth'], 1512 + (1920 - 1200) / 2);
    expect(m['offsetHeight'], (1080 - 800) / 2);
    expect(m['width'], 1200.0);
    expect(m['isFullscreen'], true);
  });

  test('first time full screen, with only another window\'s frame to go on, lands on this monitor', () {
    // The global frame belongs to some other session on the left panel.
    final m = remember(fallback: {
      'width': 1000.0, 'height': 700.0, 'offsetWidth': 50.0, 'offsetHeight': 50.0,
    }, live: right);
    expect(right.contains(Offset(m['offsetWidth'] + m['width'] / 2,
        m['offsetHeight'] + m['height'] / 2)), isTrue);
    expect(m['width'], 1000.0); // not the offset, as upstream had it
  });

  test('a saved frame bigger than the new monitor is shrunk to fit it', () {
    final m = remember(peerSaved: saved(1600, 0, 1900, 1070), live: left);
    expect(m['width'], 1512.0);
    expect(m['height'], 982.0);
    expect(m['offsetWidth'], 0.0);
  });

  test('nothing saved anywhere: a default window centred on this monitor', () {
    final m = remember(live: right, maximized: true, fullscreen: false);
    expect(m, {
      'width': 1280.0, 'height': 720.0,
      'offsetWidth': 1512 + (1920 - 1280) / 2, 'offsetHeight': (1080 - 720) / 2,
      'isMaximized': true, 'isFullscreen': false,
    });
  });

  test('live frame unknown (window hidden): keep what was saved', () {
    final m = remember(peerSaved: saved(100, 100, 1200, 800), live: null);
    expect(m['offsetWidth'], 100.0);
    expect(m['isFullscreen'], true);
  });
}
