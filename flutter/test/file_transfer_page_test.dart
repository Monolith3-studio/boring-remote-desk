// boring-remote (v1.7 t28): pumps the real File Transfer page with a loaded folder on both sides.
// Needs a rebranded tree with the generated bridge (boring/rebrand.py, then the bridge step), like
// the other tests here that import models/.
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/pages/file_manager_page.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_test/flutter_test.dart';

/// The bridge calls the page makes at build time, answered the way Rust does. Everything else is
/// fire-and-forget (Future<void>), which is all the page does with the other calls.
class _FakeBridge implements RustdeskImpl {
  @override
  dynamic noSuchMethod(Invocation i) {
    switch (i.memberName) {
      case #translate:
        return i.namedArguments[#name] as String;
      case #sessionStart:
        return const Stream<EventToUI>.empty();
      case #getDoubleClickTime:
        return 500;
      case #sessionAddSync:
      case #mainGetLocalOption:
      case #getLocalFlutterOption:
      case #mainGetUserDefaultOption:
      case #mainGetBuildinOption:
      case #mainGetOptionSync:
      case #mainGetEnv:
      case #mainGetPeerOptionSync:
      case #mainGetPeerFlutterOptionSync:
        return '';
      case #mainGetUseTextureRender:
      case #mainHasGpuTextureRender:
      case #isOutgoingOnly:
      case #isIncomingOnly:
      case #isCustomClient:
      case #isDisableAb:
      case #isDisableAccount:
      case #isDisableGroupPanel:
      case #isDisableSettings:
      case #isDisableInstallation:
        return false;
      case #optionSynced:
        return Future<bool>.value(false);
      case #sessionGetTrackpadSpeed:
        return Future<int?>.value(100);
      case #mainGetConnectStatus:
        return Future<String>.value('{}');
      case #sessionGetPlatform:
        return Future<String>.value('Mac OS');
      case #sessionGetFlutterOption:
      case #sessionGetOption:
        return Future<String?>.value(null);
      case #sessionGetPeerOption:
        return Future<String>.value('');
    }
    return Future<void>.value();
  }
}

FileDirectory movies() => FileDirectory.fromJson({
      'id': 0,
      'path': '/Users/jason/Movies',
      'entries': [
        {'entry_type': 3, 'name': 'cut.mov', 'size': 1000, 'modified_time': 1700000000},
        {'entry_type': 2, 'name': 'Footage', 'size': 0, 'modified_time': 1700000000},
      ],
    });

void main() {
  for (final (name, size) in [
    ('normal', const Size(1300, 800)),
    ('narrow', const Size(800, 600)),
    ('full screen', const Size(2560, 1440)),
  ]) {
    testWidgets('both panes show their location bar and files: $name window', (tester) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      isTest = true; // ServerModel's forever timer stays off
      // The test font draws every letter 14px wide, which overflows the pane headers at 800px. An
      // overflow only clips, it is not the grey block this test is for; anything else still fails.
      final inner = FlutterError.onError;
      if (size.width < 1000) {
        FlutterError.onError = (d) {
          if (!d.exceptionAsString().contains('overflowed')) inner?.call(d);
        };
      }
      platformFFI.ffiBindForTest = _FakeBridge();

      final page = FileManagerPage(id: '192.168.1.112', password: null, isSharedPassword: null);
      await tester.pumpWidget(MaterialApp(theme: boringKitTheme, home: page));
      await tester.pump();
      page.ffi.fileModel.localController.directory.value = movies();
      page.ffi.fileModel.remoteController.directory.value = movies();
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 500));
      FlutterError.onError = inner;

      // What went grey in the release build: on the old theme this throws on MyTheme.tabbar.
      expect(tester.takeException(), isNull);
      expect(find.byType(ErrorWidget), findsNothing);
      expect(find.text('cut.mov'), findsNWidgets(2));
      expect(find.text('Footage'), findsNWidgets(2));
      expect(find.text('Movies'), findsNWidgets(2)); // location bar, one per pane
    });
  }
}
