import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/session_toolbar.dart';

Widget host(Widget w) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: w));

/// A session window is wide; the test font is wider than any real one.
void wide(WidgetTester tester) {
  tester.view.physicalSize = const Size(1600, 600);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
}

SessionToolbar bar({
  LinkState link = LinkState.local,
  VoidCallback? onSendFiles,
  VoidCallback? onDisconnect,
  void Function(int)? onPickDisplay,
  void Function(String)? onQuality,
  List<Widget> more = const [],
}) =>
    SessionToolbar(
      link: link,
      onSendFiles: onSendFiles ?? () {},
      displays: 2,
      display: 0,
      onPickDisplay: onPickDisplay ?? (_) {},
      quality: 'balanced',
      qualities: const {'balanced': 'Auto', 'best': 'Best picture', 'low': 'Fastest'},
      onQuality: onQuality ?? (_) {},
      onDisconnect: onDisconnect ?? () {},
      more: more,
    );

void main() {
  test('Link Badge follows the path the session actually took (Rust stream_type)', () {
    expect(linkStateFor('Local'), LinkState.local);
    expect(linkStateFor('Tailscale'), LinkState.viaInternet);
    // v1.7 t05: Rust re-reports a Local session once High Efficiency is actually applied.
    expect(linkStateFor('LocalHighEfficiency'), LinkState.localHighEfficiency);
    for (final other in ['', 'TCP', 'UDP', 'WebRTC/IPv6', 'other']) {
      expect(linkStateFor(other), LinkState.unknown, reason: other);
    }
  });

  testWidgets('Link Badge names the link, and hides when unknown', (tester) async {
    for (final (link, label) in [
      (LinkState.local, 'Local'),
      (LinkState.localHighEfficiency, 'Local · High Efficiency'),
      (LinkState.viaInternet, 'Via internet'),
    ]) {
      await tester.pumpWidget(host(LinkBadge(link: link)));
      expect(find.text(label), findsOneWidget);
    }
    await tester.pumpWidget(host(const LinkBadge()));
    expect(find.byType(Text), findsNothing);
  });

  testWidgets('five primary actions show: badge, send files, display, quality, disconnect',
      (tester) async {
    wide(tester);
    await tester.pumpWidget(host(bar()));
    expect(find.text('Local'), findsOneWidget);
    expect(find.text('Send files'), findsOneWidget);
    expect(find.text('Display 1'), findsOneWidget);
    expect(find.text('Quality: Auto'), findsOneWidget);
    expect(find.text('Disconnect'), findsOneWidget);
  });

  testWidgets('send files and disconnect call back', (tester) async {
    final got = <String>[];
    wide(tester);
    await tester.pumpWidget(host(bar(
        onSendFiles: () => got.add('send'), onDisconnect: () => got.add('bye'))));
    await tester.tap(find.text('Send files'));
    await tester.tap(find.text('Disconnect'));
    expect(got, ['send', 'bye']);
  });

  testWidgets('display pick lists every display and switches to the one picked',
      (tester) async {
    wide(tester);
    final got = <int>[];
    await tester.pumpWidget(host(bar(onPickDisplay: got.add)));
    await tester.tap(find.text('Display 1'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Display 2').last);
    await tester.pumpAndSettle();
    expect(got, [1]);
  });

  testWidgets('quality defaults to Auto and reports the pick', (tester) async {
    wide(tester);
    final got = <String>[];
    await tester.pumpWidget(host(bar(onQuality: got.add)));
    await tester.tap(find.text('Quality: Auto'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Fastest'));
    await tester.pumpAndSettle();
    expect(got, ['low']);
  });

  testWidgets('rare actions stay behind More until it is pressed', (tester) async {
    wide(tester);
    await tester.pumpWidget(host(bar(more: const [Text('Lock screen')])));
    expect(find.text('Lock screen'), findsNothing);
    await tester.tap(find.byKey(SessionToolbar.moreKey));
    await tester.pump();
    expect(find.text('Lock screen'), findsOneWidget);
    await tester.tap(find.byKey(SessionToolbar.moreKey));
    await tester.pump();
    expect(find.text('Lock screen'), findsNothing);
  });

  testWidgets('no More button when there is nothing rare', (tester) async {
    wide(tester);
    await tester.pumpWidget(host(bar()));
    expect(find.byKey(SessionToolbar.moreKey), findsNothing);
  });
}
