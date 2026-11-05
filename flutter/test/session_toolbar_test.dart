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

  testWidgets('while High Efficiency is on, Quality says so, not Auto; a hand pick still reports',
      (tester) async {
    wide(tester);
    final got = <String>[];
    await tester.pumpWidget(host(bar(link: LinkState.localHighEfficiency, onQuality: got.add)));
    expect(find.text('Quality: High Efficiency'), findsOneWidget);
    expect(find.text('Quality: Auto'), findsNothing);
    await tester.tap(find.text('Quality: High Efficiency'));
    await tester.pumpAndSettle();
    final on = tester.widget<CheckedPopupMenuItem<String>>(
        find.widgetWithText(CheckedPopupMenuItem<String>, 'High Efficiency'));
    expect(on.checked, isTrue);
    await tester.tap(find.text('Fastest'));
    await tester.pumpAndSettle();
    expect(got, ['low']);
  });

  // boring-remote (v1.7 t25): a slow path is visible.
  test('the badge names the link type Rust reports', () {
    expect(linkStateFor('LocalWired'), LinkState.localWired);
    expect(linkStateFor('LocalWiFi'), LinkState.localWiFi);
    expect(linkStateFor('LocalWiredHighEfficiency'), LinkState.localWiredHighEfficiency);
    expect(linkStateFor('LocalWiFiHighEfficiency'), LinkState.localWiFiHighEfficiency);
    expect(LinkBadge.label(LinkState.localWired), 'Local · wired');
    expect(LinkBadge.label(LinkState.localWiFi), 'Local · Wi-Fi');
    expect(LinkBadge.label(LinkState.localWiredHighEfficiency), 'Local · wired · High Efficiency');
    expect(LinkBadge.label(LinkState.localWiFiHighEfficiency), 'Local · Wi-Fi · High Efficiency');
    for (final he in LinkState.values) {
      expect(he.isHighEfficiency, he.name.endsWith('HighEfficiency'), reason: he.name);
    }
  });

  test('picking a quality by hand keeps the link type', () {
    expect(streamTypeAfterQualityPick('LocalWiredHighEfficiency'), 'LocalWired');
    expect(streamTypeAfterQualityPick('LocalWiFiHighEfficiency'), 'LocalWiFi');
    expect(streamTypeAfterQualityPick('LocalWired'), 'LocalWired');
  });

  test('picking a quality by hand drops the link back to plain Local', () {
    expect(streamTypeAfterQualityPick('LocalHighEfficiency'), 'Local');
    expect(linkStateFor(streamTypeAfterQualityPick('LocalHighEfficiency')), LinkState.local);
    for (final other in ['Local', 'Tailscale', '']) {
      expect(streamTypeAfterQualityPick(other), other, reason: other);
    }
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
