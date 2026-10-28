import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/widgets/update_notice_banner.dart';

Widget host(UpdateNoticeBanner b) =>
    MaterialApp(home: Scaffold(body: b));

void main() {
  testWidgets('banner shows for a newer version', (tester) async {
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async => const UpdateNotice('1.6.0'),
      isEnabled: () => true,
      openUrl: (_) async {},
    )));
    await tester.pump();
    expect(find.text('Boring Remote 1.6.0 is out.'), findsOneWidget);
    expect(find.text('Get update'), findsOneWidget);
  });

  testWidgets('banner hidden when bridge returns null', (tester) async {
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async => null,
      isEnabled: () => true,
      openUrl: (_) async {},
    )));
    await tester.pump();
    expect(find.textContaining('is out.'), findsNothing);
    expect(find.text('Get update'), findsNothing);
  });

  testWidgets('switch off: bridge is never called, no banner', (tester) async {
    var calls = 0;
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async {
        calls++;
        return const UpdateNotice('9.9.9');
      },
      isEnabled: () => false,
      openUrl: (_) async {},
    )));
    await tester.pump();
    expect(calls, 0);
    expect(find.textContaining('is out.'), findsNothing);
  });

  testWidgets('hourly timer re-checks', (tester) async {
    var calls = 0;
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async {
        calls++;
        return null;
      },
      isEnabled: () => true,
      openUrl: (_) async {},
    )));
    await tester.pump();
    expect(calls, 1);
    await tester.pump(kBoringUpdateRecheckInterval);
    expect(calls, 2);
  });

  testWidgets('banner hides when a later check returns null', (tester) async {
    final answers = <UpdateNotice?>[const UpdateNotice('1.6.0'), null];
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async => answers.removeAt(0),
      isEnabled: () => true,
      openUrl: (_) async {},
    )));
    await tester.pump();
    expect(find.text('Boring Remote 1.6.0 is out.'), findsOneWidget);
    await tester.pump(kBoringUpdateRecheckInterval);
    await tester.pump();
    expect(find.textContaining('is out.'), findsNothing);
  });

  testWidgets('Get update opens the one update URL', (tester) async {
    Uri? opened;
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async => const UpdateNotice('1.6.0'),
      isEnabled: () => true,
      openUrl: (u) async => opened = u,
    )));
    await tester.pump();
    await tester.tap(find.text('Get update'));
    expect(opened.toString(), 'https://boringlabs.online/remote/update');
  });

  testWidgets('dismiss hides the banner when not below min', (tester) async {
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async => const UpdateNotice('1.6.0'),
      isEnabled: () => true,
      openUrl: (_) async {},
    )));
    await tester.pump();
    expect(find.byTooltip('Dismiss'), findsOneWidget);
    await tester.tap(find.byTooltip('Dismiss'));
    await tester.pump();
    expect(find.textContaining('is out.'), findsNothing);
  });

  testWidgets('below min: no dismiss control, banner stays', (tester) async {
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async => const UpdateNotice('1.7.0', belowMin: true),
      isEnabled: () => true,
      openUrl: (_) async {},
    )));
    await tester.pump();
    expect(find.text('Boring Remote 1.7.0 is out.'), findsOneWidget);
    expect(find.byTooltip('Dismiss'), findsNothing);
  });

  test('fromBridge parses the Rust JSON and rejects junk', () {
    expect(UpdateNotice.fromBridge(null), isNull);
    expect(UpdateNotice.fromBridge('nope'), isNull);
    expect(UpdateNotice.fromBridge('{"below_min":true}'), isNull);
    final n = UpdateNotice.fromBridge('{"version":"1.7.0","below_min":true}')!;
    expect(n.version, '1.7.0');
    expect(n.belowMin, isTrue);
    expect(UpdateNotice.fromBridge('{"version":"1.7.0"}')!.belowMin, isFalse);
  });
}
