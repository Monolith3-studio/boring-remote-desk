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

  testWidgets('switch off: one launch call (health report), no banner', (tester) async {
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
    expect(calls, 1);
    expect(find.textContaining('is out.'), findsNothing);
  });

  testWidgets('switch off: a rolled-back update still shows', (tester) async {
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async =>
          UpdateNotice.fromBridge('{"failed":"1.6.0","running":"1.5.0"}'),
      isEnabled: () => false,
      openUrl: (_) async {},
    )));
    await tester.pump();
    expect(find.textContaining('1.5.0'), findsOneWidget);
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

  // --- Install update (ticket 12) ---
  UpdateNoticeBanner withKey({
    bool hasKey = true,
    bool live = false,
    Future<String> Function()? install,
    UpdateNotice notice = const UpdateNotice('1.6.0'),
  }) =>
      UpdateNoticeBanner(
        check: () async => notice,
        isEnabled: () => true,
        openUrl: (_) async {},
        hasKey: () => hasKey,
        liveSession: () async => live,
        install: install ?? () async => 'ok',
      );

  testWidgets('with a key: Install update, no Get update', (tester) async {
    await tester.pumpWidget(host(withKey()));
    await tester.pump();
    expect(find.text('Install update'), findsOneWidget);
    expect(find.text('Get update'), findsNothing);
  });

  testWidgets('no key: Get update, no Install update', (tester) async {
    await tester.pumpWidget(host(withKey(hasKey: false)));
    await tester.pump();
    expect(find.text('Get update'), findsOneWidget);
    expect(find.text('Install update'), findsNothing);
  });

  testWidgets('live session: button disabled with the reason', (tester) async {
    var calls = 0;
    await tester.pumpWidget(host(withKey(live: true, install: () async {
      calls++;
      return 'ok';
    })));
    await tester.pump();
    expect(find.text('Finish your session to update'), findsOneWidget);
    await tester.tap(find.text('Finish your session to update'));
    await tester.pump();
    expect(calls, 0);
  });

  testWidgets('Install update calls the bridge once', (tester) async {
    var calls = 0;
    await tester.pumpWidget(host(withKey(install: () async {
      calls++;
      return 'ok';
    })));
    await tester.pump();
    await tester.tap(find.text('Install update'));
    await tester.pump();
    expect(calls, 1);
  });

  testWidgets('a failed install shows an error and keeps the button', (tester) async {
    await tester.pumpWidget(host(withKey(install: () async => 'sha256')));
    await tester.pump();
    await tester.tap(find.text('Install update'));
    await tester.pump();
    expect(find.text(kBoringInstallErrorText['sha256']!), findsOneWidget);
    expect(find.text('Install update'), findsOneWidget);
  });

  testWidgets('below min with a key: Install update and no dismiss', (tester) async {
    await tester.pumpWidget(host(withKey(notice: const UpdateNotice('1.6.0', belowMin: true))));
    await tester.pump();
    expect(find.text('Install update'), findsOneWidget);
    expect(find.byTooltip('Dismiss'), findsNothing);
  });

  testWidgets('rolled-back update says it failed, no install button', (tester) async {
    await tester.pumpWidget(host(UpdateNoticeBanner(
      check: () async =>
          UpdateNotice.fromBridge('{"failed":"1.6.0","running":"1.5.0"}'),
      isEnabled: () => true,
      openUrl: (_) async {},
      hasKey: () => true,
      install: () async => 'ok',
    )));
    await tester.pump();
    expect(find.text("That update didn't take. You're still on 1.5.0."), findsOneWidget);
    expect(find.text('Install update'), findsNothing);
    await tester.tap(find.byTooltip('Dismiss'));
    await tester.pump();
    expect(find.textContaining("didn't take"), findsNothing);
  });

  // --- Key field in the banner (ticket 15) ---
  UpdateNoticeBanner noKey(Future<String> Function(String) setKey) =>
      UpdateNoticeBanner(
        check: () async => const UpdateNotice('1.6.0'),
        isEnabled: () => true,
        openUrl: (_) async {},
        hasKey: () => false,
        liveSession: () async => false,
        install: () async => 'ok',
        setKey: setKey,
      );

  testWidgets('no key: key field shown, Get update kept', (tester) async {
    await tester.pumpWidget(host(noKey((_) async => 'valid')));
    await tester.pump();
    expect(find.byType(TextField), findsOneWidget);
    expect(find.text('Get update'), findsOneWidget);
    expect(find.text('Install update'), findsNothing);
  });

  testWidgets('valid key from the banner: Install update', (tester) async {
    String? sent;
    await tester.pumpWidget(host(noKey((k) async {
      sent = k;
      return 'valid';
    })));
    await tester.pump();
    await tester.enterText(find.byType(TextField), 'BR-123');
    await tester.tap(find.text('Check'));
    await tester.pumpAndSettle();
    expect(sent, 'BR-123');
    expect(find.text('Install update'), findsOneWidget);
    expect(find.byType(TextField), findsNothing);
  });

  testWidgets('invalid key: message shown, field stays', (tester) async {
    await tester.pumpWidget(host(noKey((_) async => 'unknown')));
    await tester.pump();
    await tester.enterText(find.byType(TextField), 'nope');
    await tester.tap(find.text('Check'));
    await tester.pumpAndSettle();
    expect(find.textContaining("We don't recognize that key"), findsOneWidget);
    expect(find.byType(TextField), findsOneWidget);
    expect(find.text('Install update'), findsNothing);
  });
}
