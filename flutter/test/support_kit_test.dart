import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/desktop/kit/access.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/simple_settings.dart';
import 'package:flutter_hbb/desktop/kit/support.dart';
import 'package:flutter_test/flutter_test.dart';

/// v1.7 t20: Settings' "Save a support file" and Home's notice after a crash.
void main() {
  Widget app(Widget child) => MaterialApp(theme: Kit.theme(), home: Material(child: child));
  const saved = '/Users/me/Desktop/Boring Remote support 2026-11-03.zip';

  tearDown(KitWords.mac);

  test('the Access rows go in as one line each, a failed read counted as no', () async {
    final checks = [
      AccessCheck(label: 'Screen Recording', why: '', read: () async => true, fix: () async {}),
      AccessCheck(label: 'Accessibility', why: '', read: () async => false, fix: () async {}),
      AccessCheck(label: 'Open for connections', why: '', read: () => Future.error('down'), fix: () async {}),
    ];
    expect(await accessReport(checks), 'Screen Recording: yes\nAccessibility: no\nOpen for connections: no');
    expect(await accessReport(const []), '');
  });

  test('the words are plain and short', () {
    expect(SupportWords.save, 'Save a support file');
    expect(SupportWords.crashed, 'Boring Remote closed unexpectedly last time.');
    expect(SupportWords.saved('Boring Remote support 2026-11-03.zip'),
        'Saved to your Desktop: Boring Remote support 2026-11-03.zip');
    for (final w in [SupportWords.what, SupportWords.crashed, SupportWords.failed]) {
      expect(w.split(RegExp(r'[.!?] ')).every((s) => s.split(' ').length <= 16), isTrue, reason: w);
      expect(w.toLowerCase(), isNot(anyOf(contains('log'), contains('diagnostic'), contains('error'))), reason: w);
    }
  });

  testWidgets('Settings: one click saves, says where, and can save again', (tester) async {
    var calls = 0;
    final done = Completer<String>();
    await tester.pumpWidget(app(SupportSection(save: () {
      calls++;
      return done.future;
    })));
    expect(find.text(SupportWords.title), findsOneWidget);
    expect(find.text(SupportWords.what), findsOneWidget);
    await tester.tap(find.text(SupportWords.save));
    await tester.pump();
    expect(find.text(SupportWords.saving), findsOneWidget);
    await tester.tap(find.text(SupportWords.saving)); // no second zip while one is being made
    done.complete(saved);
    await tester.pump();
    expect(calls, 1);
    expect(find.text(SupportWords.saved('Boring Remote support 2026-11-03.zip')), findsOneWidget);
    await tester.tap(find.text(SupportWords.save));
    await tester.pump();
    expect(calls, 2);
  });

  testWidgets('Settings: a save that fails says so and lets you try again', (tester) async {
    await tester.pumpWidget(app(SupportSection(save: () async => '')));
    await tester.tap(find.text(SupportWords.save));
    await tester.pump();
    expect(find.text(SupportWords.failed), findsOneWidget);
    await tester.pumpWidget(app(SupportSection(save: () => Future.error('disk full'))));
    await tester.tap(find.text(SupportWords.save));
    await tester.pump();
    expect(find.text(SupportWords.failed), findsOneWidget);
    expect(find.text(SupportWords.save), findsOneWidget);
  });

  testWidgets('Home: no crash, no notice', (tester) async {
    await tester.pumpWidget(app(CrashNotice(crashed: () => false, save: () async => saved, onDone: () {})));
    expect(find.text(SupportWords.crashed), findsNothing);
    expect(find.byType(SizedBox), findsWidgets);
  });

  testWidgets('Home: after a crash one calm line offers the support file, once', (tester) async {
    var checked = 0, done = 0;
    await tester.pumpWidget(app(CrashNotice(
        crashed: () {
          checked++;
          return true;
        },
        save: () async => saved,
        onDone: () => done++)));
    expect(find.text(SupportWords.crashed), findsOneWidget);
    expect(find.byIcon(Icons.error_outline), findsNothing); // calm: no alarm icon
    await tester.tap(find.text(SupportWords.save));
    await tester.pump();
    expect(find.text(SupportWords.saved('Boring Remote support 2026-11-03.zip')), findsOneWidget);
    expect(done, 1);
    await tester.pumpWidget(app(CrashNotice(crashed: () => true, save: () async => saved, onDone: () => done++)));
    expect(checked, 1); // read once, not on every rebuild
  });

  testWidgets('Home: Not now hides it and does not offer these crashes again', (tester) async {
    var done = 0;
    await tester.pumpWidget(app(CrashNotice(crashed: () => true, save: () async => saved, onDone: () => done++)));
    await tester.tap(find.text(SupportWords.notNow));
    await tester.pump();
    expect(find.text(SupportWords.crashed), findsNothing);
    expect(done, 1);
  });

  testWidgets('Settings shows Help when the page passes it', (tester) async {
    await tester.pumpWidget(app(SimpleSettings(
      macName: 'Edit Bay 2',
      onRename: (_) async {},
      passwordSet: true,
      generatePassword: () async => '',
      remoteAccess: true,
      onRemoteAccess: (_) {},
      checkUpdates: true,
      onCheckUpdates: (_) {},
      help: SupportSection(save: () async => saved),
    )));
    await tester.scrollUntilVisible(find.text(SupportWords.save), 200,
        scrollable: find.descendant(of: find.byType(ListView), matching: find.byType(Scrollable)).first);
    expect(find.text(SupportWords.save), findsOneWidget);
  });

  testWidgets('Windows words: nothing says Mac', (tester) async {
    KitWords.windows();
    await tester.pumpWidget(app(Column(children: [
      SupportSection(save: () async => saved),
      CrashNotice(crashed: () => true, save: () async => saved, onDone: () {}),
    ])));
    final texts = tester.widgetList<Text>(find.byType(Text)).map((t) => t.data ?? '');
    expect(texts.where((s) => s.contains('Mac')), isEmpty);
  });
}
