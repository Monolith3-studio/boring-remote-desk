import 'package:flutter/material.dart';
import 'package:flutter_hbb/desktop/kit/access.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_test/flutter_test.dart';

/// v1.7 t17 follow-up: Settings' Access section and Home's "not ready" line.
void main() {
  late Map<String, bool> state;
  late List<String> fixed;

  List<AccessCheck> checks() => [
        for (final id in ['screen', 'control', 'running'])
          AccessCheck(
            label: 'Row $id',
            why: 'Why $id',
            read: () async => state[id]!,
            fix: () async => fixed.add(id),
          ),
      ];

  Widget app(Widget child) => MaterialApp(theme: Kit.theme(), home: Material(child: child));

  setUp(() {
    state = {'screen': true, 'control': true, 'running': true};
    fixed = [];
  });

  test('the first missing row is the one the summary names', () {
    expect(firstMissing([true, true, true]), isNull);
    expect(firstMissing([true, false, false]), 1);
    expect(firstMissing([]), isNull);
  });

  testWidgets('all granted: one green Ready line, a check on every row, no Fix', (tester) async {
    await tester.pumpWidget(app(AccessSection(checks: checks(), pollEvery: const Duration(hours: 1))));
    await tester.pump();
    expect(find.text(AccessWords.ready), findsOneWidget);
    expect(find.byIcon(Icons.check_circle), findsNWidgets(4)); // summary + 3 rows
    expect(find.text(AccessWords.fix), findsNothing);
  });

  testWidgets('one missing: the summary names it with its Fix, the row has a Fix too', (tester) async {
    state['control'] = false;
    await tester.pumpWidget(app(AccessSection(checks: checks(), pollEvery: const Duration(hours: 1))));
    await tester.pump();
    expect(find.text(AccessWords.ready), findsNothing);
    expect(find.text(AccessWords.notReady('Row control')), findsOneWidget);
    expect(find.text(AccessWords.fix), findsNWidgets(2));
    await tester.tap(find.text(AccessWords.fix).first);
    await tester.pump();
    expect(fixed, ['control']);
  });

  testWidgets('rows turn green while the page is open', (tester) async {
    state['screen'] = false;
    await tester.pumpWidget(app(AccessSection(checks: checks(), pollEvery: const Duration(seconds: 3))));
    await tester.pump();
    expect(find.text(AccessWords.notReady('Row screen')), findsOneWidget);
    state['screen'] = true;
    await tester.pump(const Duration(seconds: 3));
    await tester.pump();
    expect(find.text(AccessWords.ready), findsOneWidget);
  });

  testWidgets('Home shows nothing when ready, the first missing row when not', (tester) async {
    await tester.pumpWidget(app(AccessSummary(checks: checks(), pollEvery: const Duration(hours: 1))));
    await tester.pump();
    expect(find.text(AccessWords.ready), findsNothing);
    expect(find.text(AccessWords.fix), findsNothing);
    state['running'] = false;
    await tester.pumpWidget(app(AccessSummary(key: UniqueKey(), checks: checks(), pollEvery: const Duration(hours: 1))));
    await tester.pump();
    expect(find.text(AccessWords.notReady('Row running')), findsOneWidget);
    await tester.tap(find.text(AccessWords.fix));
    expect(fixed, ['running']);
  });

  test('open at login: a LaunchAgent that opens the app by bundle id, credited to it', () {
    final p = openAtLoginPlist('io.boringlabs.remote.agent');
    expect(p, contains('<string>/usr/bin/open</string>'));
    expect(p, contains('<string>-b</string>'));
    expect(p, contains('<key>AssociatedBundleIdentifiers</key>'));
    expect(p, contains('<key>RunAtLoad</key>'));
    expect(p, isNot(contains('KeepAlive')));
    expect(openAtLoginPath('/Users/x'), '/Users/x/Library/LaunchAgents/$kOpenAtLoginLabel.plist');
  });
}
