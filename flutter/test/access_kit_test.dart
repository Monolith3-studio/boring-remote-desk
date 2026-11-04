import 'dart:io';

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

  test('the why lines name the other machine in this platform\'s word', () {
    KitWords.windows();
    addTearDown(KitWords.mac);
    expect(AccessWords.runningWhy, 'So your other computers can get in with this window closed.');
    expect(AccessWords.listeningWhy, 'So your other computers on this network can reach this one.');
    KitWords.mac();
    expect(AccessWords.runningWhy, 'So your other computers can get in with this window closed.');
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

  // A real Mac (macOS 26) after the bundle was replaced: launchd held the agent at
  // "spawn failed" (EX_CONFIG 78, "needs LWCR update"); kickstart -k exited 0 and did nothing.
  const stuck = 'gui/501/$kAgentLabel = {\n\tstate = spawn scheduled\n\tjob state = spawn failed\n'
      '\tlast exit code = 78: EX_CONFIG\n\tproperties = needs LWCR update | managed LWCR | has LWCR\n}\n';
  const up = 'gui/501/$kAgentLabel = {\n\tstate = running\n\tpid = 4242\n}\n';

  /// A fake launchctl holding the stuck job: kickstart brings it up only when [kickstartFixes],
  /// bootstrap (after bootout) only when [bootstrapFixes].
  ({List<String> calls, RunProcess run}) launchd({bool kickstartFixes = false, bool bootstrapFixes = true}) {
    final calls = <String>[];
    var loaded = true, running = false;
    Future<ProcessResult> run(String exe, List<String> args) async {
      calls.add('$exe ${args.join(' ')}');
      var out = '', code = 0;
      switch (args.first) {
        case 'print':
          if (!loaded) code = 113;
          out = running ? up : stuck;
        case 'kickstart':
          if (kickstartFixes) running = true;
        case 'bootout':
          loaded = false;
          running = false;
        case 'bootstrap':
          loaded = true;
          running = bootstrapFixes;
      }
      return ProcessResult(0, code, out, '');
    }

    return (calls: calls, run: run);
  }

  Future<void> noWait(Duration _) async {}

  test('the agent counts as running only on launchctl\'s own "state = running" line', () {
    expect(agentRunning(up), isTrue);
    expect(agentRunning(stuck), isFalse);
    expect(agentRunning('\t\tstate = active\n'), isFalse); // an endpoint, not the job
  });

  test('kickstart that brings the agent up is enough', () async {
    final l = launchd(kickstartFixes: true);
    expect(await restartAgent(l.run, '501', sleep: noWait), isTrue);
    expect(l.calls.where((c) => c.contains('bootout')), isEmpty);
    expect(l.calls.first, 'launchctl kickstart -k gui/501/$kAgentLabel');
  });

  test('a job stuck at spawn failed is booted out and bootstrapped again, then checked', () async {
    final l = launchd();
    expect(await restartAgent(l.run, '501', sleep: noWait), isTrue);
    final out = l.calls.indexOf('launchctl bootout gui/501/$kAgentLabel');
    final boot = l.calls.indexOf('launchctl bootstrap gui/501 $kAgentPlist');
    expect(out, greaterThan(0));
    expect(boot, greaterThan(out));
    expect(l.calls.last, 'launchctl print gui/501/$kAgentLabel');
  });

  test('still down after bootstrap: says so', () async {
    final l = launchd(bootstrapFixes: false);
    expect(await restartAgent(l.run, '501', sleep: noWait), isFalse);
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
