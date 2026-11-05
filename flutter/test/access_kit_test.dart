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

  group('Switch is on but still not working? (t31)', () {
    test('runs tccutil for our three switches on our bundle only, with nothing else in the list', () async {
      final calls = <List<String>>[];
      final ok = await clearSwitches((exe, args) async {
        calls.add([exe, ...args]);
        return ProcessResult(0, 0, '', '');
      });
      expect(ok, isTrue);
      expect(calls, [
        ['/usr/bin/tccutil', 'reset', 'Accessibility', 'io.boringlabs.remote.agent'],
        ['/usr/bin/tccutil', 'reset', 'ScreenCapture', 'io.boringlabs.remote.agent'],
        ['/usr/bin/tccutil', 'reset', 'ListenEvent', 'io.boringlabs.remote.agent'],
      ]);
    });

    test('one failing still runs the others, and says it failed', () async {
      final calls = <String>[];
      final ok = await clearSwitches((exe, args) async {
        calls.add(args[1]);
        return ProcessResult(0, args[1] == 'ScreenCapture' ? 70 : 0, '', 'No such bundle identifier');
      });
      expect(ok, isFalse);
      expect(calls, ['Accessibility', 'ScreenCapture', 'ListenEvent']);
    });

    test('tccutil not running at all is a failure, not a crash', () async {
      expect(await clearSwitches((exe, args) async => throw const ProcessException('tccutil', [])), isFalse);
    });

    testWidgets('Access offers it with what it costs; hidden when not passed', (tester) async {
      await tester.pumpWidget(app(AccessSection(checks: checks(), pollEvery: const Duration(hours: 1))));
      await tester.pump();
      expect(find.text(AccessWords.stuckTitle), findsNothing);
      await tester.pumpWidget(app(AccessSection(
          key: UniqueKey(), checks: checks(), pollEvery: const Duration(hours: 1), clearSwitches: () async => true)));
      await tester.pump();
      expect(find.text('Switch is on but still not working?'), findsOneWidget, reason: 'all green can still be stuck');
      expect(find.textContaining("You'll need to turn them back on."), findsOneWidget);
    });

    testWidgets('clearing from Access reads the rows again and says so', (tester) async {
      await tester.pumpWidget(app(SingleChildScrollView(
        child: AccessSection(
            checks: checks(),
            pollEvery: const Duration(hours: 1),
            clearSwitches: () async {
              state['screen'] = false;
              return true;
            }),
      )));
      await tester.pump();
      await tester.tap(find.text(AccessWords.stuckButton));
      await tester.pump();
      await tester.pump();
      await tester.pump();
      expect(find.text(AccessWords.stuckDone), findsOneWidget);
      expect(find.text(AccessWords.notReady('Row screen')), findsOneWidget);
    });

    testWidgets('a failed clear says what to do', (tester) async {
      await tester.pumpWidget(app(SingleChildScrollView(
        child: AccessSection(
            checks: checks(), pollEvery: const Duration(hours: 1), clearSwitches: () async => false),
      )));
      await tester.pump();
      await tester.tap(find.text(AccessWords.stuckButton));
      await tester.pump();
      await tester.pump();
      expect(find.text(AccessWords.stuckFailed), findsOneWidget);
    });
  });

  group('what --server can do (t31)', () {
    const allOn = 'server=Y screen=Y control=Y input=Y sessions=0';

    test('reads the line --server and a new process print', () {
      final a = MacAccess.parse('server=Y screen=Y control=N input=Y sessions=2\n')!;
      expect((a.server, a.screen, a.control, a.input, a.sessions), (true, true, false, true, 2));
      expect(a.all, isFalse);
      expect(MacAccess.parse(allOn)!.all, isTrue);
      expect(MacAccess.parse('server=N screen=N control=N input=N sessions=0')!.server, isFalse);
    });

    test('no --server, or an older one that does not know the name, is no answer', () {
      expect(MacAccess.parse(''), isNull);
      expect(MacAccess.parse('Y'), isNull);
      expect(MacAccess.parse('screen=Y'), isNull);
    });

    /// A watch over a fake --server, fake new process and fake clock. [restarted] flips --server's answer.
    ({
      ServeWatch watch,
      List<String> log,
      void Function(String) setServer,
      void Function(String?) setFresh,
      void Function(Duration) tick,
      void Function(bool) setMay,
    }) rig({String? server = allOn, String? fresh, String? afterRestart, bool windowOn = false}) {
      final log = <String>[];
      var clock = DateTime(2026, 11, 5);
      var answer = server, newProcess = fresh, may = true;
      final w = ServeWatch(
        askServer: () async {
          log.add('server');
          return answer == null ? null : MacAccess.parse(answer!);
        },
        askFresh: () async {
          log.add('fresh');
          return newProcess == null ? null : MacAccess.parse(newProcess!);
        },
        askWindow: () {
          log.add('window');
          return MacAccess(screen: windowOn, control: windowOn, input: windowOn);
        },
        restart: () async {
          log.add('restart');
          if (afterRestart != null) answer = afterRestart;
          return true;
        },
        mayRestart: () => may,
        now: () => clock,
      );
      return (
        watch: w,
        log: log,
        setServer: (a) => answer = a,
        setFresh: (a) => newProcess = a,
        tick: (d) => clock = clock.add(d),
        setMay: (m) => may = m,
      );
    }

    const off = 'server=Y screen=N control=Y input=Y sessions=0';
    const freshOn = 'server=N screen=Y control=Y input=Y sessions=0';

    test('all on at --server: one IPC read, no new process, no restart', () async {
      final r = rig();
      expect(await r.watch.serves((a) => a.screen), isTrue);
      expect(r.log, ['server']);
    });

    test('a switch on that --server still reads as off restarts it, once, and Ready follows', () async {
      final r = rig(server: off, fresh: freshOn, afterRestart: allOn);
      expect(await r.watch.serves((a) => a.screen), isTrue);
      expect(r.log, ['server', 'fresh', 'restart', 'server']);
      r.log.clear();
      await r.watch.read();
      expect(r.log, ['server']);
    });

    test('still off at --server after restarts: not ready, and it stops trying', () async {
      final r = rig(server: off, fresh: freshOn);
      for (var i = 0; i < 8; i++) {
        expect(await r.watch.serves((a) => a.screen), isFalse);
        r.tick(const Duration(seconds: 30));
      }
      expect(r.log.where((c) => c == 'restart').length, 3);
    });

    test('restarts are spaced out', () async {
      final r = rig(server: off, fresh: freshOn);
      await r.watch.read();
      r.tick(const Duration(seconds: 5));
      await r.watch.read();
      expect(r.log.where((c) => c == 'restart').length, 1);
      r.tick(const Duration(seconds: 20));
      await r.watch.read();
      expect(r.log.where((c) => c == 'restart').length, 2);
    });

    test('never restarts during a session', () async {
      final r = rig(server: 'server=Y screen=N control=Y input=Y sessions=1', fresh: freshOn);
      await r.watch.read();
      expect(r.log, isNot(contains('restart')));
    });

    test('never restarts while remote access is off', () async {
      final r = rig(server: off, fresh: freshOn)..setMay(false);
      await r.watch.read();
      expect(r.log, isNot(contains('restart')));
    });

    test('a switch that really is off is no reason to restart', () async {
      final r = rig(server: off, fresh: 'server=N screen=N control=Y input=Y sessions=0');
      await r.watch.read();
      expect(r.log, ['server', 'fresh']);
    });

    test('in Setup, a new process is read at most every two seconds', () async {
      final r = rig(server: off, fresh: 'server=N screen=N control=Y input=Y sessions=0');
      await r.watch.switchesNow();
      r.tick(const Duration(seconds: 1));
      await r.watch.switchesNow();
      expect(r.log.where((c) => c == 'fresh').length, 1);
      r.tick(const Duration(seconds: 1));
      await r.watch.switchesNow();
      expect(r.log.where((c) => c == 'fresh').length, 2);
    });

    test('a Mac that leaves the switches off pays once a minute, and a Fix click speeds it back up', () async {
      final r = rig(server: off, fresh: 'server=N screen=N control=Y input=Y sessions=0');
      await r.watch.read();
      for (var i = 0; i < 11; i++) {
        r.tick(const Duration(seconds: 5));
        await r.watch.read();
      }
      expect(r.log.where((c) => c == 'fresh').length, 1);
      r.tick(const Duration(seconds: 5));
      await r.watch.read();
      expect(r.log.where((c) => c == 'fresh').length, 2);
      r.watch.forget();
      await r.watch.read();
      r.tick(const Duration(seconds: 3));
      await r.watch.read();
      expect(r.log.where((c) => c == 'fresh').length, 4);
    });

    test('the window standing in says nothing about --server: no restart, not answering', () async {
      final r = rig(server: 'server=N screen=N control=N input=N sessions=0', fresh: freshOn);
      expect(await r.watch.answering(), isFalse);
      expect(r.log, isNot(contains('restart')));
      expect(await r.watch.serves((a) => a.screen), isTrue, reason: 'the switch row shows the switch; the running row says --server is down');
    });

    test('no --server at all: not answering, the switches still read', () async {
      final r = rig(server: null, fresh: freshOn);
      expect(await r.watch.answering(), isFalse);
      expect((await r.watch.switchesNow())!.screen, isTrue);
      expect(r.log, isNot(contains('restart')));
    });

    test('a new process failing falls back on the window', () async {
      final r = rig(server: null, windowOn: true);
      expect((await r.watch.switchesNow())!.control, isTrue);
      expect(r.log, ['server', 'fresh', 'window']);
    });

    test('--server up with every switch on after being off clears the count', () async {
      final r = rig(server: off, fresh: freshOn);
      for (var i = 0; i < 4; i++) {
        await r.watch.read();
        r.tick(const Duration(seconds: 30));
      }
      r.setServer(allOn);
      await r.watch.read();
      r.setServer(off);
      r.log.clear();
      r.tick(const Duration(seconds: 30));
      await r.watch.read();
      expect(r.log, contains('restart'));
    });

    test('rows polled together share one read', () async {
      final r = rig();
      await Future.wait([r.watch.read(), r.watch.read(), r.watch.answering(), r.watch.serves((a) => a.input)]);
      expect(r.log, ['server']);
    });

    test('forget starts the count and the new-process wait over', () async {
      final r = rig(server: off, fresh: freshOn);
      for (var i = 0; i < 4; i++) {
        await r.watch.read();
        r.tick(const Duration(seconds: 30));
      }
      expect(r.log.where((c) => c == 'restart').length, 3);
      r.watch.forget();
      await r.watch.read();
      expect(r.log.where((c) => c == 'restart').length, 4);
    });
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
