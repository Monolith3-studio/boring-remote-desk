import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/access.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/setup.dart';

Widget host(Widget w) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: w));

/// Scrolls the button into view first, as a buyer would on a small window.
Future<void> tapText(WidgetTester tester, String text) async {
  await tester.ensureVisible(find.text(text));
  await tester.pump();
  await tester.tap(find.text(text));
}

SetupFlow flow({
  SetupPlatform platform = SetupPlatform.mac,
  Future<String>? computerName,
  Future<void> Function(String)? onName,
  bool Function()? canSeeScreen,
  bool Function()? canControl,
  void Function(String url)? openPane,
  Future<bool> Function()? canBeReached,
  Future<void> Function()? allowReach,
  bool passwordSet = false,
  Future<bool> Function(String)? setPassword,
  int startStep = 0,
  void Function(int)? onStep,
  VoidCallback? onDone,
  bool welcome = false,
  bool ready = false,
  bool Function()? canMonitorInput,
  List<AccessCheck> readyChecks = const [],
  Future<void> Function(String)? copyText,
  Future<MacAccess?> Function()? switchesNow,
  Future<bool> Function()? clearSwitches,
}) =>
    SetupFlow(
      platform: platform,
      computerName: computerName ?? Future.value("Sam's MacBook Pro"),
      onName: onName ?? (_) async {},
      canSeeScreen: canSeeScreen ?? () => false,
      canControl: canControl ?? () => false,
      openPane: openPane ?? (_) {},
      canBeReached: canBeReached ?? () async => false,
      allowReach: allowReach ?? () async {},
      passwordSet: passwordSet,
      setPassword: setPassword ?? (_) async => true,
      startStep: startStep,
      onStep: onStep ?? (_) {},
      onDone: onDone ?? () {},
      welcome: welcome,
      ready: ready,
      canMonitorInput: canMonitorInput,
      readyChecks: readyChecks,
      copyText: copyText ?? (_) async {},
      switchesNow: switchesNow,
      clearSwitches: clearSwitches,
    );

void main() {
  group('screen 1: name this Mac', () {
    testWidgets('prefills the computer name and saves it', (tester) async {
      final got = <String>[];
      await tester.pumpWidget(host(flow(onName: (n) async => got.add(n))));
      await tester.pump();
      expect(find.text(setupCopy['name.title']!), findsOneWidget);
      expect(find.text('Step 1 of 3'), findsOneWidget);
      expect(find.text("Sam's MacBook Pro"), findsOneWidget);
      await tester.enterText(find.byKey(SetupFlow.nameKey), '  Edit Bay 2 ');
      await tapText(tester, setupCopy['next']!);
      await tester.pumpAndSettle();
      expect(got, ['Edit Bay 2']);
      expect(find.text(setupCopy['allow.title']!), findsOneWidget);
    });

    testWidgets('a blank name is refused with one thing to do', (tester) async {
      final got = <String>[];
      await tester.pumpWidget(host(flow(onName: (n) async => got.add(n))));
      await tester.pump();
      await tester.enterText(find.byKey(SetupFlow.nameKey), '   ');
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
      expect(got, isEmpty);
      expect(find.text(setupCopy['name.blank']!), findsOneWidget);
      expect(find.text(setupCopy['name.title']!), findsOneWidget);
    });

    testWidgets('typing before the computer name arrives keeps what was typed', (tester) async {
      final name = Completer<String>();
      await tester.pumpWidget(host(flow(computerName: name.future)));
      await tester.enterText(find.byKey(SetupFlow.nameKey), 'Stage Left');
      name.complete('Studio Mac');
      await tester.pump();
      expect(find.text('Stage Left'), findsOneWidget);
    });
  });

  group('screen 2: one switch at a time', () {
    const after = Duration(milliseconds: 1200); // SetupFlow.moveOnAfter

    /// Three switches, each turned on by the test.
    SetupFlow three(Map<String, bool> on, {List<String>? opened, Future<bool> Function()? clear}) => flow(
        startStep: 1,
        openPane: opened?.add,
        canSeeScreen: () => on['screen']!,
        canControl: () => on['control']!,
        canMonitorInput: () => on['input']!,
        clearSwitches: clear);

    testWidgets('shows only the first missing switch, with where it sits among the three', (tester) async {
      await tester.pumpWidget(host(three({'screen': false, 'control': false, 'input': false})));
      expect(find.text('Step 2 of 3'), findsOneWidget);
      expect(find.text('Switch 1 of 3'), findsOneWidget);
      expect(find.text(setupCopy['allow.screen']!), findsOneWidget);
      expect(find.text(setupCopy['allow.screen.button']!), findsOneWidget);
      expect(find.text(setupCopy['allow.control.button']!), findsNothing);
      expect(find.text(setupCopy['allow.input.button']!), findsNothing);
      for (final name in [AccessWords.screen, AccessWords.control, AccessWords.input]) {
        expect(find.text(name), findsOneWidget);
      }
    });

    testWidgets('the button opens the exact pane for that switch', (tester) async {
      final opened = <String>[];
      final on = {'screen': false, 'control': false, 'input': false};
      await tester.pumpWidget(host(three(on, opened: opened)));
      await tapText(tester, setupCopy['allow.screen.button']!);
      await tester.pump();
      expect(opened, ['x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture']);
      expect(find.text(setupCopy['allow.waiting']!), findsOneWidget);
      on['screen'] = true;
      await tester.pump(const Duration(seconds: 1));
      await tapText(tester, setupCopy['allow.control.button']!);
      on['control'] = true;
      await tester.pump(const Duration(seconds: 1));
      await tapText(tester, setupCopy['allow.input.button']!);
      expect(opened.skip(1), [
        'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility',
        'x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent',
      ]);
    });

    testWidgets('moves on by itself and never opens a pane on its own', (tester) async {
      final opened = <String>[];
      final steps = <int>[];
      final on = {'screen': false, 'control': false, 'input': false};
      await tester.pumpWidget(host(SetupFlow(
          computerName: Future.value('x'),
          onName: (_) async {},
          startStep: 1,
          canSeeScreen: () => on['screen']!,
          canControl: () => on['control']!,
          canMonitorInput: () => on['input']!,
          openPane: opened.add,
          canBeReached: () async => false,
          allowReach: () async {},
          passwordSet: false,
          setPassword: (_) async => true,
          onStep: steps.add,
          onDone: () {},
          welcome: false,
          ready: false)));

      on['screen'] = true;
      await tester.pump(const Duration(seconds: 1));
      expect(find.text('Switch 2 of 3'), findsOneWidget);
      expect(find.text(setupCopy['allow.control']!), findsOneWidget);
      expect(find.text(setupCopy['allow.screen.button']!), findsNothing);

      on['control'] = true;
      await tester.pump(const Duration(seconds: 1));
      expect(find.text('Switch 3 of 3'), findsOneWidget);
      expect(find.text(setupCopy['allow.input']!), findsOneWidget);

      on['input'] = true;
      await tester.pump(const Duration(seconds: 1));
      expect(find.text(setupCopy['allow.all']!), findsOneWidget, reason: 'the last check stays up a moment');
      expect(steps, isEmpty);
      await tester.pump(after);
      expect(find.text(setupCopy['password.title']!), findsOneWidget);
      expect(steps, [2]);
      expect(opened, isEmpty, reason: 'moving on must not take over System Settings while someone is in it');
    });

    testWidgets('opened with everything on: says so and waits for Continue', (tester) async {
      await tester.pumpWidget(host(three({'screen': true, 'control': true, 'input': true})));
      expect(find.text(setupCopy['allow.all']!), findsOneWidget);
      await tester.pump(const Duration(seconds: 5));
      expect(find.text(setupCopy['allow.title']!), findsOneWidget);
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
      expect(find.text(setupCopy['password.title']!), findsOneWidget);
    });

    testWidgets('a switch going back off before Setup moves on keeps it here', (tester) async {
      final on = {'screen': true, 'control': true, 'input': false};
      await tester.pumpWidget(host(three(on)));
      on['input'] = true;
      await tester.pump(const Duration(seconds: 1));
      on['input'] = false;
      await tester.pump(const Duration(seconds: 1));
      await tester.pump(after);
      expect(find.text(setupCopy['allow.input']!), findsOneWidget);
    });

    testWidgets('Quit & Reopen is only mentioned for the switches where macOS asks it', (tester) async {
      final on = {'screen': false, 'control': false, 'input': false};
      await tester.pumpWidget(host(three(on)));
      expect(find.text(setupCopy['allow.quit']!), findsOneWidget);
      on['screen'] = true;
      await tester.pump(const Duration(seconds: 1));
      expect(find.text(setupCopy['allow.quit']!), findsNothing);
      on['control'] = true;
      await tester.pump(const Duration(seconds: 1));
      expect(find.text(setupCopy['allow.quit']!), findsOneWidget);
    });

    testWidgets('the window not noticing Screen Recording does not hold Setup up', (tester) async {
      // macOS can keep a running process's answer until it restarts: the window still reads off.
      var fresh = const MacAccess(screen: false, control: false, input: false);
      await tester.pumpWidget(host(flow(
          startStep: 1,
          canSeeScreen: () => false,
          canControl: () => false,
          canMonitorInput: () => false,
          switchesNow: () async => fresh)));
      expect(find.text(setupCopy['allow.screen']!), findsOneWidget);
      fresh = const MacAccess(screen: true, control: false, input: false);
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(find.text(setupCopy['allow.control']!), findsOneWidget);
      fresh = const MacAccess(screen: true, control: true, input: true);
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      await tester.pump(after);
      expect(find.text(setupCopy['password.title']!), findsOneWidget);
    });

    testWidgets('no answer from the new read falls back on the window', (tester) async {
      await tester.pumpWidget(host(flow(
          startStep: 1,
          canSeeScreen: () => true,
          canControl: () => false,
          switchesNow: () async => null)));
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(find.text(setupCopy['allow.control']!), findsOneWidget);
    });

    testWidgets('skipping says what it costs before it skips', (tester) async {
      await tester.pumpWidget(host(flow(startStep: 1)));
      expect(find.text(setupCopy['allow.skip.why']!), findsNothing);
      await tapText(tester, setupCopy['skip']!);
      await tester.pump();
      expect(find.text(setupCopy['allow.skip.why']!), findsOneWidget);
      expect(find.text(setupCopy['password.title']!), findsNothing);
      await tapText(tester, setupCopy['skip.confirm']!);
      await tester.pump();
      expect(find.text(setupCopy['password.title']!), findsOneWidget);
    });

    testWidgets('stops polling once it leaves the screen', (tester) async {
      var reads = 0;
      await tester.pumpWidget(host(flow(startStep: 1, canSeeScreen: () {
        reads++;
        return true;
      }, canControl: () => true)));
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
      final after = reads;
      await tester.pump(const Duration(seconds: 5));
      expect(reads, after);
    });

    group('Switch is on but still not working?', () {
      testWidgets('hidden without a way to clear, offered with one button and what it costs', (tester) async {
        await tester.pumpWidget(host(flow(startStep: 1)));
        expect(find.text(AccessWords.stuckTitle), findsNothing);
        await tester.pumpWidget(host(flow(startStep: 1, clearSwitches: () async => true)));
        expect(find.text('Switch is on but still not working?'), findsOneWidget);
        expect(find.textContaining("You'll need to turn them back on."), findsOneWidget);
        expect(find.text(AccessWords.stuckButton), findsOneWidget);
      });

      testWidgets('clearing goes back to the first switch and says they are off', (tester) async {
        final on = {'screen': true, 'control': false, 'input': false};
        var cleared = 0;
        await tester.pumpWidget(host(three(on, clear: () async {
          cleared++;
          on.updateAll((_, __) => false);
          return true;
        })));
        expect(find.text(setupCopy['allow.control']!), findsOneWidget);
        await tapText(tester, AccessWords.stuckButton);
        await tester.pump();
        await tester.pump();
        expect(cleared, 1);
        expect(find.text(setupCopy['allow.screen']!), findsOneWidget);
        expect(find.text('Switch 1 of 3'), findsOneWidget);
        expect(find.text(AccessWords.stuckDone), findsOneWidget);
        expect(find.text(setupCopy['allow.waiting']!), findsOneWidget, reason: 'the clear already opened the pane');
      });

      testWidgets('offered with everything on too, and clearing from there goes back to the first switch', (tester) async {
        final on = {'screen': true, 'control': true, 'input': true};
        await tester.pumpWidget(host(three(on, clear: () async {
          on.updateAll((_, __) => false);
          return true;
        })));
        expect(find.text(setupCopy['allow.all']!), findsOneWidget);
        await tapText(tester, AccessWords.stuckButton);
        await tester.pump();
        await tester.pump();
        expect(find.text(setupCopy['allow.screen']!), findsOneWidget);
        expect(find.text(AccessWords.stuckDone), findsOneWidget, reason: 'the word stays after the card changes');
      });

      testWidgets('a clear that failed says what to do and leaves the switch where it was', (tester) async {
        final on = {'screen': true, 'control': false, 'input': false};
        await tester.pumpWidget(host(three(on, clear: () async => false)));
        await tapText(tester, AccessWords.stuckButton);
        await tester.pump();
        await tester.pump();
        expect(find.text(AccessWords.stuckFailed), findsOneWidget);
        expect(find.text(setupCopy['allow.control']!), findsOneWidget);
      });

      testWidgets('a clear that throws reads as failed', (tester) async {
        await tester.pumpWidget(host(flow(startStep: 1, clearSwitches: () async => throw 'no')));
        await tapText(tester, AccessWords.stuckButton);
        await tester.pump();
        await tester.pump();
        expect(find.text(AccessWords.stuckFailed), findsOneWidget);
      });
    });
  });

  group('screen 3: Unattended Password', () {
    testWidgets('a blank or weak password is refused, a strong one saved', (tester) async {
      final got = <String>[];
      var done = 0;
      await tester.pumpWidget(host(flow(
          startStep: 2,
          setPassword: (p) async {
            got.add(p);
            return true;
          },
          onDone: () => done++)));
      expect(find.text('Step 3 of 3'), findsOneWidget);
      for (final weak in ['', 'password']) {
        await tester.enterText(find.byKey(SetupFlow.passwordKey), weak);
        await tapText(tester, setupCopy['password.save']!);
        await tester.pump();
      }
      expect(got, isEmpty);
      await tester.enterText(find.byKey(SetupFlow.passwordKey), 'Edit2bay9');
      await tapText(tester, setupCopy['password.save']!);
      await tester.pump();
      expect(got, ['Edit2bay9']);
      expect(find.text(setupCopy['password.saved']!), findsOneWidget);
      expect(find.text('Edit2bay9'), findsNothing);
      await tapText(tester, setupCopy['done']!);
      expect(done, 1);
    });

    testWidgets('a failed save says to try again and does not finish', (tester) async {
      await tester.pumpWidget(host(flow(startStep: 2, setPassword: (_) async => false)));
      await tester.enterText(find.byKey(SetupFlow.passwordKey), 'Edit2bay9');
      await tapText(tester, setupCopy['password.save']!);
      await tester.pump();
      expect(find.text(setupCopy['password.failed']!), findsOneWidget);
      expect(find.text(setupCopy['done']!), findsNothing);
    });

    testWidgets('skipping says what it costs, then finishes', (tester) async {
      var done = 0;
      await tester.pumpWidget(host(flow(startStep: 2, onDone: () => done++)));
      await tapText(tester, setupCopy['skip']!);
      await tester.pump();
      expect(find.text(setupCopy['password.skip.why']!), findsOneWidget);
      expect(done, 0);
      await tapText(tester, setupCopy['skip.confirm']!);
      expect(done, 1);
    });

    testWidgets('opened again with a password set: Finish needs nothing typed', (tester) async {
      var done = 0;
      await tester.pumpWidget(host(flow(startStep: 2, passwordSet: true, onDone: () => done++)));
      expect(find.text(setupCopy['password.already']!), findsOneWidget);
      await tapText(tester, setupCopy['done']!);
      expect(done, 1);
    });
  });

  group('the flow', () {
    testWidgets('reports each screen so a Quit & Reopen comes back to it', (tester) async {
      final steps = <int>[];
      await tester.pumpWidget(host(flow(onStep: steps.add, canSeeScreen: () => true, canControl: () => true)));
      await tester.pump();
      await tapText(tester, setupCopy['next']!);
      await tester.pumpAndSettle();
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
      expect(steps, [1, 2]);
    });

  });

  // v1.7 ticket 12: Windows asks to let other computers reach it in place of the Mac step.
  group('screen 2 on Windows: let other computers reach this one', () {
    Future<void> toReach(WidgetTester tester, SetupFlow f) async {
      await tester.pumpWidget(host(f));
      await tester.pump();
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
    }

    testWidgets('three screens, the middle one is reach, not the Mac step', (tester) async {
      await tester.pumpWidget(host(flow(platform: SetupPlatform.windows, computerName: Future.value('FRONT-DESK'))));
      await tester.pump();
      expect(find.text('Step 1 of 3'), findsOneWidget);
      expect(find.text('Name this computer'), findsOneWidget);
      expect(find.text('Your other computers will list it by this name.'), findsOneWidget);
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
      expect(find.text(setupCopy['reach.title']!), findsOneWidget);
      expect(find.text(setupCopy['allow.title']!), findsNothing);
      expect(find.text('Step 2 of 3'), findsOneWidget);
    });

    testWidgets('already allowed (the installer did it) shows green and Continue works', (tester) async {
      await toReach(tester, flow(platform: SetupPlatform.windows, canBeReached: () async => true));
      await tester.pump();
      expect(find.text(setupCopy['allow.on']!), findsOneWidget);
      expect(find.text(setupCopy['reach.button']!), findsNothing);
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
      expect(find.text(setupCopy['password.title']!), findsOneWidget);
    });

    testWidgets('Allow asks Windows once, then turns green when the rule is there', (tester) async {
      var allowed = false, asked = 0;
      await toReach(
          tester,
          flow(
              platform: SetupPlatform.windows,
              canBeReached: () async => allowed,
              allowReach: () async {
                asked++;
                allowed = true;
              }));
      await tester.pump();
      final next = tester.widget<FilledButton>(find.widgetWithText(FilledButton, setupCopy['next']!));
      expect(next.onPressed, isNull);
      await tapText(tester, setupCopy['reach.button']!);
      await tester.pumpAndSettle();
      expect(asked, 1);
      expect(find.text(setupCopy['allow.on']!), findsOneWidget);
      expect(find.text(setupCopy['reach.failed']!), findsNothing);
    });

    testWidgets('a No at the Windows prompt says the one thing to do next', (tester) async {
      await toReach(tester, flow(platform: SetupPlatform.windows));
      await tester.pump();
      await tapText(tester, setupCopy['reach.button']!);
      await tester.pumpAndSettle();
      expect(find.text(setupCopy['reach.failed']!), findsOneWidget);
      expect(find.text(setupCopy['reach.button']!), findsOneWidget);
    });

    testWidgets('turns green live if it gets allowed some other way', (tester) async {
      var allowed = false;
      await toReach(tester,
          flow(platform: SetupPlatform.windows, canBeReached: () async => allowed));
      await tester.pump();
      expect(find.text(setupCopy['allow.on']!), findsNothing);
      allowed = true;
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(find.text(setupCopy['allow.on']!), findsOneWidget);
      await tapText(tester, setupCopy['next']!); // leave the screen so the poll stops
      await tester.pump();
    });

    testWidgets('skipping says what it costs before it skips', (tester) async {
      await toReach(tester, flow(platform: SetupPlatform.windows));
      await tester.pump();
      await tapText(tester, setupCopy['skip']!);
      await tester.pump();
      expect(find.text(setupCopy['reach.skip.why']!), findsOneWidget);
      await tapText(tester, setupCopy['skip.confirm']!);
      await tester.pump();
      expect(find.text(setupCopy['password.title']!), findsOneWidget);
      expect(find.text('Your other computers can get in with this password when no one is at this one.'),
          findsOneWidget);
    });

    test('the rule commands: read without admin, add asks Windows once, path quoted', () {
      expect(windowsRuleShowArgs(),
          ['advfirewall', 'firewall', 'show', 'rule', 'name=Boring Remote Service', 'dir=in', 'verbose']);
      final add = windowsRuleAddArgs(r"C:\Program Files\BoringRemote\BoringRemote.exe");
      expect(add.take(2), ['-NoProfile', '-Command']);
      expect(add.last,
          "Start-Process -FilePath netsh -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList "
          "'advfirewall firewall add rule name=\"Boring Remote Service\" dir=in action=allow "
          "program=\"C:\\Program Files\\BoringRemote\\BoringRemote.exe\" enable=yes profile=any'");
      expect(windowsRuleAddArgs(r"C:\it's\BoringRemote.exe").last, contains(r"C:\it''s\BoringRemote.exe"));
    });

    test('the reach check counts the rule only when it is for this copy of Boring Remote', () {
      // `netsh advfirewall firewall show rule name="Boring Remote Service" dir=in verbose`, trimmed.
      const installed = 'Rule Name:                            Boring Remote Service\r\n'
          '----------------------------------------------------------------------\r\n'
          'Enabled:                              Yes\r\n'
          'Direction:                            In\r\n'
          r'Program:                              C:\Program Files\BoringRemote\BoringRemote.exe' '\r\n'
          'Action:                               Allow\r\n'
          'Ok.\r\n';
      expect(windowsRuleAllowsExe(installed, r'c:\program files\boringremote\BoringRemote.EXE'), isTrue);
      expect(windowsRuleAllowsExe(installed, r'D:\Portable\BoringRemote.exe'), isFalse); // a copy elsewhere
      expect(windowsRuleAllowsExe('No rules match the specified criteria.', r'C:\x\BoringRemote.exe'), isFalse);
      // Windows in another language names the line differently; the path is what counts.
      expect(windowsRuleAllowsExe(r'Programm:   D:\Portable\BoringRemote.exe', r'D:\Portable\BoringRemote.exe'),
          isTrue);
    });

    test("screen 1 starts from Windows' own computer name, in the case it was typed", () {
      expect(windowsComputerName({'COMPUTERNAME': 'FRONT-DESK'}, 'Front-Desk'), 'Front-Desk');
      expect(windowsComputerName({'COMPUTERNAME': 'FRONT-DESK'}, 'something-else'), 'FRONT-DESK');
      expect(windowsComputerName({}, 'Front-Desk'), 'Front-Desk');
    });
  });

  group('first launch only', () {
    test('Setup shows until it has been finished once', () {
      expect(setupNeeded(''), isTrue);
      expect(setupNeeded('Y'), isFalse);
    });

    test('opens on the saved screen, else the first', () {
      expect(setupStartStep('', 3), 0);
      expect(setupStartStep('1', 3), 1);
      expect(setupStartStep('2', 3), 2);
      expect(setupStartStep('3', 3), 0);
      expect(setupStartStep('-1', 3), 0);
      expect(setupStartStep('x', 3), 0);
    });
  });

  testWidgets('screen 3 asks for a password in plain words', (tester) async {
    await tester.pumpWidget(host(flow(startStep: 2)));
    expect(tester.widget<TextField>(find.byKey(SetupFlow.passwordKey)).decoration?.hintText, 'Type a password');
  });

  test('no jargon in what the buyer reads', () {
    final banned = RegExp(r'\b(permission|permissions|accessibility api|port|firewall|ip|codec|tcc|daemon|id)\b',
        caseSensitive: false);
    // "Accessibility" alone is allowed: it is the macOS label the buyer must click.
    final hits = setupCopy.values.where(banned.hasMatch).toList();
    expect(hits, isEmpty);
  });

  test('t31 words: plain, no em dash, no jargon, and they say the switches come back off', () {
    const stuck = [
      AccessWords.stuckTitle,
      AccessWords.stuckBody,
      AccessWords.stuckButton,
      AccessWords.stuckDone,
      AccessWords.stuckFailed,
    ];
    final jargon = RegExp(r'\b(permission|permissions|tcc|tccutil|reset|grant|signature|daemon|agent|server)\b', caseSensitive: false);
    expect(stuck.where(jargon.hasMatch), isEmpty);
    expect([...stuck, ...setupCopy.values].where((w) => w.contains('\u2014') || w.contains('\u2013')), isEmpty);
    expect(AccessWords.stuckTitle, 'Switch is on but still not working?');
    expect(AccessWords.stuckBody, contains("You'll need to turn them back on."));
  });

  // v1.7 ticket 21: opened app to Ready, then the other computer.
  group('first run: welcome, then Ready and the other computer', () {
    testWidgets('a welcome comes first and is not a numbered step', (tester) async {
      await tester.pumpWidget(host(flow(welcome: true)));
      await tester.pump();
      expect(find.text(setupCopy['welcome.title']!), findsOneWidget);
      expect(find.textContaining('Step '), findsNothing);
      await tapText(tester, setupCopy['welcome.start']!);
      await tester.pump();
      expect(find.text(setupCopy['name.title']!), findsOneWidget);
      expect(find.text('Step 1 of 3'), findsOneWidget);
    });

    testWidgets('no welcome when Setup comes back to a later screen', (tester) async {
      await tester.pumpWidget(host(flow(welcome: true, startStep: 2)));
      expect(find.text(setupCopy['welcome.title']!), findsNothing);
      expect(find.text(setupCopy['password.title']!), findsOneWidget);
    });

    testWidgets('after the last step: Ready, the name it shows up as, and the download link', (tester) async {
      var done = 0;
      final copied = <String>[];
      await tester.pumpWidget(host(flow(
          ready: true, passwordSet: true, onDone: () => done++, copyText: (t) async => copied.add(t),
          canSeeScreen: () => true, canControl: () => true)));
      await tester.pump();
      await tester.enterText(find.byKey(SetupFlow.nameKey), 'Tori Laptop');
      await tapText(tester, setupCopy['next']!);
      await tester.pumpAndSettle();
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
      await tapText(tester, setupCopy['done']!);
      await tester.pump();
      expect(done, 0, reason: 'Finish on the password screen leads to Ready, not straight out');
      expect(find.text(setupCopy['ready.title']!), findsOneWidget);
      expect(find.text(setupCopy['ready.ok']!), findsOneWidget);
      expect(find.text('On your other computer, open Boring Remote. This one shows up as “Tori Laptop”.'),
          findsOneWidget);
      await tapText(tester, setupCopy['ready.copy']!);
      await tester.pump();
      expect(copied, [kSetupDownloadUrl]);
      expect(find.text(setupCopy['ready.copied']!), findsOneWidget);
      await tapText(tester, setupCopy['ready.done']!);
      expect(done, 1);
    });

    testWidgets('Ready is the same green line as Settings, or what is missing and its Fix', (tester) async {
      var granted = false;
      final checks = [
        AccessCheck(label: 'Screen Recording', why: '', read: () async => granted, fix: () async => granted = true),
      ];
      await tester.pumpWidget(host(flow(ready: true, passwordSet: true, startStep: 2, readyChecks: checks)));
      await tapText(tester, setupCopy['done']!);
      await tester.pump();
      await tester.pump();
      expect(find.text(AccessWords.notReady('Screen Recording')), findsOneWidget);
      await tester.tap(find.text(AccessWords.fix));
      await tester.pump();
      await tester.pump();
      expect(find.text(AccessWords.ready), findsOneWidget);
    });

    testWidgets('Ready offers the way out only while something is missing', (tester) async {
      var granted = false;
      final checks = [AccessCheck(label: 'Screen Recording', why: '', read: () async => granted, fix: () async {})];
      await tester.pumpWidget(host(flow(
          ready: true, passwordSet: true, startStep: 2, readyChecks: checks, clearSwitches: () async => true)));
      await tapText(tester, setupCopy['done']!);
      await tester.pump();
      await tester.pump();
      expect(find.text(AccessWords.stuckTitle), findsOneWidget);
      granted = true;
      await tester.pump(const Duration(seconds: 2));
      await tester.pump();
      expect(find.text(AccessWords.stuckTitle), findsNothing);
      expect(find.text(AccessWords.ready), findsOneWidget);
    });

    test('the download link is the one place the other computer gets the app', () {
      expect(kSetupDownloadUrl, 'https://boringlabs.online/remote');
    });
  });
}
