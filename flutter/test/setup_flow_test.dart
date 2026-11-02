import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
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
}) =>
    SetupFlow(
      platform: platform,
      computerName: computerName ?? Future.value("Jason's MacBook Pro"),
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
    );

void main() {
  group('screen 1: name this Mac', () {
    testWidgets('prefills the computer name and saves it', (tester) async {
      final got = <String>[];
      await tester.pumpWidget(host(flow(onName: (n) async => got.add(n))));
      await tester.pump();
      expect(find.text(setupCopy['name.title']!), findsOneWidget);
      expect(find.text('Step 1 of 3'), findsOneWidget);
      expect(find.text("Jason's MacBook Pro"), findsOneWidget);
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

  group('screen 2: see and control this Mac', () {
    testWidgets('buttons open the exact System Settings panes', (tester) async {
      final opened = <String>[];
      await tester.pumpWidget(host(flow(startStep: 1, openPane: opened.add)));
      expect(find.text('Step 2 of 3'), findsOneWidget);
      await tapText(tester, setupCopy['allow.screen.button']!);
      await tapText(tester, setupCopy['allow.control.button']!);
      expect(opened, [
        'x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture',
        'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility',
      ]);
    });

    testWidgets('checks turn green live as each switch is turned on', (tester) async {
      var screen = false, control = false;
      await tester.pumpWidget(host(flow(startStep: 1, canSeeScreen: () => screen, canControl: () => control)));
      expect(find.byIcon(Icons.check_circle), findsNothing);
      FilledButton next() => tester.widget<FilledButton>(find.widgetWithText(FilledButton, setupCopy['next']!));
      expect(next().onPressed, isNull);

      screen = true;
      await tester.pump(const Duration(seconds: 1));
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
      expect(find.text(setupCopy['allow.screen.button']!), findsNothing);
      expect(next().onPressed, isNull);

      control = true;
      await tester.pump(const Duration(seconds: 1));
      expect(find.byIcon(Icons.check_circle), findsNWidgets(2));
      expect(next().onPressed, isNotNull);
      await tapText(tester, setupCopy['next']!);
      await tester.pump();
      expect(find.text(setupCopy['password.title']!), findsOneWidget);
    });

    testWidgets('already allowed shows green straight away', (tester) async {
      await tester.pumpWidget(host(flow(startStep: 1, canSeeScreen: () => true, canControl: () => true)));
      expect(find.byIcon(Icons.check_circle), findsNWidgets(2));
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
      await tester.pump();
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
}
