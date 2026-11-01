import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/simple_settings.dart';

Widget host(Widget w) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: w));

SimpleSettings settings({
  String macName = 'Edit Bay 2',
  Future<void> Function(String)? onRename,
  bool passwordSet = false,
  Future<bool> Function(String)? setPassword,
  bool startAtLogin = false,
  void Function(bool)? onStartAtLogin,
  bool checkUpdates = true,
  void Function(bool)? onCheckUpdates,
  List<SettingsLink> advanced = const [],
}) =>
    SimpleSettings(
      macName: macName,
      onRename: onRename ?? (_) async {},
      passwordSet: passwordSet,
      setPassword: setPassword ?? (_) async => true,
      startAtLogin: startAtLogin,
      onStartAtLogin: onStartAtLogin ?? (_) {},
      checkUpdates: checkUpdates,
      onCheckUpdates: onCheckUpdates ?? (_) {},
      advanced: advanced,
    );

void main() {
  testWidgets("shows this Mac's name and renames it", (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(settings(onRename: (n) async => got.add(n))));
    expect(find.text('Edit Bay 2'), findsOneWidget);
    await tester.enterText(find.byKey(SimpleSettings.nameKey), '  Stage Left ');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    expect(got, ['Stage Left']);
  });

  testWidgets('a blank name is not saved', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(settings(onRename: (n) async => got.add(n))));
    await tester.enterText(find.byKey(SimpleSettings.nameKey), '   ');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    expect(got, isEmpty);
  });

  testWidgets('Unattended Password: says whether one is set, never shows it', (tester) async {
    await tester.pumpWidget(host(settings(passwordSet: false)));
    expect(find.text('Not set. Someone has to approve each connection here.'), findsOneWidget);
    expect(find.text('Set password'), findsOneWidget);
    await tester.pumpWidget(host(settings(passwordSet: true)));
    expect(find.text('Set. Trusted people can get in with no one here.'), findsOneWidget);
    expect(find.text('Change password'), findsOneWidget);
  });

  Future<void> typePassword(WidgetTester tester, String pw) async {
    await tester.tap(find.text('Set password'));
    await tester.pump();
    await tester.enterText(find.byKey(SimpleSettings.passwordKey), pw);
    await tester.tap(find.text('Save password'));
    await tester.pump();
  }

  testWidgets('a blank or weak password is refused', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(settings(setPassword: (p) async {
      got.add(p);
      return true;
    })));
    await typePassword(tester, '');
    expect(find.text('At least 8 characters, with a capital, a small letter and a number.'),
        findsOneWidget);
    await tester.enterText(find.byKey(SimpleSettings.passwordKey), 'password');
    await tester.tap(find.text('Save password'));
    await tester.pump();
    expect(got, isEmpty);
  });

  testWidgets('a good password is saved, typed hidden', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(settings(setPassword: (p) async {
      got.add(p);
      return true;
    })));
    await tester.tap(find.text('Set password'));
    await tester.pump();
    final field = tester.widget<TextField>(find.byKey(SimpleSettings.passwordKey));
    expect(field.obscureText, isTrue);
    await tester.enterText(find.byKey(SimpleSettings.passwordKey), 'Stage4Left');
    await tester.tap(find.text('Save password'));
    await tester.pumpAndSettle();
    expect(got, ['Stage4Left']);
    expect(find.text('Stage4Left'), findsNothing);
  });

  testWidgets('a password the Mac rejects says so', (tester) async {
    await tester.pumpWidget(host(settings(setPassword: (_) async => false)));
    await typePassword(tester, 'Stage4Left');
    await tester.pumpAndSettle();
    expect(find.text("Couldn't save that password. Try again."), findsOneWidget);
  });

  testWidgets('start at login and updates are switches', (tester) async {
    final login = <bool>[], updates = <bool>[];
    await tester.pumpWidget(host(settings(
        startAtLogin: false, onStartAtLogin: login.add, checkUpdates: true, onCheckUpdates: updates.add)));
    await tester.tap(find.widgetWithText(SwitchListTile, 'Start at login'));
    await tester.tap(find.widgetWithText(SwitchListTile, 'Check for updates'));
    expect(login, [true]);
    expect(updates, [false]);
  });

  testWidgets('Advanced lists every entry the page passes', (tester) async {
    final opened = <String>[];
    tester.view.physicalSize = const Size(1200, 2400);
    addTearDown(tester.view.resetPhysicalSize);
    await tester.pumpWidget(host(settings(advanced: [
      SettingsLink(label: 'All settings', onTap: () => opened.add('all')),
      SettingsLink(label: 'Trusted Controllers', onTap: () => opened.add('trusted')),
    ])));
    expect(find.text('Advanced'), findsOneWidget);
    await tester.tap(find.text('Trusted Controllers'));
    await tester.tap(find.text('All settings'));
    expect(opened, ['trusted', 'all']);
  });
}
