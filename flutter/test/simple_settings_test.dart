import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/simple_settings.dart';

Widget host(Widget w) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: w));

SimpleSettings settings({
  String macName = 'Edit Bay 2',
  Future<void> Function(String)? onRename,
  bool passwordSet = false,
  Future<bool> Function(String)? setPassword,
  bool remoteAccess = false,
  void Function(bool)? onRemoteAccess,
  bool? openAtLogin,
  void Function(bool)? onOpenAtLogin,
  Widget? access,
  bool checkUpdates = true,
  void Function(bool)? onCheckUpdates,
  List<SettingsLink> advanced = const [],
  VoidCallback? onRunSetup,
  void Function(String)? openUrl,
}) =>
    SimpleSettings(
      macName: macName,
      onRename: onRename ?? (_) async {},
      passwordSet: passwordSet,
      setPassword: setPassword ?? (_) async => true,
      remoteAccess: remoteAccess,
      onRemoteAccess: onRemoteAccess ?? (_) {},
      openAtLogin: openAtLogin,
      onOpenAtLogin: onOpenAtLogin ?? (_) {},
      access: access,
      checkUpdates: checkUpdates,
      onCheckUpdates: onCheckUpdates ?? (_) {},
      advanced: advanced,
      onRunSetup: onRunSetup,
      openUrl: openUrl,
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
    expect(find.text('Password for when no one is here'), findsOneWidget);
    expect(find.text('Not set. Someone has to be at this Mac to click Allow each time.'), findsOneWidget);
    expect(find.text('Set password'), findsOneWidget);
    await tester.pumpWidget(host(settings(passwordSet: true)));
    expect(find.text('Set. Your other Macs can get in with it when no one is here.'), findsOneWidget);
    expect(find.text('Change password'), findsOneWidget);
    await tester.tap(find.text('Change password'));
    await tester.pump();
    expect(tester.widget<TextField>(find.byKey(SimpleSettings.passwordKey)).decoration?.hintText, 'Type a new password');
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

  testWidgets('remote access, open at login and updates are switches', (tester) async {
    final access = <bool>[], login = <bool>[], updates = <bool>[];
    await tester.pumpWidget(host(settings(
        remoteAccess: false, onRemoteAccess: access.add, openAtLogin: false, onOpenAtLogin: login.add,
        checkUpdates: true, onCheckUpdates: updates.add)));
    await tester.tap(find.widgetWithText(SwitchListTile, 'Let your other Macs in'));
    await tester.tap(find.widgetWithText(SwitchListTile, 'Open Boring Remote at login'));
    await tester.tap(find.widgetWithText(SwitchListTile, 'Check for updates'));
    expect(access, [true]);
    expect(login, [true]);
    expect(updates, [false]);
  });

  testWidgets('open at login on and off never touches remote access (t17)', (tester) async {
    final access = <bool>[], login = <bool>[];
    await tester.pumpWidget(host(settings(
        remoteAccess: true, onRemoteAccess: access.add, openAtLogin: true, onOpenAtLogin: login.add)));
    await tester.tap(find.widgetWithText(SwitchListTile, 'Open Boring Remote at login'));
    await tester.pump();
    expect(login, [false]);
    expect(access, isEmpty);
    expect(find.text('Turn off'), findsNothing);
  });

  testWidgets('no open-at-login row when the page passes none; the Access slot shows', (tester) async {
    await tester.pumpWidget(host(settings(access: const Text('ACCESS ROWS'))));
    expect(find.widgetWithText(SwitchListTile, 'Open Boring Remote at login'), findsNothing);
    expect(find.text('ACCESS ROWS'), findsOneWidget);
  });

  testWidgets('turning remote access off says what it stops first, and only then turns it off',
      (tester) async {
    final login = <bool>[];
    const why = "Turn this off and your other Macs can't get into this one, starting now. "
        'Turn it back on to let them in. Your Mac may ask you to confirm, and Boring Remote may restart.';
    await tester.pumpWidget(host(settings(remoteAccess: true, onRemoteAccess: login.add)));
    await tester.tap(find.widgetWithText(SwitchListTile, 'Let your other Macs in'));
    await tester.pump();
    expect(find.text(why), findsOneWidget);
    expect(login, isEmpty);
    await tester.tap(find.text('Keep it on'));
    await tester.pump();
    expect(find.text(why), findsNothing);
    expect(login, isEmpty);
    await tester.tap(find.widgetWithText(SwitchListTile, 'Let your other Macs in'));
    await tester.pump();
    await tester.tap(find.text('Turn off'));
    await tester.pump();
    expect(login, [false]);
    expect(find.text(why), findsNothing);
  });

  testWidgets('set up another Mac: download link, copy the link, three plain steps', (tester) async {
    tester.view.physicalSize = const Size(1200, 2400);
    addTearDown(tester.view.resetPhysicalSize);
    final opened = <String>[], copied = <String>[];
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') copied.add((call.arguments as Map)['text'] as String);
      return null;
    });
    addTearDown(() => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null));
    await tester.pumpWidget(host(settings(openUrl: opened.add)));
    expect(find.text('Set up another Mac'), findsOneWidget);
    expect(find.text('1. On the other Mac, open theboringremote.com/download and download Boring Remote.'),
        findsOneWidget);
    expect(find.text('2. Open it and follow the three setup steps.'), findsOneWidget);
    expect(find.text("3. You'll see it by name on this Mac's Home screen when both are on the same network."), findsOneWidget);
    await tester.ensureVisible(find.text('Download Boring Remote'));
    await tester.pump();
    await tester.tap(find.text('Download Boring Remote'));
    expect(opened, ['https://theboringremote.com/download']);
    await tester.ensureVisible(find.text('Copy the link'));
    await tester.pump();
    await tester.tap(find.text('Copy the link'));
    await tester.pump();
    expect(find.text('Link copied.'), findsOneWidget);
    expect(copied, ['https://theboringremote.com/download']);
  });

  testWidgets('Advanced lists every entry the page passes', (tester) async {
    final opened = <String>[];
    tester.view.physicalSize = const Size(1200, 4800);
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

  testWidgets('Setup can be opened again from Settings', (tester) async {
    var opened = 0;
    await tester.pumpWidget(host(settings(onRunSetup: () => opened++)));
    await tester.tap(find.text('Run Setup again'));
    expect(opened, 1);
    await tester.pumpWidget(host(settings()));
    expect(find.text('Run Setup again'), findsNothing);
  });
}
