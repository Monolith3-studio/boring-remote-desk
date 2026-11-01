// v1.7 review: the Windows install screen in the kit, plain words, one Install button.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/install.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/kit_look.dart';

Widget host(Widget w) => MaterialApp(theme: kitLook(Kit.theme()), home: Scaffold(body: w));

InstallScreen screen({
  bool installing = false,
  bool canTry = true,
  VoidCallback? onInstall,
  ValueChanged<bool>? onStartMenu,
}) =>
    InstallScreen(
      path: TextEditingController(text: r'C:\Program Files\BoringRemote'),
      onChangePath: () {},
      startMenu: true,
      onStartMenu: onStartMenu ?? (_) {},
      desktopIcon: true,
      onDesktopIcon: (_) {},
      printer: false,
      onPrinter: (_) {},
      installing: installing,
      canTryWithoutInstalling: canTry,
      onInstall: onInstall ?? () {},
      onCancel: () {},
      onTryWithoutInstalling: () {},
      onLicence: () {},
    );

void wide(WidgetTester tester) {
  tester.view.physicalSize = const Size(900, 900);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
}

void main() {
  testWidgets('shows where it installs, the choices, and Install', (tester) async {
    wide(tester);
    var installs = 0;
    final starts = <bool>[];
    await tester.pumpWidget(host(screen(onInstall: () => installs++, onStartMenu: starts.add)));
    expect(find.text(InstallWords.title), findsOneWidget);
    expect(find.text(r'C:\Program Files\BoringRemote'), findsOneWidget);
    expect(find.text(InstallWords.tryIt), findsOneWidget);
    await tester.tap(find.text(InstallWords.startMenu));
    expect(starts, [false]);
    await tester.tap(find.byKey(InstallScreen.installKey));
    expect(installs, 1);
  });

  testWidgets('while installing every control is off and it says to click Yes', (tester) async {
    wide(tester);
    var installs = 0;
    await tester.pumpWidget(host(screen(installing: true, canTry: false, onInstall: () => installs++)));
    expect(find.text(InstallWords.installing), findsOneWidget);
    expect(find.text(InstallWords.tryIt), findsNothing);
    await tester.tap(find.byKey(InstallScreen.installKey));
    expect(installs, 0);
  });
}
