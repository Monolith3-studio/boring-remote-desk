// v1.7 review: the connection window (the Mac being controlled) in the kit.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/connection_window.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/kit_look.dart';

Widget host(Widget w) => MaterialApp(theme: kitLook(Kit.theme()), home: Scaffold(body: w));

void main() {
  tearDown(KitWords.mac);

  testWidgets('the card says who is in and for how long, never an ID', (tester) async {
    var chats = 0;
    await tester.pumpWidget(host(ConnectedHeader(
      name: 'Edit Bay 2',
      kind: ConnectedKind.control,
      allowed: true,
      ended: false,
      connectedFor: const Duration(minutes: 3, seconds: 7),
      onChat: () => chats++,
    )));
    expect(find.text('Edit Bay 2'), findsOneWidget);
    expect(find.text('Controlling this Mac'), findsOneWidget);
    expect(find.text('Connected · 3:07'), findsOneWidget);
    expect(find.textContaining(RegExp(r'\d{6,}')), findsNothing);
    await tester.tap(find.byTooltip('Messages'));
    expect(chats, 1);
  });

  testWidgets('before Allow it says it is asking, with no chat button', (tester) async {
    await tester.pumpWidget(host(const ConnectedHeader(
        name: '', kind: ConnectedKind.files, allowed: false, ended: false)));
    expect(find.text('A Mac on this network'), findsOneWidget);
    expect(find.text('Asking to come in'), findsOneWidget);
    expect(find.byType(IconButton), findsNothing);
  });

  testWidgets('permission switches report the change, in plain words', (tester) async {
    final changes = <String>[];
    await tester.pumpWidget(host(PermissionSwitches(
      values: const {'keyboard': true, 'audio': false, 'unknown': true},
      canChange: true,
      onChanged: (name, on) => changes.add('$name=$on'),
    )));
    expect(find.text('Use the mouse and keyboard'), findsOneWidget);
    expect(find.text("Hear this Mac's sound"), findsOneWidget);
    expect(find.byType(Switch), findsNWidgets(2)); // unknown names are skipped
    await tester.tap(find.byType(Switch).first);
    expect(changes, ['keyboard=false']);
  });

  testWidgets('switches are fixed when this Mac does not allow changes', (tester) async {
    final changes = <String>[];
    await tester.pumpWidget(host(PermissionSwitches(
      values: const {'keyboard': true},
      canChange: false,
      onChanged: (name, on) => changes.add(name),
    )));
    await tester.tap(find.byType(Switch));
    expect(changes, isEmpty);
  });

  testWidgets('buttons tap; Disconnect is the primary one', (tester) async {
    var taps = 0;
    await tester.pumpWidget(host(Column(children: [
      CmButton(label: 'Disconnect', primary: CmButton.primaryKeys.contains('Disconnect'), onTap: () => taps++),
    ])));
    await tester.tap(find.text('Disconnect'));
    expect(taps, 1);
    expect(CmButton.primaryKeys.contains('Elevate'), isFalse);
  });

  test('on Windows the card says computer', () {
    KitWords.windows();
    expect(ConnectedWords.doing(ConnectedKind.control), 'Controlling this computer');
    expect(ConnectedWords.permissions['restart'], 'Restart this computer');
  });
}
