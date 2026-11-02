// v1.7 ticket 12: on Windows the kit says "computer" where the Mac build says "Mac".
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/file_transfer.dart';
import 'package:flutter_hbb/desktop/kit/lan_macs.dart';
import 'package:flutter_hbb/desktop/kit/mac_home.dart';
import 'package:flutter_hbb/desktop/kit/simple_settings.dart';
import 'package:flutter_hbb/desktop/kit/trust.dart';

Widget host(Widget w) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: w));

/// Every Text on screen, so a test can say no "Mac" is left anywhere.
List<String> texts(WidgetTester tester) => [
      for (final w in tester.widgetList<Text>(find.byType(Text))) w.data ?? '',
      for (final w in tester.widgetList<TextField>(find.byType(TextField))) w.decoration?.hintText ?? '',
    ];

void main() {
  tearDown(KitWords.mac);

  test('Mac is the default, Windows says computer', () {
    expect((KitWords.one, KitWords.many), ('Mac', 'Macs'));
    KitWords.windows();
    expect((KitWords.one, KitWords.many), ('computer', 'computers'));
    expect(KitWords.cap(KitWords.many), 'Computers');
    KitWords.mac();
    expect(KitWords.cap(KitWords.one), 'Mac');
  });

  testWidgets('Windows Home says computer, never Mac', (tester) async {
    KitWords.windows();
    await tester.pumpWidget(host(MacHome(macs: const [], tailscaleAddress: () async => null, onConnect: (_) {})));
    expect(find.text('Connect to a computer'), findsOneWidget);
    expect(find.text('Computers'), findsOneWidget);
    expect(
        find.text("No other computers found yet. Open Boring Remote on the other computer. "
            "You'll see it here once both are on the same network."),
        findsOneWidget);
    expect(texts(tester).where((s) => s.contains('Mac')), isEmpty);
    await tester.tap(find.text('Connect from outside the building'));
    await tester.pumpAndSettle();
    expect(find.textContaining('pick this computer by name'), findsOneWidget);
  });

  test('a Windows computer on the network with no name is an Unnamed computer', () {
    KitWords.windows();
    expect(lanMacsFromJson('[{"hostname":"","ip":"10.0.4.7"}]').single.name, 'Unnamed computer');
  });

  testWidgets('Windows file transfer panes are This computer / That computer', (tester) async {
    KitWords.windows();
    await tester.pumpWidget(host(Row(children: [
      Expanded(child: TransferPane(side: TransferSide.thisMac, onDropFromOther: () {}, child: const SizedBox())),
      Expanded(child: TransferPane(side: TransferSide.thatMac, onDropFromOther: () {}, child: const SizedBox())),
    ])));
    expect(find.text('This computer'), findsOneWidget);
    expect(find.text('That computer'), findsOneWidget);
    await tester.pumpWidget(host(TransferList(jobs: const [], onCancel: (_) {}, onResume: (_) {}, onRemove: (_) {})));
    expect(find.text('Drag files from one computer to the other.'), findsOneWidget);
  });

  testWidgets('Windows approval and Trusted Controllers say computer', (tester) async {
    KitWords.windows();
    await tester.pumpWidget(host(ApprovalPrompt(name: '', onAllow: () {}, onDeny: () {})));
    expect(find.text('A computer on this network wants to control this computer.'), findsOneWidget);
    await tester.pumpWidget(host(TrustedControllersPage(
        trusted: const [], known: const [], onRemove: (_) async {}, onForget: (_) async {})));
    expect(texts(tester).where((s) => s.contains('Mac')), isEmpty);
    expect(find.text('None yet. A computer lands here once you allow it in.'), findsOneWidget);
  });

  testWidgets('Windows Settings names this computer', (tester) async {
    KitWords.windows();
    await tester.pumpWidget(host(SimpleSettings(
      macName: 'Front Desk',
      onRename: (_) async {},
      passwordSet: false,
      setPassword: (_) async => true,
      remoteAccess: false,
      onRemoteAccess: (_) {},
      checkUpdates: true,
      onCheckUpdates: (_) {},
      advanced: const [],
    )));
    expect(find.text("This computer's name"), findsOneWidget);
    expect(texts(tester).where((s) => s.contains('Mac')), isEmpty);
  });
}
