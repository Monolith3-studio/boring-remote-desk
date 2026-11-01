import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/lan_macs.dart';
import 'package:flutter_hbb/desktop/kit/mac_home.dart';
import 'package:flutter_hbb/desktop/kit/tailscale.dart';

const macs = [
  MacEntry(name: 'Edit Bay 2', target: '123456789'),
  MacEntry(name: 'Stage Left', target: '987654321'),
];

const lan = [LanMac(name: 'edit-bay-2', ip: '192.168.1.20'), LanMac(name: 'stage-left', ip: '10.0.4.7')];

Widget host(MacHome home) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: home));

MacHome home({List<MacEntry> list = macs, void Function(String)? onConnect, Future<String?> Function()? tailscale}) =>
    MacHome(
        macs: list,
        tailscaleAddress: tailscale ?? () async => '100.101.102.103',
        onConnect: onConnect ?? (_) {});

void main() {
  testWidgets('Home shows the Address box and Macs by name, never an ID',
      (tester) async {
    await tester.pumpWidget(host(home()));
    expect(find.byKey(MacHome.addressKey), findsOneWidget);
    expect(find.text('Edit Bay 2'), findsOneWidget);
    expect(find.text('Stage Left'), findsOneWidget);
    expect(find.textContaining('123456789'), findsNothing);
  });

  testWidgets('outside the building: what to type on the other Mac is this Mac\'s Tailscale address',
      (tester) async {
    await tester.pumpWidget(host(home()));
    await tester.tap(find.text('Connect from outside the building'));
    await tester.pumpAndSettle();
    expect(find.text('From another network, type this on the other Mac:'), findsOneWidget);
    expect(find.text('100.101.102.103'), findsOneWidget);
    expect(find.textContaining('Tailscale is a free app that links your computers over the internet'),
        findsOneWidget);
    expect(find.textContaining('123456789'), findsNothing);
  });

  testWidgets('outside the building with no Tailscale here: says what to do, then Check again finds it',
      (tester) async {
    String? address;
    await tester.pumpWidget(host(home(tailscale: () async => address)));
    await tester.tap(find.text('Connect from outside the building'));
    await tester.pumpAndSettle();
    expect(find.textContaining('both Macs need Tailscale'), findsOneWidget);
    expect(find.textContaining('sign in with the same account'), findsOneWidget);
    expect(find.text('From another network, type this on the other Mac:'), findsNothing);
    address = '100.70.1.2';
    await tester.ensureVisible(find.text('Check again'));
    await tester.tap(find.text('Check again'));
    await tester.pumpAndSettle();
    expect(find.text('100.70.1.2'), findsOneWidget);
  });

  test("this computer's Tailscale address: 100.64.0.0/10 first, else fd7a:115c:a1e0::/48, else none", () {
    InternetAddress a(String s) => InternetAddress(s);
    expect(tailscaleAddressIn([a('192.168.1.20'), a('fd7a:115c:a1e0::5'), a('100.101.102.103')]),
        '100.101.102.103');
    expect(tailscaleAddressIn([a('192.168.1.20'), a('fd7a:115c:a1e0:ab12::5')]), 'fd7a:115c:a1e0:ab12::5');
    expect(tailscaleAddressIn([a('100.64.0.1')]), '100.64.0.1');
    expect(tailscaleAddressIn([a('100.127.255.254')]), '100.127.255.254');
    for (final no in ['100.63.255.255', '100.128.0.1', '10.0.0.1', 'fd7a:115c:a1e1::1', 'fe80::1']) {
      expect(tailscaleAddressIn([a(no)]), isNull, reason: no);
    }
  });

  testWidgets('clicking a Mac connects to it', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(home(onConnect: got.add)));
    await tester.tap(find.text('Stage Left'));
    expect(got, ['987654321']);
  });

  testWidgets('typing an IP and pressing Return connects to it', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(home(onConnect: got.add)));
    await tester.enterText(find.byKey(MacHome.addressKey), ' 192.168.1.40 ');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    expect(got, ['192.168.1.40']);
  });

  testWidgets('typing a name narrows the Macs list', (tester) async {
    await tester.pumpWidget(host(home()));
    await tester.enterText(find.byKey(MacHome.addressKey), 'stage');
    await tester.pump();
    expect(find.text('Stage Left'), findsOneWidget);
    expect(find.text('Edit Bay 2'), findsNothing);
  });

  testWidgets('no Macs yet: says how to reach one', (tester) async {
    await tester.pumpWidget(host(home(list: const [])));
    expect(
        find.text("No other Macs found yet. Open Boring Remote on the other Mac. "
            "You'll see it here once both are on the same network."),
        findsOneWidget);
    expect(find.text('Or type its address above, like 192.168.1.20.'), findsOneWidget);
  });

  testWidgets('Home leads with a name, never the word IP', (tester) async {
    await tester.pumpWidget(host(home(list: const [])));
    final hint = tester.widget<TextField>(find.byKey(MacHome.addressKey)).decoration?.hintText;
    expect(hint, "Type a Mac's name");
    final words = [hint ?? '', for (final t in tester.widgetList<Text>(find.byType(Text))) t.data ?? ''];
    expect(words.where(RegExp(r'\bIP\b').hasMatch), isEmpty);
  });

  testWidgets('Macs used before sit under their own heading', (tester) async {
    await tester.pumpWidget(host(MacHome(
        macs: macs, lan: lan, tailscaleAddress: () async => null, onConnect: (_) {})));
    expect(find.text('On this network'), findsOneWidget);
    expect(find.text('Used before'), findsOneWidget);
  });

  testWidgets('notices from the page show above the Address box', (tester) async {
    await tester.pumpWidget(host(MacHome(
        macs: macs, tailscaleAddress: () async => null, onConnect: (_) {}, notices: const [Text('Update ready')])));
    expect(find.text('Update ready'), findsOneWidget);
  });

  MacHome lanHome({void Function(String)? onConnect, VoidCallback? discover}) => MacHome(
      macs: const [], lan: lan, tailscaleAddress: () async => null, onConnect: onConnect ?? (_) {}, discover: discover);

  testWidgets('Macs on this network show by name and IP; clicking one connects to its IP', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(lanHome(onConnect: got.add)));
    expect(find.text('On this network'), findsOneWidget);
    expect(find.text('edit-bay-2'), findsOneWidget);
    expect(find.text('192.168.1.20'), findsOneWidget);
    await tester.tap(find.text('stage-left'));
    expect(got, ['10.0.4.7']);
  });

  testWidgets('search narrows Macs on this network by name or IP prefix', (tester) async {
    await tester.pumpWidget(host(lanHome()));
    await tester.enterText(find.byKey(MacHome.addressKey), 'STAGE');
    await tester.pump();
    expect(find.text('stage-left'), findsOneWidget);
    expect(find.text('edit-bay-2'), findsNothing);
    await tester.enterText(find.byKey(MacHome.addressKey), '192.168');
    await tester.pump();
    expect(find.text('edit-bay-2'), findsOneWidget);
    expect(find.text('stage-left'), findsNothing);
  });

  testWidgets('a typed IP that is not in the list still offers Connect', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(lanHome(onConnect: got.add)));
    await tester.enterText(find.byKey(MacHome.addressKey), '192.168.1.99');
    await tester.pump();
    await tester.tap(find.text('Connect to 192.168.1.99'));
    expect(got, ['192.168.1.99']);
    await tester.enterText(find.byKey(MacHome.addressKey), '192.168.1.20');
    await tester.pump();
    expect(find.textContaining('Connect to 192'), findsNothing);
  });

  testWidgets('typing the name of a Mac on this network and pressing Return connects to its IP', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(MacHome(
        macs: const [MacEntry(name: 'stage-left', target: '987654321')],
        lan: lan,
        tailscaleAddress: () async => null,
        onConnect: got.add)));
    await tester.enterText(find.byKey(MacHome.addressKey), 'Edit-Bay-2');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    // On this network wins over a recent with the same name.
    await tester.enterText(find.byKey(MacHome.addressKey), 'STAGE-LEFT ');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    expect(got, ['192.168.1.20', '10.0.4.7']);
  });

  testWidgets('Home asks for LAN Discovery on open and again every cycle', (tester) async {
    var calls = 0;
    await tester.pumpWidget(host(lanHome(discover: () => calls++)));
    expect(calls, 1);
    await tester.pump(MacHome.discoverEvery);
    expect(calls, 2);
  });
}
