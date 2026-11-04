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
    expect(find.text('From another network, type this on the other computer:'), findsOneWidget);
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
    expect(find.textContaining('both computers need Tailscale'), findsOneWidget);
    expect(find.textContaining('sign in with the same account'), findsOneWidget);
    expect(find.text('From another network, type this on the other computer:'), findsNothing);
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
    expect(find.text('No other computers found on this network yet.'), findsOneWidget);
    expect(find.text('1. Open Boring Remote on the other computer and finish its Setup.'), findsOneWidget);
    expect(find.text('2. Check both are on the same Wi-Fi or network.'), findsOneWidget);
    expect(find.text('It shows up here by itself within a few seconds.'), findsOneWidget);
    expect(find.text('Or type its address above, like 192.168.1.20.'), findsOneWidget);
  });

  testWidgets('Macs used before but none on this network: still says what to do (ticket 21)', (tester) async {
    await tester.pumpWidget(host(home()));
    expect(find.text('Edit Bay 2'), findsOneWidget);
    expect(find.text('No other computers found on this network yet.'), findsOneWidget);
  });

  testWidgets('the empty note goes once a Mac on this network answers, or while searching', (tester) async {
    await tester.pumpWidget(host(MacHome(macs: const [], lan: lan, tailscaleAddress: () async => null, onConnect: (_) {})));
    expect(find.text('No other computers found on this network yet.'), findsNothing);
    await tester.pumpWidget(host(home(list: const [])));
    await tester.enterText(find.byKey(MacHome.addressKey), 'edit');
    await tester.pump();
    expect(find.text('No other computers found on this network yet.'), findsNothing);
  });

  // v1.7 t26: the other end can be a PC, so Home says computer on the Mac build too.
  testWidgets('Mac build Home says computer about the Target, Mac about this one', (tester) async {
    await tester.pumpWidget(host(home(list: const [])));
    expect(find.text('Connect to a computer'), findsOneWidget);
    expect(find.text('Computers'), findsOneWidget);
    final hint = tester.widget<TextField>(find.byKey(MacHome.addressKey)).decoration?.hintText;
    expect(hint, "Type a computer's name");
    expect(tester.widgetList<Text>(find.byType(Text)).where((t) => (t.data ?? '').contains('Mac')), isEmpty);
    await tester.tap(find.text('Connect from outside the building'));
    await tester.pumpAndSettle();
    expect(find.textContaining('pick this Mac by name'), findsOneWidget);
    expect(find.text('From another network, type this on the other computer:'), findsOneWidget);
  });

  testWidgets('Mac build, no Tailscale: reach this Mac, both computers need it', (tester) async {
    await tester.pumpWidget(host(home(tailscale: () async => null)));
    await tester.tap(find.text('Connect from outside the building'));
    await tester.pumpAndSettle();
    expect(find.textContaining('To reach this Mac from another network, both computers need Tailscale.'),
        findsOneWidget);
    expect(find.textContaining('what to type on the other computer'), findsOneWidget);
  });

  // v1.7 t26: one machine reached by name, Wi-Fi, wired and Tailscale is one row.
  group('oneEntryPerMachine', () {
    List<String> targets(List<MacEntry> list) => [for (final m in oneEntryPerMachine(list)) m.target];

    test('the same trust key under four addresses is one entry, the newest', () {
      expect(
          targets(const [
            MacEntry(name: 'm1-d2', target: '100.70.1.2', identity: 'pk1'),
            MacEntry(name: 'm1-d2', target: 'm1-d2', identity: 'pk1'),
            MacEntry(name: 'other', target: '10.0.0.9', identity: 'pk2'),
            MacEntry(name: 'm1-d2', target: '192.168.1.20', identity: 'pk1'),
            MacEntry(name: 'm1-d2', target: '10.0.0.20', identity: 'pk1'),
          ]),
          ['100.70.1.2', '10.0.0.9']);
    });

    test('no identity: the display name decides, any case', () {
      expect(
          targets(const [
            MacEntry(name: 'm1-d2', target: '192.168.1.20'),
            MacEntry(name: 'M1-D2', target: '10.0.0.20'),
            MacEntry(name: 'stage', target: '10.0.0.30'),
          ]),
          ['192.168.1.20', '10.0.0.30']);
    });

    test('an address nothing is pinned for joins the machine of that name, whichever is newer', () {
      expect(
          targets(const [
            MacEntry(name: 'm1-d2', target: '100.70.1.2', identity: 'pk1'),
            MacEntry(name: 'm1-d2', target: '10.0.0.20'),
          ]),
          ['100.70.1.2']);
      expect(
          targets(const [
            MacEntry(name: 'm1-d2', target: '10.0.0.20'),
            MacEntry(name: 'm1-d2', target: '100.70.1.2', identity: 'pk1'),
            MacEntry(name: 'm1-d2', target: '192.168.1.20', identity: 'pk1'),
          ]),
          ['10.0.0.20']);
    });

    test('two machines with one name but different trust keys both stay', () {
      expect(
          targets(const [
            MacEntry(name: 'iMac', target: '10.0.0.1', identity: 'pk1'),
            MacEntry(name: 'iMac', target: '10.0.0.2', identity: 'pk2'),
          ]),
          ['10.0.0.1', '10.0.0.2']);
    });

    test('nameless entries with no identity are never treated as one machine', () {
      expect(
          targets(const [
            MacEntry(name: KitWords.unnamed, target: '10.0.0.1'),
            MacEntry(name: KitWords.unnamed, target: '10.0.0.2'),
          ]),
          ['10.0.0.1', '10.0.0.2']);
    });
  });

  testWidgets('Used before shows a machine once; its row dials the newest address, an older one can be typed',
      (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(MacHome(
        macs: oneEntryPerMachine(const [
          MacEntry(name: 'm1-d2', target: '100.70.1.2', identity: 'pk1'),
          MacEntry(name: 'm1-d2', target: '192.168.1.20', identity: 'pk1'),
        ]),
        tailscaleAddress: () async => null,
        onConnect: got.add)));
    expect(find.text('m1-d2'), findsOneWidget);
    await tester.tap(find.text('m1-d2'));
    expect(got, ['100.70.1.2']);
    await tester.enterText(find.byKey(MacHome.addressKey), '192.168.1.20');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    expect(got, ['100.70.1.2', '192.168.1.20']);
  });

  testWidgets('Home leads with a name, never the word IP', (tester) async {
    await tester.pumpWidget(host(home(list: const [])));
    final hint = tester.widget<TextField>(find.byKey(MacHome.addressKey)).decoration?.hintText;
    expect(hint, "Type a computer's name");
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
