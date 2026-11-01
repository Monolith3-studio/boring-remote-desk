import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/mac_home.dart';

const macs = [
  MacEntry(name: 'Edit Bay 2', target: '123456789'),
  MacEntry(name: 'Stage Left', target: '987654321'),
];

Widget host(MacHome home) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: home));

MacHome home({List<MacEntry> list = macs, void Function(String)? onConnect}) =>
    MacHome(macs: list, myId: '555 666 777', onConnect: onConnect ?? (_) {});

void main() {
  testWidgets('Home shows the Address box and Macs by name, never an ID',
      (tester) async {
    await tester.pumpWidget(host(home()));
    expect(find.byKey(MacHome.addressKey), findsOneWidget);
    expect(find.text('Edit Bay 2'), findsOneWidget);
    expect(find.text('Stage Left'), findsOneWidget);
    expect(find.textContaining('123456789'), findsNothing);
    expect(find.textContaining('555 666 777'), findsNothing);
  });

  testWidgets('Outside-the-building sheet holds the ID', (tester) async {
    await tester.pumpWidget(host(home()));
    await tester.tap(find.text('Connect from outside the building'));
    await tester.pumpAndSettle();
    expect(find.text('555 666 777'), findsOneWidget);
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
    expect(find.text('No Macs yet. Type a Mac name or IP above.'), findsOneWidget);
  });

  testWidgets('notices from the page show above the Address box', (tester) async {
    await tester.pumpWidget(host(MacHome(
        macs: macs, myId: '1', onConnect: (_) {}, notices: const [Text('Update ready')])));
    expect(find.text('Update ready'), findsOneWidget);
  });
}
