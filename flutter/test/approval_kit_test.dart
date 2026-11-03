import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/approval.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/trust.dart';

// A main window with something in it, as the overlay finds it.
Future<GlobalKey<NavigatorState>> mainWindow(WidgetTester tester, Size size) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  final nav = GlobalKey<NavigatorState>();
  await tester.pumpWidget(MaterialApp(
    navigatorKey: nav,
    theme: Kit.theme(),
    home: const Scaffold(body: Center(child: Text('Home'))),
  ));
  return nav;
}

/// Every word of the ask and both buttons are inside the window, nothing overflowed.
void expectWhole(WidgetTester tester, Size size, String question) {
  expect(tester.takeException(), isNull);
  final window = Offset.zero & size;
  for (final f in [find.text(question), find.text(kApprovalWhy), find.text('Allow'), find.text("Don't allow")]) {
    expect(f, findsOneWidget);
    final r = tester.getRect(f);
    expect(window.contains(r.topLeft) && window.contains(r.bottomRight - const Offset(0.01, 0.01)), isTrue,
        reason: '$f at $r is outside $window');
  }
  for (final k in ['approval-allow', 'approval-deny']) {
    expect(tester.getSize(find.byKey(ValueKey(k))).height, greaterThanOrEqualTo(56));
  }
}

void main() {
  test('messages round-trip in the format src/boring_approval.rs carries', () {
    final ask = parseApproval(approvalAsk(7, 'Jason M Studio: edit bay'))!;
    expect((ask.kind, ask.id, ask.name), (ApprovalKind.ask, 7, 'Jason M Studio: edit bay'));
    expect(approvalAsk(7, 'a b'), 'boring-approval-ask:7::::a%20b');
    // Audit H1: the ask carries new / removed, the trust key and the address, not just a name.
    final v6 = parseApproval(approvalAsk(8, 'Edit Bay 2', trust: 'removed', key: 'bb22cc33dd44ee55', ip: 'fe80::1'))!;
    expect((v6.id, v6.name, v6.trust, v6.key, v6.ip), (8, 'Edit Bay 2', 'removed', 'bb22cc33dd44ee55', 'fe80::1'));
    final old = parseApproval('boring-approval-ask:7:a%20b')!;
    expect((old.name, old.trust, old.key), ('a b', '', ''));
    final done = parseApproval(approvalDone(7))!;
    expect((done.kind, done.id), (ApprovalKind.done, 7));
    expect(parseApproval(approvalAnswer(7, true))!.allow, isTrue);
    expect(parseApproval(approvalAnswer(7, false))!.allow, isFalse);
    expect(parseApproval('boring-approval-answer:7:maybe'), isNull);
    expect(parseApproval('boring-approval-ask:x:y'), isNull);
    expect(parseApproval('boringremote://connect/1'), isNull);
  });

  for (final size in [const Size(1280, 800), const Size(640, 480), const Size(520, 360), const Size(320, 240)]) {
    testWidgets('the ask fills the main window whole at ${size.width.toInt()}x${size.height.toInt()}',
        (tester) async {
      final nav = await mainWindow(tester, size);
      var fronted = 0;
      final answers = <String>[];
      final desk = ApprovalDesk(
        overlay: () => nav.currentState?.overlay,
        toFront: () async => fronted++,
        answer: (id, allow) => answers.add('$id:$allow'),
      );
      desk.take(ApprovalMsg(ApprovalKind.ask, 3, name: 'Jason M Studio, the long-named edit bay Mac upstairs'));
      await tester.pumpAndSettle();
      expect(fronted, 1);
      const q = 'Jason M Studio, the long-named edit bay Mac upstairs wants to control this Mac.';
      // A short window scrolls the card; the buttons are reachable and then fully in view.
      await tester.ensureVisible(find.byKey(const ValueKey('approval-allow')));
      await tester.pumpAndSettle();
      // In a window this size or bigger, all of it shows at once; smaller, it scrolls into view.
      if (size.height >= 480) expectWhole(tester, size, q);
      expect(tester.takeException(), isNull);
      await tester.tap(find.byKey(const ValueKey('approval-allow')));
      await tester.pumpAndSettle();
      expect(answers, ['3:true']);
      expect(find.text(q), findsNothing);
      expect(ApprovalDesk.waitingNow.value, isEmpty);
    });
  }

  testWidgets("Don't allow answers no; a second ask waits its turn; done drops one", (tester) async {
    final nav = await mainWindow(tester, const Size(900, 600));
    final answers = <String>[];
    final desk = ApprovalDesk(
      overlay: () => nav.currentState?.overlay,
      toFront: () async {},
      answer: (id, allow) => answers.add('$id:$allow'),
    );
    desk.take(const ApprovalMsg(ApprovalKind.ask, 1, name: 'Edit Bay 2'));
    desk.take(const ApprovalMsg(ApprovalKind.ask, 2, name: 'Stage Left'));
    desk.take(const ApprovalMsg(ApprovalKind.ask, 4, name: 'FOH'));
    await tester.pumpAndSettle();
    expect(ApprovalDesk.waitingNow.value.map((w) => w.name), ['Edit Bay 2', 'Stage Left', 'FOH']);
    expect(find.text('Edit Bay 2 wants to control this Mac.'), findsOneWidget);
    await tester.tap(find.text("Don't allow"));
    await tester.pumpAndSettle();
    expect(answers, ['1:false']);
    expect(find.text('Stage Left wants to control this Mac.'), findsOneWidget);
    // Settled in the connection window: the main window drops it and shows the next.
    desk.take(const ApprovalMsg(ApprovalKind.done, 2));
    await tester.pumpAndSettle();
    expect(find.text('FOH wants to control this Mac.'), findsOneWidget);
    expect(answers, ['1:false']);
    desk.take(const ApprovalMsg(ApprovalKind.done, 4));
    await tester.pumpAndSettle();
    expect(find.textContaining('wants to control'), findsNothing);
    expect(find.text('Home'), findsOneWidget);
  });

  testWidgets('Settings: Allow next to whoever is waiting answers the same way', (tester) async {
    final nav = await mainWindow(tester, const Size(900, 700));
    final answers = <String>[];
    final desk = ApprovalDesk(
      overlay: () => nav.currentState?.overlay,
      toFront: () async {},
      answer: (id, allow) => answers.add('$id:$allow'),
    );
    desk.take(const ApprovalMsg(ApprovalKind.ask, 9, name: 'Jason M Studio'));
    await tester.pumpAndSettle();
    final rows = WaitingApprovals(waiting: ApprovalDesk.waitingNow, onDecide: desk.decide);
    await tester.pumpWidget(MaterialApp(theme: Kit.theme(), home: Scaffold(body: rows)));
    expect(find.text('Jason M Studio wants to control this Mac.'), findsOneWidget);
    await tester.tap(find.text('Allow'));
    await tester.pumpAndSettle();
    expect(answers, ['9:true']);
    expect(find.text('Jason M Studio wants to control this Mac.'), findsNothing);
    desk.decide(9, true); // already answered: nothing sent twice
    expect(answers, ['9:true']);
  });

  testWidgets('the ask in the main window says new or removed, and where it is', (tester) async {
    final nav = await mainWindow(tester, const Size(900, 600));
    final desk = ApprovalDesk(overlay: () => nav.currentState?.overlay, toFront: () async {}, answer: (_, __) {});
    desk.take(const ApprovalMsg(ApprovalKind.ask, 1, name: 'Edit Bay 2', trust: 'new', key: 'aa', ip: '192.168.1.66'));
    await tester.pumpAndSettle();
    expect(find.text('New computer, at 192.168.1.66.'), findsOneWidget);
    desk.decide(1, false);
    desk.take(const ApprovalMsg(ApprovalKind.ask, 2, name: 'Edit Bay 2', trust: 'removed', key: 'bb', ip: '192.168.1.20'));
    await tester.pumpAndSettle();
    expect(find.text('Removed earlier from the Trusted list, at 192.168.1.20.'), findsOneWidget);
    final rows = WaitingApprovals(waiting: ApprovalDesk.waitingNow, onDecide: desk.decide);
    await tester.pumpWidget(MaterialApp(theme: Kit.theme(), home: Scaffold(body: rows)));
    expect(find.text('Removed earlier from the Trusted list, at 192.168.1.20.'), findsOneWidget);
    desk.decide(2, false);
  });

  test('Allow on a removed row lets in only the ask that holds its key, never one with its name', () {
    const removed = TrustedController(key: 'bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff001122334455', name: 'Jason M Studio');
    const waiting = [
      WaitingAsk(1, 'Jason M Studio', trust: 'new', key: '0123456789abcdef', ip: '192.168.1.66'),
      WaitingAsk(2, 'Jason M Studio', trust: 'removed', key: 'bb22cc33dd44ee55', ip: '192.168.1.20'),
      WaitingAsk(3, 'Jason M Studio', trust: 'removed', key: 'ffffffffffffffff', ip: '192.168.1.67'),
      WaitingAsk(4, 'Jason M Studio', trust: 'new', key: 'bb22cc33dd44ee55', ip: '192.168.1.68'),
      WaitingAsk(5, 'Jason M Studio'),
      WaitingAsk(6, 'Someone', trust: 'removed', key: 'bb22', ip: '192.168.1.69'),
    ];
    expect(waitingFrom(removed, waiting), [2]);
    expect(waitingFrom(const TrustedController(key: '', name: 'Jason M Studio'), waiting), isEmpty);
  });

  const trusted = '[{"key":"aa11","name":"Edit Bay 2","added":1761955200},'
      '{"key":"bb22","name":"Jason M Studio","added":1761955300,"removed":true}]';

  test('Allow on a removed Controller does what trust.rs reinstate does', () {
    expect(parseRemoved(trusted).map((c) => c.name), ['Jason M Studio']);
    final back = reinstateTrusted(trusted, 'bb22', now: 1793660000);
    expect(parseRemoved(back), isEmpty);
    expect(parseTrusted(back).map((c) => c.key), ['aa11', 'bb22']);
    expect((jsonDecode(back) as List)[1], {'key': 'bb22', 'name': 'Jason M Studio', 'added': 1793660000});
    expect(reinstateTrusted('not json', 'bb22'), '[]');
  });

  testWidgets('Trusted Controllers: removed ones with a big Allow, and who is waiting', (tester) async {
    final allowed = <String>[];
    await tester.pumpWidget(MaterialApp(
      theme: Kit.theme(),
      home: Scaffold(
        body: TrustedControllersPage(
          trusted: parseTrusted(trusted),
          known: const [],
          onRemove: (_) async {},
          onForget: (_) async {},
          removed: parseRemoved(trusted),
          onAllow: (c) async => allowed.add(c.key),
          waiting: const Text('waiting rows'),
        ),
      ),
    ));
    expect(find.text('waiting rows'), findsOneWidget);
    expect(find.text('Removed'), findsOneWidget);
    final allow = find.widgetWithText(FilledButton, 'Allow');
    expect(tester.getSize(allow).height, greaterThanOrEqualTo(48));
    await tester.tap(allow);
    await tester.pumpAndSettle();
    expect(allowed, ['bb22']);
    expect(find.text('Removed'), findsNothing);
    expect(find.text('Jason M Studio'), findsOneWidget); // now listed as Trusted, with Remove
    expect(find.text('Remove'), findsNWidgets(2));
  });
}
