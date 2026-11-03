import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/trust.dart';

Widget host(Widget w) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: w));

// What libs/base/src/trust.rs and direct_link.rs write.
const trustedJson = '[{"key":"aa11","name":"Edit Bay 2","added":1761955200},'
    '{"key":"bb22","name":"Stage Left","added":1761955300}]';
const knownJson = '{"123456789":{"pk":"00ff","lan":"192.168.1.20:21118","tailscale":""},'
    '"987654321":{"pk":"11ee","lan":"","tailscale":"100.64.0.2:21118"}}';

void main() {
  test('reads and removes Trusted Controllers in the Rust format', () {
    final list = parseTrusted(trustedJson);
    expect(list.map((c) => c.name), ['Edit Bay 2', 'Stage Left']);
    expect(parseTrusted(removeTrusted(trustedJson, 'aa11')).map((c) => c.key), ['bb22']);
    // Removed stays in the JSON, hidden, so the Target still knows that token and asks (A2 step 5).
    expect(removeTrusted(trustedJson, 'aa11'), contains('"key":"aa11","name":"Edit Bay 2","added":1761955200,"removed":true'));
    expect(parseTrusted('[{"key":"aa11","name":"x","removed":true}]'), isEmpty);
    expect(parseTrusted(''), isEmpty);
    expect(parseTrusted('not json'), isEmpty);
  });

  test("forgets a Mac's pinned key by Target ID", () {
    final known = parseKnown(knownJson);
    expect(known.map((m) => m.address), ['192.168.1.20', '100.64.0.2']); // no LAN address: its Tailscale one
    expect(parseKnown(forgetId(knownJson, '123456789')).map((m) => m.id), ['987654321']);
    expect(forgetId('{"123456789":"00abc"}', '123456789'), '{}');
  });

  testWidgets('lists Trusted Controllers and removes one', (tester) async {
    final removed = <String>[];
    await tester.pumpWidget(host(TrustedControllersPage(
      trusted: parseTrusted(trustedJson),
      known: const [],
      onRemove: (k) async => removed.add(k),
      onForget: (_) async {},
    )));
    expect(find.text('Edit Bay 2'), findsOneWidget);
    expect(find.text('Trusted list'), findsOneWidget);
    expect(find.textContaining('Controller'), findsNothing, reason: 'Controller is an internal word');
    await tester.tap(find.text('Remove').first);
    await tester.pumpAndSettle();
    expect(removed, ['aa11']);
    expect(find.text('Edit Bay 2'), findsNothing);
    expect(find.text('Stage Left'), findsOneWidget);
  });

  testWidgets("forgets a reinstalled Mac's key so it can pair again", (tester) async {
    final forgot = <String>[];
    await tester.pumpWidget(host(TrustedControllersPage(
      trusted: const [],
      known: parseKnown(knownJson),
      onRemove: (_) async {},
      onForget: (id) async => forgot.add(id),
    )));
    expect(find.text('None yet. A Mac lands here once you allow it in.'), findsOneWidget);
    expect(find.text('192.168.1.20'), findsOneWidget);
    expect(find.text('100.64.0.2'), findsOneWidget);
    expect(find.textContaining('987654321'), findsNothing); // never the ID
    expect(find.text("If one of these was reinstalled, it won't connect. Click Forget next to it, "
        'then connect to it again.'), findsOneWidget);
    await tester.tap(find.text('Forget').first);
    await tester.pumpAndSettle();
    expect(forgot, ['123456789']);
    expect(find.text('192.168.1.20'), findsNothing);
  });

  testWidgets('a Mac with no address left is named in plain words, never by its ID', (tester) async {
    await tester.pumpWidget(host(TrustedControllersPage(
      trusted: const [],
      known: const [KnownMac(id: '555666777', address: '')],
      onRemove: (_) async {},
      onForget: (_) async {},
    )));
    expect(find.text('A Mac you connected to'), findsOneWidget);
    expect(find.textContaining('555666777'), findsNothing);
  });

  testWidgets('approval prompt says who is asking, Allow or Don\'t allow', (tester) async {
    final got = <String>[];
    await tester.pumpWidget(host(ApprovalPrompt(
      name: 'Edit Bay 2',
      onAllow: () => got.add('allow'),
      onDeny: () => got.add('deny'),
    )));
    expect(find.text('Edit Bay 2 wants to control this Mac.'), findsOneWidget);
    await tester.tap(find.text("Don't allow"));
    await tester.tap(find.text('Allow'));
    expect(got, ['deny', 'allow']);
  });

  testWidgets('a nameless Mac is still described in plain words', (tester) async {
    await tester.pumpWidget(host(ApprovalPrompt(name: '  ', onAllow: () {}, onDeny: () {})));
    expect(find.text('A Mac on this network wants to control this Mac.'), findsOneWidget);
  });
}
