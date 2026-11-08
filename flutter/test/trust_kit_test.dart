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

  test('Always ask for password: read, switched on and off in the Rust format', () {
    expect(parseTrusted(trustedJson).map((c) => c.alwaysAsk), [false, false], reason: '1.7.0 lists are off');
    final on = setAlwaysAsk(trustedJson, 'aa11', true);
    expect(on, contains('"key":"aa11","name":"Edit Bay 2","added":1761955200,"always_ask":true}'));
    expect(parseTrusted(on).map((c) => c.alwaysAsk), [true, false]);
    // Off is not written, as trust.rs skips it: the list goes back to exactly what 1.7.0 wrote.
    expect(setAlwaysAsk(on, 'aa11', false), trustedJson);
    // Remove and Allow keep it.
    expect(parseRemoved(removeTrusted(on, 'aa11')).single.alwaysAsk, isTrue);
    expect(parseTrusted(reinstateTrusted(removeTrusted(on, 'aa11'), 'aa11', now: 1)).first.alwaysAsk, isTrue);
    // A removed one has no switch (trust.rs set_always_ask); bad JSON is no list, as for Remove.
    final removed = removeTrusted(trustedJson, 'aa11');
    expect(setAlwaysAsk(removed, 'aa11', true), removed);
    expect(setAlwaysAsk('not json', 'aa11', true), '[]');
  });

  // v1.7 t26: Home keys a recent by the key pinned for its Target ID or last address.
  // boring-remote (v1.7 t25): every address it advertised is the same machine on Home.
  test('identities: each stored address of a Target is that Target', () {
    final who = identitiesFromKnown('{"303012600":{"pk":"AB01","lan":"192.168.1.127:21118","tailscale":"",'
        '"addrs":[{"ip":"192.168.1.127","link":"wired","mbps":1000},{"ip":"192.168.1.124","link":"wifi","mbps":130}]}}');
    expect(who['192.168.1.127'], 'AB01');
    expect(who['192.168.1.124'], 'AB01');
  });

  test('identities: a pinned key under the Target ID, the LAN address and the Tailscale address', () {
    final who = identitiesFromKnown('{"303012600":{"pk":"AB01","lan":"192.168.1.124:21118",'
        '"tailscale":"[fd7a:115c:a1e0::5]:21118"},"5":{"pk":"cd","lan":"","tailscale":"100.70.1.2:21118"}}');
    expect(who['303012600'], 'AB01');
    expect(who['192.168.1.124'], 'AB01');
    expect(who['fd7a:115c:a1e0::5'], 'AB01');
    expect(who['100.70.1.2'], 'cd');
    expect(who[''], isNull);
    expect(identitiesFromKnown('not json'), isEmpty);
    expect(identitiesFromKnown('{"7":{"lan":"10.0.0.7:21118"}}')['10.0.0.7'], '7', reason: 'no key: the Target ID');
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

  testWidgets('each Trusted computer has Always ask for password, off unless set', (tester) async {
    final set = <String>[];
    await tester.pumpWidget(host(TrustedControllersPage(
      trusted: parseTrusted(setAlwaysAsk(trustedJson, 'bb22', true)),
      known: const [],
      onRemove: (_) async {},
      onForget: (_) async {},
      onAlwaysAsk: (k, on) async => set.add('$k $on'),
    )));
    expect(find.text('Always ask for password'), findsNWidgets(2));
    expect(find.text(alwaysAskWhy()), findsNWidgets(2));
    expect(alwaysAskWhy(), "It needs this Mac's Unattended Password every time it connects.");
    bool value(int i) => tester.widget<SwitchListTile>(find.byType(SwitchListTile).at(i)).value;
    expect([value(0), value(1)], [false, true]);
    await tester.tap(find.text('Always ask for password').first);
    await tester.pumpAndSettle();
    expect(set, ['aa11 true']);
    expect(value(0), isTrue);
    await tester.tap(find.text('Always ask for password').last);
    await tester.pumpAndSettle();
    expect(set, ['aa11 true', 'bb22 false']);
    expect(value(1), isFalse);
    // No onAlwaysAsk, nowhere to save it: no switch.
    await tester.pumpWidget(host(TrustedControllersPage(
        trusted: parseTrusted(trustedJson), known: const [], onRemove: (_) async {}, onForget: (_) async {})));
    expect(find.text('Always ask for password'), findsNothing, reason: 'no switch without somewhere to save it');
  });

  testWidgets("forgets a reinstalled Mac's key so it can pair again", (tester) async {
    final forgot = <String>[];
    await tester.pumpWidget(host(TrustedControllersPage(
      trusted: const [],
      known: parseKnown(knownJson),
      onRemove: (_) async {},
      onForget: (id) async => forgot.add(id),
    )));
    expect(find.text('None yet. A computer lands here once you allow it in.'), findsOneWidget);
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
    expect(find.text('A computer you connected to'), findsOneWidget);
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

  testWidgets('the connection window prompt says new or removed, and the address', (tester) async {
    await tester.pumpWidget(host(ApprovalPrompt(
        name: 'Edit Bay 2', trust: 'removed', ip: '192.168.1.20', onAllow: () {}, onDeny: () {})));
    expect(find.text('Edit Bay 2 wants to control this Mac.'), findsOneWidget);
    expect(find.text('Removed earlier from the Trusted list, at 192.168.1.20.'), findsOneWidget);
    await tester.pumpWidget(host(ApprovalPrompt(name: 'Edit Bay 2', onAllow: () {}, onDeny: () {})));
    expect(find.text('New computer.'), findsOneWidget, reason: 'no trust facts is never shown as known');
    expect(approvalWho('new', 'fe80::1'), 'New computer, at fe80::1.');
    expect(approvalWho('trusted', '192.168.1.20'), '');
  });

  testWidgets('a nameless Mac is still described in plain words', (tester) async {
    await tester.pumpWidget(host(ApprovalPrompt(name: '  ', onAllow: () {}, onDeny: () {})));
    expect(find.text('A computer on this network wants to control this Mac.'), findsOneWidget);
  });
}
