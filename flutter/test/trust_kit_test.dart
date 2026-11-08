import 'dart:convert';

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
  test('reads Trusted Controllers in the Rust format', () {
    final list = parseTrusted(trustedJson);
    expect(list.map((c) => c.name), ['Edit Bay 2', 'Stage Left']);
    expect(list.map((c) => c.alwaysAsk), [false, false], reason: '1.7.0 lists are off');
    const later = '[{"key":"aa11","name":"Edit Bay 2","always_ask":true},{"key":"bb22","name":"x","removed":true,"always_ask":true}]';
    expect(parseTrusted(later).single.alwaysAsk, isTrue);
    expect(parseRemoved(later).single.alwaysAsk, isTrue, reason: 'Allow brings it back still asking');
    expect(parseTrusted('[{"key":"aa11","name":"x","removed":true}]'), isEmpty);
    expect(parseTrusted(''), isEmpty);
    expect(parseTrusted('not json'), isEmpty);
  });

  // Every change to the list is the service's (trust.rs `edit`): Settings sends what to do and
  // shows what came back.
  test('edits go to the service as trust.rs reads them, and its answer is shown as it is', () {
    expect(jsonDecode(trustEdit('remove', 'aa11')), {'op': 'remove', 'key': 'aa11'});
    expect(jsonDecode(trustEdit('always_ask', 'aa11', on: true, password: 'pw')),
        {'op': 'always_ask', 'key': 'aa11', 'on': true, 'password': 'pw'});
    expect(trustEditError('{"ok":true}'), isNull);
    expect(trustEditError('{"ok":false,"error":"That isn\'t this computer\'s Unattended Password."}'),
        "That isn't this computer's Unattended Password.");
    expect(trustEditError(''), kTrustNoAnswer, reason: 'no answer is never taken as saved');
    expect(trustEditError('{"ok":false}'), kTrustNoAnswer);
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
      onRemove: (k) async {
        removed.add(k);
        return null;
      },
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

  Widget page({
    String json = trustedJson,
    String? answer,
    List<String>? sent,
    bool newAlwaysAsk = false,
    List<bool>? newSent,
  }) =>
      host(TrustedControllersPage(
        trusted: parseTrusted(json),
        known: const [],
        onRemove: (k) async {
          sent?.add('remove $k');
          return answer;
        },
        onForget: (_) async {},
        onAlwaysAsk: (k, on, pw) async {
          sent?.add('$k $on $pw');
          return answer;
        },
        newAlwaysAsk: newAlwaysAsk,
        onNewAlwaysAsk: (on) async => newSent?.add(on),
      ));

  bool value(WidgetTester tester, String key) => tester.widget<SwitchListTile>(find.byKey(ValueKey('always-ask-$key'))).value;

  testWidgets('each Trusted computer has Always ask for password, off unless set', (tester) async {
    final sent = <String>[];
    await tester.pumpWidget(page(json: '[{"key":"aa11","name":"Edit Bay 2"},{"key":"bb22","name":"Stage Left","always_ask":true}]', sent: sent));
    expect(find.text('Always ask for password'), findsNWidgets(2));
    expect(find.text(alwaysAskWhy()), findsNWidgets(2));
    expect(alwaysAskWhy(),
        "It needs this Mac's Unattended Password every time it connects. Turning it on makes every computer that saved the password type it again.");
    expect([value(tester, 'aa11'), value(tester, 'bb22')], [false, true]);

    // Off: no password needed, saved at once.
    await tester.tap(find.byKey(const ValueKey('always-ask-bb22')));
    await tester.pumpAndSettle();
    expect(sent, ['bb22 false ']);
    expect(value(tester, 'bb22'), isFalse);

    // On: the Unattended Password, typed here, first. Cancel changes nothing.
    await tester.tap(find.byKey(const ValueKey('always-ask-aa11')));
    await tester.pumpAndSettle();
    expect(find.text(alwaysAskAsk()), findsOneWidget);
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(sent, ['bb22 false ']);
    expect(value(tester, 'aa11'), isFalse);
    await tester.tap(find.byKey(const ValueKey('always-ask-aa11')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'Studio-pass-1');
    await tester.tap(find.text('Turn on'));
    await tester.pumpAndSettle();
    expect(sent, ['bb22 false ', 'aa11 true Studio-pass-1']);
    expect(value(tester, 'aa11'), isTrue);

    // No onAlwaysAsk, nowhere to save it: no switch.
    await tester.pumpWidget(host(TrustedControllersPage(
        trusted: parseTrusted(trustedJson), known: const [], onRemove: (_) async => null, onForget: (_) async {})));
    expect(find.text('Always ask for password'), findsNothing, reason: 'no switch without somewhere to save it');
    expect(find.text('New computers always ask for password'), findsNothing);
  });

  testWidgets('a refused change shows why and leaves the page as saved', (tester) async {
    const why = "That isn't this computer's Unattended Password.";
    await tester.pumpWidget(page(answer: why));
    await tester.tap(find.byKey(const ValueKey('always-ask-aa11')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'wrong');
    await tester.tap(find.text('Turn on'));
    await tester.pumpAndSettle();
    expect(find.text(why), findsOneWidget);
    expect(value(tester, 'aa11'), isFalse);
    await tester.tap(find.text('Remove').first);
    await tester.pumpAndSettle();
    expect(find.text('Edit Bay 2'), findsOneWidget, reason: 'not removed: still listed');
  });

  testWidgets('New computers always ask for password: off unless set, saved when switched', (tester) async {
    final newSent = <bool>[];
    await tester.pumpWidget(page(newSent: newSent));
    final sw = find.byKey(const ValueKey('new-always-ask'));
    expect(find.text('New computers always ask for password'), findsOneWidget);
    expect(find.text(kNewAlwaysAskWhy), findsOneWidget);
    expect(tester.widget<SwitchListTile>(sw).value, isFalse);
    await tester.tap(sw);
    await tester.pumpAndSettle();
    expect(newSent, [true]);
    expect(tester.widget<SwitchListTile>(sw).value, isTrue);
    await tester.pumpWidget(const SizedBox());
    await tester.pumpWidget(page(newAlwaysAsk: true));
    expect(tester.widget<SwitchListTile>(sw).value, isTrue);
  });

  testWidgets("forgets a reinstalled Mac's key so it can pair again", (tester) async {
    final forgot = <String>[];
    await tester.pumpWidget(host(TrustedControllersPage(
      trusted: const [],
      known: parseKnown(knownJson),
      onRemove: (_) async => null,
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
      onRemove: (_) async => null,
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
