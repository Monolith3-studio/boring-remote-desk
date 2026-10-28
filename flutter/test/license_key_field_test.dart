import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/widgets/license_key_field.dart';

Widget host(LicenseKeyField f) => MaterialApp(home: Scaffold(body: f));

Future<void> enter(WidgetTester t, String key) async {
  await t.enterText(find.byType(TextField), key);
  await t.tap(find.text('Check'));
  await t.pump();
}

void main() {
  testWidgets('shows the stored key on open', (t) async {
    await t.pumpWidget(host(LicenseKeyField(
        initialKey: 'ABC-123', setKey: (_) async => 'valid')));
    expect(find.text('ABC-123'), findsOneWidget);
  });

  testWidgets('Check sends the typed key and shows each status', (t) async {
    const want = {
      'valid': "Key's good.",
      'revoked': 'This key has been revoked.',
      'refunded': "This key was refunded, so it can't update.",
      'unknown': "We don't recognize that key. Check it against your purchase email.",
      'busy': 'Too many checks. Try again in an hour.',
      'network': "Couldn't reach the store. Your key's saved. Check your connection and try again.",
    };
    for (final e in want.entries) {
      String? sent;
      await t.pumpWidget(host(LicenseKeyField(
          key: UniqueKey(),
          initialKey: '',
          setKey: (k) async {
            sent = k;
            return e.key;
          })));
      await enter(t, 'K-${e.key}');
      expect(sent, 'K-${e.key}');
      expect(find.text(e.value), findsOneWidget, reason: e.key);
    }
  });

  testWidgets('bridge throwing reads as a network failure, not invalid', (t) async {
    await t.pumpWidget(host(LicenseKeyField(
        initialKey: '', setKey: (_) async => throw 'boom')));
    await enter(t, 'K');
    expect(find.text("Couldn't reach the store. Your key's saved. Check your connection and try again."),
        findsOneWidget);
  });

  testWidgets('shows checking while in flight', (t) async {
    await t.pumpWidget(host(LicenseKeyField(
        initialKey: '',
        setKey: (_) => Future.delayed(const Duration(seconds: 1), () => 'valid'))));
    await enter(t, 'K');
    expect(find.text('Checking…'), findsOneWidget);
    await t.pump(const Duration(seconds: 1));
    expect(find.text("Key's good."), findsOneWidget);
  });
}
