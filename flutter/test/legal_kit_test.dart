// Ticket 32: the Legal dialog carries AGPL 5(d)'s notices and the source link.
import 'dart:ui' show Size;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/legal.dart';

Future<List<String>> open(WidgetTester tester, {Future<String> Function()? read}) async {
  final opened = <String>[];
  await tester.pumpWidget(MaterialApp(
      theme: Kit.theme(),
      home: Scaffold(
          body: Builder(
              builder: (context) => TextButton(
                  onPressed: () => showLegalDialog(context,
                      readLicense: read ?? () async => 'GNU AFFERO GENERAL PUBLIC LICENSE', openUrl: opened.add),
                  child: const Text('About item'))))));
  await tester.tap(find.text('About item'));
  await tester.pumpAndSettle();
  return opened;
}

void main() {
  testWidgets('shows every notice AGPL 5(d) asks for, in these words', (tester) async {
    await open(tester);
    for (final words in [
      'Legal',
      'Boring Remote is based on RustDesk, © Purslane Tech Pte. Ltd.',
      "It's licensed under the GNU AGPL, version 3. You may copy, change and share it under that license.",
      'It comes with no warranty.',
      'The source code for each version is here:',
      'https://boringlabs.online/remote/source/',
      'Read the license',
      'Get the source code',
    ]) {
      expect(find.text(words), findsOneWidget, reason: words);
    }
  });

  testWidgets('Get the source code opens the source page', (tester) async {
    final opened = await open(tester);
    await tester.tap(find.text('Get the source code'));
    expect(opened, ['https://boringlabs.online/remote/source/']);
  });

  testWidgets('Read the license shows the bundled text, Close comes back', (tester) async {
    await open(tester);
    await tester.tap(find.text('Read the license'));
    await tester.pumpAndSettle();
    expect(find.text('GNU AFFERO GENERAL PUBLIC LICENSE'), findsOneWidget);
    await tester.tap(find.text('Close').last);
    await tester.pumpAndSettle();
    expect(find.text('GNU AFFERO GENERAL PUBLIC LICENSE'), findsNothing);
    expect(find.text('Get the source code'), findsOneWidget);
    await tester.tap(find.text('Close'));
    await tester.pumpAndSettle();
    expect(find.text('Get the source code'), findsNothing);
  });

  testWidgets('a license that will not load says where to read it', (tester) async {
    await open(tester, read: () async => throw StateError('no asset'));
    await tester.tap(find.text('Read the license'));
    await tester.pumpAndSettle();
    expect(find.text("Couldn't open the license. Read it at https://www.gnu.org/licenses/agpl-3.0.html"),
        findsOneWidget);
  });

  testWidgets('fits a small window, long license included', (tester) async {
    tester.view.physicalSize = const Size(420, 360);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    await open(tester, read: () async => List.filled(700, 'Everyone is permitted to copy.').join('\n'));
    await tester.tap(find.text('Read the license'));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
    expect(find.text('Close'), findsNWidgets(2));
  });
}
