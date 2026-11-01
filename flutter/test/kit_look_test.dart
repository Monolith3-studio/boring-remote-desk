// v1.7 review: the upstream surfaces Mac and Windows still show, in the kit and in plain words.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/kit_look.dart';

Widget host(Widget w) => MaterialApp(theme: kitLook(Kit.theme()), home: Scaffold(body: w));

void main() {
  tearDown(KitWords.mac);

  testWidgets('dialogs, buttons and switches take kit colours, never RustDesk blue', (tester) async {
    await tester.pumpWidget(host(Builder(builder: (context) {
      final t = Theme.of(context);
      expect(t.dialogTheme.backgroundColor, Kit.panel);
      expect(t.elevatedButtonTheme.style!.backgroundColor!.resolve({}), Kit.paper);
      expect(t.elevatedButtonTheme.style!.foregroundColor!.resolve({}), Kit.ink);
      expect(t.switchTheme.trackColor!.resolve({WidgetState.selected}), Kit.paper);
      expect(t.checkboxTheme.fillColor!.resolve({WidgetState.selected}), Kit.paper);
      expect(t.menuTheme.style!.backgroundColor!.resolve({}), Kit.panel);
      return const SizedBox();
    })));
  });

  testWidgets('a settings section shows its title and rows; a tab row reports a tap', (tester) async {
    var tapped = 0;
    await tester.pumpWidget(host(Column(children: [
      const KitSection(title: 'Security', children: [Text('Unlock security settings')]),
      KitTabRow(label: 'General', icon: Icons.settings, selected: true, onTap: () => tapped++),
    ])));
    expect(find.text('Security'), findsOneWidget);
    expect(find.text('Unlock security settings'), findsOneWidget);
    await tester.tap(find.text('General'));
    expect(tapped, 1);
  });

  test('connection errors read as plain words with one next step', () {
    final timeout = kitMessageWords('error', 'Connection Error', 'Timeout')!;
    expect(timeout.title, "Couldn't connect");
    expect(timeout.body, "That Mac didn't answer in time.");
    expect(timeout.next, contains('then try again'));

    final unknown = kitMessageWords('error', 'Connection Error', 'os error 61')!;
    expect(unknown.body, isNull); // the upstream text stays, under a plain title
    expect(unknown.next, isNotNull);

    final waiting = kitMessageWords('wait-remote-accept-nook', 'Prompt',
        'Please wait for the remote side to accept your session request...')!;
    expect(waiting.body, 'Someone at that Mac needs to click Allow.');
    expect(kitMessageWaits('wait-remote-accept-nook', ''), isTrue);

    expect(kitMessageWords('info', 'Prompt', 'no_audio_input_device_tip'), isNull);
  });

  test('on Windows the words say computer', () {
    KitWords.windows();
    expect(kitMessageWords('error', 'Connection Error', 'Remote desktop is offline')!.body,
        'That computer is offline.');
    expect(KitPasswordWords.title, 'Password for that computer');
  });

  testWidgets('a message shows its title, body and next step, no icon', (tester) async {
    await tester.pumpWidget(host(const KitMessage(
        title: "Couldn't connect", body: "That Mac didn't answer in time.", next: 'Try again.')));
    expect(find.text("Couldn't connect"), findsOneWidget);
    expect(find.text("That Mac didn't answer in time."), findsOneWidget);
    expect(find.text('Try again.'), findsOneWidget);
    expect(find.byType(Icon), findsNothing);
  });
}
