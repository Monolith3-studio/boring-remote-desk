import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/file_transfer.dart';

TransferJob job(String state,
        {int finished = 0,
        int total = 1000,
        String err = '',
        bool remoteToLocal = false,
        bool delete = false,
        double speed = 0,
        double? averageSpeed}) =>
    TransferJob.fromEngine(
        id: 7,
        path: '/Users/j/Movies/cut.mov',
        remoteToLocal: remoteToLocal,
        state: state,
        finished: finished,
        total: total,
        err: err,
        delete: delete,
        speed: speed,
        averageSpeed: averageSpeed);

void main() {
  group('speed', () {
    test('says it the way a person reads it', () {
      expect(kitSpeed(108e6), '108 MB/s');
      expect(kitSpeed(107.6e6), '108 MB/s');
      expect(kitSpeed(1.24e9), '1.2 GB/s');
      expect(kitSpeed(820e3), '820 KB/s');
    });

    test('a sending job shows its share and live speed', () {
      expect(job('inProgress', finished: 250, speed: 108e6).status, '25% · 108 MB/s');
    });

    test('no speed yet: only the share', () {
      expect(job('inProgress', finished: 250).status, '25%');
    });

    test('a done job shows the average, or only Done without one', () {
      expect(job('done', averageSpeed: 97e6).status, 'Done · 97 MB/s average');
      expect(job('done', averageSpeed: 0).status, 'Done');
      expect(job('done').status, 'Done');
    });

    test('live speed stays out of the other phases', () {
      expect(job('paused', speed: 108e6).status, 'Paused');
      expect(job('none', speed: 108e6).status, 'Waiting');
      expect(job('none', delete: true, speed: 108e6).status, 'Deleting from this Mac…');
    });
  });

  group('what a finished job proved (t30)', () {
    const verified = 'Verified: 12 files, 4.3 GB';
    const partial = 'Not verified: 1 of 12 files failed: A001.MOV (the copy doesn\'t match the original). 11 proved, 4.0 GB';
    const oldPeer = 'Not verified: the other computer needs the latest Boring Remote';
    const leftBehind = 'Not verified: 12 proved, 4.3 GB. Not copied: B002 (couldn\'t read this folder)';

    test('says the engine\'s words, with the average after them', () {
      expect(job('done', err: verified, averageSpeed: 97e6).status, 'Verified: 12 files, 4.3 GB · 97 MB/s average');
      expect(job('done', err: verified).status, verified);
      expect(job('done', err: oldPeer).status, oldPeer);
      expect(job('done', err: partial).status, partial);
    });

    test('Not verified is marked, Verified is not', () {
      expect(job('done', err: verified).notVerified, isFalse);
      expect(job('done', err: partial).notVerified, isTrue);
      expect(job('done', err: oldPeer).notVerified, isTrue);
      expect(job('done', err: leftBehind).notVerified, isTrue);
    });

    test('a job with no report never claims anything', () {
      expect(job('done').status, 'Done');
      expect(job('done').status, isNot(contains('Verified')));
      expect(job('done', err: 'skipped').status, 'Done');
    });

    test('cancelled and failed jobs keep their own words', () {
      expect(job('done', err: 'cancel').status, 'Cancelled');
      expect(job('error', err: 'Not enough room: this needs 4.3 GB and 1.0 GB is free').status,
          "Didn't send: Not enough room: this needs 4.3 GB and 1.0 GB is free. Drag it across to try again.");
    });

    test('at 100% and still going, it is checking the copy', () {
      expect(job('inProgress', finished: 1000, speed: 5e6).status, 'Checking the copy…');
      expect(job('inProgress', finished: 999).status, '100%');
    });

    test('a delete job ignores any report', () {
      expect(job('done', delete: true, err: oldPeer).status, 'Deleted from this Mac');
    });

    testWidgets('a Not verified row carries the warning icon and shows every word', (t) async {
      await t.pumpWidget(MaterialApp(
          home: Scaffold(
              body: TransferList(
                  jobs: [job('done', err: partial), job('done', err: verified)],
                  onCancel: (_) {},
                  onResume: (_) {},
                  onRemove: (_) {}))));
      expect(find.byIcon(Icons.error_outline), findsOneWidget);
      expect(find.byIcon(Icons.check_circle_outline), findsOneWidget);
      expect(find.text(partial), findsOneWidget);
      expect(find.text(verified), findsOneWidget);
    });
  });

  group('TransferClock averages one run', () {
    final t0 = DateTime(2026, 11, 4, 12);
    DateTime at(int seconds) => t0.add(Duration(seconds: seconds));
    const gb = 1000000000;

    test('from the first bytes to Done, not from the moment it was queued', () {
      final c = TransferClock();
      expect(c.observe(1, 'inProgress', 0, 2 * gb, at(0)), isNull); // an overwrite question
      expect(c.observe(1, 'inProgress', 100000000, 2 * gb, at(60)), isNull);
      expect(c.observe(1, 'done', 2 * gb, 2 * gb, at(79)), 100000000);
    });

    test('keeps its answer when the list looks again later', () {
      final c = TransferClock();
      c.observe(1, 'inProgress', 100000000, 2 * gb, at(0));
      final first = c.observe(1, 'done', 2 * gb, 2 * gb, at(19));
      expect(c.observe(1, 'done', 2 * gb, 2 * gb, at(500)), first);
    });

    test('Resume times the new run only', () {
      final c = TransferClock();
      c.observe(1, 'inProgress', 100000000, 2 * gb, at(0));
      c.observe(1, 'paused', 500000000, 2 * gb, at(5));
      c.observe(1, 'inProgress', 1000000000, 2 * gb, at(100));
      expect(c.observe(1, 'done', 2 * gb, 2 * gb, at(110)), 100000000);
    });

    test('a job too quick to have a sample has no average', () {
      final c = TransferClock();
      expect(c.observe(1, 'done', 1000, 1000, at(0)), isNull);
      c.observe(2, 'inProgress', 1000, 1000, at(0));
      expect(c.observe(2, 'done', 1000, 1000, at(1)), isNull); // nothing after the first sample
    });

    test('jobs are timed separately', () {
      final c = TransferClock();
      c.observe(1, 'inProgress', 100, 1100, at(0));
      c.observe(2, 'inProgress', 100, 2100, at(0));
      expect(c.observe(1, 'done', 1100, 1100, at(1)), 1000);
      expect(c.observe(2, 'done', 2100, 2100, at(1)), 2000);
    });
  });

  group('drives', () {
    ({String name, bool directory, bool link}) e(String name, {bool directory = true, bool link = false}) =>
        (name: name, directory: directory, link: link);

    test('each computer has its own place to look', () {
      expect(transferDriveRoot('Mac OS'), '/Volumes');
      expect(transferDriveRoot('Windows'), '/');
      expect(transferDriveRoot('Linux'), isNull);
      expect(transferDriveRoot(''), isNull);
    });

    test('Mac: the startup disk is the link to /, the rest live in /Volumes', () {
      final d = transferDrivesFrom('Mac OS', [e('Macintosh HD', link: true), e('T9_1_2TB')]);
      expect(d.map((x) => x.label), ['Macintosh HD', 'T9_1_2TB']);
      expect(d.map((x) => x.path), ['/', '/Volumes/T9_1_2TB']);
    });

    test('Mac: leaves out hidden folders and loose files', () {
      final d = transferDrivesFrom('Mac OS', [e('.timemachine'), e('note.txt', directory: false), e('')]);
      expect(d, isEmpty);
    });

    test('Windows: drive letters open at their root', () {
      final d = transferDrivesFrom('Windows', [e('C:'), e('E:')]);
      expect(d.map((x) => x.label), ['C:', 'E:']);
      expect(d.map((x) => x.path), ['C:\\', 'E:\\']);
    });

    Widget host(Widget w) => MaterialApp(theme: Kit.theme(), home: Scaffold(body: w));

    testWidgets('one click opens a drive, and each side has its own list', (tester) async {
      final opened = <String>[];
      await tester.pumpWidget(host(Column(children: [
        TransferDrives(load: () async => const [TransferDrive('Macintosh HD', '/')], onOpen: (p) => opened.add('this $p')),
        TransferDrives(
            load: () async => const [TransferDrive('C:', 'C:\\')], onOpen: (p) => opened.add('that $p')),
      ])));
      await tester.pump();
      await tester.tap(find.text('Macintosh HD'));
      await tester.tap(find.text('C:'));
      expect(opened, ['this /', 'that C:\\']);
    });

    testWidgets('the button looks again and finds what was plugged in', (tester) async {
      var plugged = false;
      await tester.pumpWidget(host(TransferDrives(
          load: () async => [const TransferDrive('Macintosh HD', '/'), if (plugged) const TransferDrive('T9', '/Volumes/T9')],
          onOpen: (_) {})));
      await tester.pump();
      expect(find.text('T9'), findsNothing);
      plugged = true;
      await tester.tap(find.byTooltip('Look for drives again'));
      await tester.pump();
      expect(find.text('T9'), findsOneWidget);
    });

    testWidgets('a side that can\'t list drives shows only the button', (tester) async {
      await tester.pumpWidget(host(TransferDrives(load: () async => throw 'no such folder', onOpen: (_) {})));
      await tester.pump();
      expect(find.byType(TextButton), findsNothing);
      expect(find.byTooltip('Look for drives again'), findsOneWidget);
    });
  });

  group('TransferJob reads the engine job', () {
    test('in progress: sending, with the share done', () {
      final j = job('inProgress', finished: 250, total: 1000);
      expect(j.phase, TransferPhase.sending);
      expect(j.fraction, 0.25);
      expect(j.name, 'cut.mov');
      expect(j.status, '25%');
    });

    test('direction: remote to local lands on this Mac', () {
      expect(job('none', remoteToLocal: true).toThisMac, isTrue);
      expect(job('none').toThisMac, isFalse);
    });

    test('done is done, and skipped counts as done', () {
      expect(job('done').phase, TransferPhase.done);
      expect(job('done').status, 'Done');
      expect(job('done', err: 'skipped').phase, TransferPhase.done);
    });

    test('error carries the reason', () {
      final j = job('error', err: 'Permission denied');
      expect(j.phase, TransferPhase.failed);
      expect(j.status, "Didn't send: Permission denied. Drag it across to try again.");
    });

    test('cancelled shows as stopped, not as an error', () {
      final j = job('done', err: 'cancel');
      expect(j.phase, TransferPhase.failed);
      expect(j.status, 'Cancelled');
    });

    test('waiting and paused', () {
      expect(job('none').phase, TransferPhase.waiting);
      expect(job('none').status, 'Waiting');
      expect(job('paused').phase, TransferPhase.paused);
      expect(job('paused').status, 'Paused');
    });

    test('a delete job says what it deletes and where, in plain words', () {
      // The engine marks a delete on the other side with remoteToLocal (its isRemote).
      expect(job('none', delete: true, remoteToLocal: true).status, 'Deleting from that computer…');
      expect(job('none', delete: true).status, 'Deleting from this Mac…');
      expect(job('done', delete: true, remoteToLocal: true).status, 'Deleted from that computer');
      expect(job('done', delete: true, remoteToLocal: true).phase, TransferPhase.done);
      expect(job('error', delete: true, err: 'Access denied').status, "Didn't delete: Access denied");
      expect(job('done', delete: true, err: 'cancel').status, 'Cancelled');
    });

    test('zero-size file never divides by zero', () {
      expect(job('inProgress', total: 0).fraction, 0);
    });
  });

  group('panes: drag across both ways', () {
    Widget board({required List<String> got}) => MaterialApp(
          theme: Kit.theme(),
          home: Scaffold(
            body: Row(children: [
              Expanded(
                child: TransferPane(
                  side: TransferSide.thisMac,
                  onDropFromOther: () => got.add('to this Mac'),
                  child: TransferDraggable(
                      side: TransferSide.thisMac,
                      label: 'cut.mov',
                      child: const SizedBox(height: 40, child: Text('local row'))),
                ),
              ),
              Expanded(
                child: TransferPane(
                  side: TransferSide.thatMac,
                  onDropFromOther: () => got.add('to that Mac'),
                  child: TransferDraggable(
                      side: TransferSide.thatMac,
                      label: 'notes.txt',
                      child: const SizedBox(height: 40, child: Text('remote row'))),
                ),
              ),
            ]),
          ),
        );

    Future<void> drag(WidgetTester tester, String from, Offset to) async {
      final g = await tester.startGesture(tester.getCenter(find.text(from)));
      await g.moveBy(const Offset(20, 0));
      await tester.pump();
      await g.moveTo(to);
      await tester.pump();
      await g.up();
      await tester.pumpAndSettle();
    }

    testWidgets('panes are named This Mac and That computer', (tester) async {
      await tester.pumpWidget(board(got: []));
      expect(find.text('This Mac'), findsOneWidget);
      expect(find.text('That computer'), findsOneWidget);
    });

    testWidgets('this Mac to that Mac', (tester) async {
      final got = <String>[];
      await tester.pumpWidget(board(got: got));
      await drag(tester, 'local row', tester.getCenter(find.text('remote row')));
      expect(got, ['to that Mac']);
    });

    testWidgets('that Mac to this Mac', (tester) async {
      final got = <String>[];
      await tester.pumpWidget(board(got: got));
      await drag(tester, 'remote row', tester.getCenter(find.text('local row')));
      expect(got, ['to this Mac']);
    });

    testWidgets('dropping back on the same side sends nothing', (tester) async {
      final got = <String>[];
      await tester.pumpWidget(board(got: got));
      await drag(tester, 'local row', tester.getCenter(find.text('This Mac')));
      expect(got, isEmpty);
    });
  });

  group('transfer list', () {
    Widget list(List<TransferJob> jobs,
            {void Function(int)? onCancel, void Function(int)? onResume, void Function(int)? onRemove}) =>
        MaterialApp(
          theme: Kit.theme(),
          home: Scaffold(
            body: TransferList(
              jobs: jobs,
              onCancel: onCancel ?? (_) {},
              onResume: onResume ?? (_) {},
              onRemove: onRemove ?? (_) {},
            ),
          ),
        );

    testWidgets('nothing yet: says how to send', (tester) async {
      await tester.pumpWidget(list(const []));
      expect(find.text('Drag files from one computer to the other.'), findsOneWidget);
    });

    testWidgets('sending shows a progress bar and Stop', (tester) async {
      final got = <int>[];
      await tester.pumpWidget(list([job('inProgress', finished: 500)], onCancel: got.add));
      expect(find.text('cut.mov'), findsOneWidget);
      expect(find.text('50%'), findsOneWidget);
      final bar = tester.widget<LinearProgressIndicator>(find.byType(LinearProgressIndicator));
      expect(bar.value, 0.5);
      await tester.tap(find.byTooltip('Stop'));
      expect(got, [7]);
    });

    testWidgets('sending shows the live speed, done the average', (tester) async {
      await tester.pumpWidget(list([
        job('inProgress', finished: 500, speed: 108e6),
      ]));
      expect(find.text('50% · 108 MB/s'), findsOneWidget);
      await tester.pumpWidget(list([job('done', averageSpeed: 97e6)]));
      expect(find.text('Done · 97 MB/s average'), findsOneWidget);
    });

    testWidgets('done shows Done and no bar', (tester) async {
      final got = <int>[];
      await tester.pumpWidget(list([job('done')], onRemove: got.add));
      expect(find.text('Done'), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsNothing);
      await tester.tap(find.byTooltip('Clear'));
      expect(got, [7]);
    });

    testWidgets('error shows the reason', (tester) async {
      await tester.pumpWidget(list([job('error', err: 'Disk full')]));
      expect(find.text("Didn't send: Disk full. Drag it across to try again."), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsNothing);
    });

    testWidgets('delete jobs are listed too, with a bin, and can be stopped', (tester) async {
      final got = <int>[];
      await tester.pumpWidget(list([job('none', delete: true, remoteToLocal: true)], onCancel: got.add));
      expect(find.text('cut.mov'), findsOneWidget);
      expect(find.text('Deleting from that computer…'), findsOneWidget);
      expect(find.byIcon(Icons.delete_outline), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsNothing);
      await tester.tap(find.byTooltip('Stop'));
      expect(got, [7]);
    });

    testWidgets('paused offers Resume', (tester) async {
      final got = <int>[];
      await tester.pumpWidget(list([job('paused')], onResume: got.add));
      await tester.tap(find.byTooltip('Resume'));
      expect(got, [7]);
    });
  });
}
