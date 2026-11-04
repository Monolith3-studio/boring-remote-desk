import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/kit.dart';
import 'package:flutter_hbb/desktop/kit/file_transfer.dart';

TransferJob job(String state,
        {int finished = 0, int total = 1000, String err = '', bool remoteToLocal = false, bool delete = false}) =>
    TransferJob.fromEngine(
        id: 7,
        path: '/Users/j/Movies/cut.mov',
        remoteToLocal: remoteToLocal,
        state: state,
        finished: finished,
        total: total,
        err: err,
        delete: delete);

void main() {
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
