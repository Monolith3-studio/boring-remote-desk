import 'package:flutter/material.dart';

import 'kit.dart';

/// File Transfer in the kit (v1.7 ticket 08). Bridge-free: the page maps the engine's
/// jobs into [TransferJob] and passes callbacks; the engine underneath is unchanged.

enum TransferSide { thisMac, thatMac }

enum TransferPhase { waiting, sending, paused, done, failed }

class TransferJob {
  const TransferJob({
    required this.id,
    required this.name,
    required this.toThisMac,
    required this.phase,
    required this.finished,
    required this.total,
    this.error = '',
  });

  final int id;
  final String name;
  final bool toThisMac;
  final TransferPhase phase;
  final int finished;
  final int total;
  final String error;

  /// [state] is the engine's JobState name (none, inProgress, done, error, paused);
  /// [err] its error text, where 'cancel' and 'skipped' are not real errors.
  factory TransferJob.fromEngine({
    required int id,
    required String path,
    required bool remoteToLocal,
    required String state,
    required int finished,
    required int total,
    String err = '',
  }) {
    final TransferPhase phase;
    var error = '';
    if (state == 'done' && err == 'cancel') {
      phase = TransferPhase.failed;
      error = 'cancel';
    } else if (state == 'done') {
      phase = TransferPhase.done;
    } else if (state == 'error') {
      phase = TransferPhase.failed;
      error = err.isEmpty ? 'Unknown error' : err;
    } else if (state == 'inProgress') {
      phase = TransferPhase.sending;
    } else if (state == 'paused') {
      phase = TransferPhase.paused;
    } else {
      phase = TransferPhase.waiting;
    }
    final parts = path.split(RegExp(r'[/\\]')).where((p) => p.isNotEmpty);
    return TransferJob(
      id: id,
      name: parts.isEmpty ? path : parts.last,
      toThisMac: remoteToLocal,
      phase: phase,
      finished: finished,
      total: total,
      error: error,
    );
  }

  double get fraction => total > 0 ? (finished / total).clamp(0.0, 1.0) : 0;

  String get status {
    switch (phase) {
      case TransferPhase.waiting:
        return 'Waiting';
      case TransferPhase.sending:
        return '${(fraction * 100).round()}%';
      case TransferPhase.paused:
        return 'Paused';
      case TransferPhase.done:
        return 'Done';
      case TransferPhase.failed:
        return error == 'cancel' ? 'Cancelled' : "Didn't send: $error";
    }
  }
}

/// What a row carries while it is dragged: only which side it left from.
/// The page sends that side's selection, so the engine path is the Send button's.
class TransferDrag {
  const TransferDrag(this.from);
  final TransferSide from;
}

/// One side of the board. Takes drops from the other side only.
class TransferPane extends StatelessWidget {
  const TransferPane({
    super.key,
    required this.side,
    required this.onDropFromOther,
    required this.child,
  });

  final TransferSide side;
  final VoidCallback onDropFromOther;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return DragTarget<TransferDrag>(
      onWillAcceptWithDetails: (d) => d.data.from != side,
      onAcceptWithDetails: (_) => onDropFromOther(),
      builder: (context, hovering, _) => AnimatedContainer(
        duration: const Duration(milliseconds: 120),
        margin: const EdgeInsets.all(Kit.s3),
        decoration: BoxDecoration(
          color: Kit.panel,
          borderRadius: BorderRadius.circular(Kit.radius),
          border: Border.all(
            color: hovering.isNotEmpty ? Kit.coral : Kit.line,
            width: hovering.isNotEmpty ? 2 : 1,
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(Kit.s5, Kit.s4, Kit.s5, 0),
              child: Text(
                side == TransferSide.thisMac ? 'This Mac' : 'That Mac',
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    color: Kit.paper, fontWeight: FontWeight.w700),
              ),
            ),
            Expanded(child: child),
          ],
        ),
      ),
    );
  }
}

/// Wraps a file row so it can be dragged to the other pane.
class TransferDraggable extends StatelessWidget {
  const TransferDraggable({
    super.key,
    required this.side,
    required this.label,
    required this.child,
    this.onDragStarted,
  });

  final TransferSide side;
  final String label;
  final Widget child;
  final VoidCallback? onDragStarted;

  @override
  Widget build(BuildContext context) {
    return Draggable<TransferDrag>(
      data: TransferDrag(side),
      onDragStarted: onDragStarted,
      feedback: Material(
        color: Colors.transparent,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: Kit.s4, vertical: Kit.s2),
          decoration: BoxDecoration(
            color: Kit.glass,
            borderRadius: BorderRadius.circular(Kit.radius),
            border: Border.all(color: Kit.coral),
          ),
          child: Text(label, style: const TextStyle(color: Kit.paper, fontSize: 14)),
        ),
      ),
      childWhenDragging: Opacity(opacity: 0.4, child: child),
      child: child,
    );
  }
}

/// The job list: progress while sending, Done, or the reason it didn't send.
class TransferList extends StatelessWidget {
  const TransferList({
    super.key,
    required this.jobs,
    required this.onCancel,
    required this.onResume,
    required this.onRemove,
  });

  final List<TransferJob> jobs;
  final void Function(int id) onCancel;
  final void Function(int id) onResume;
  final void Function(int id) onRemove;

  @override
  Widget build(BuildContext context) {
    final body = jobs.isEmpty
        ? const Center(
            child: Padding(
              padding: EdgeInsets.all(Kit.s5),
              child: Text('Drag files from one Mac to the other.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Kit.muted, fontSize: 15)),
            ),
          )
        : ListView.separated(
            padding: const EdgeInsets.all(Kit.s3),
            itemCount: jobs.length,
            separatorBuilder: (_, __) => const SizedBox(height: Kit.s2),
            itemBuilder: (context, i) => _row(context, jobs[i]),
          );
    return Container(
      margin: const EdgeInsets.all(Kit.s3),
      decoration: BoxDecoration(
        color: Kit.panel,
        borderRadius: BorderRadius.circular(Kit.radius),
        border: Border.all(color: Kit.line),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Padding(
            padding: EdgeInsets.fromLTRB(Kit.s5, Kit.s4, Kit.s5, 0),
            child: Text('Transfers',
                style: TextStyle(color: Kit.paper, fontSize: 16, fontWeight: FontWeight.w700)),
          ),
          Expanded(child: body),
        ],
      ),
    );
  }

  Widget _row(BuildContext context, TransferJob j) {
    final failed = j.phase == TransferPhase.failed;
    final icon = switch (j.phase) {
      TransferPhase.done => Icons.check_circle_outline,
      TransferPhase.failed => Icons.error_outline,
      _ => j.toThisMac ? Icons.arrow_back : Icons.arrow_forward,
    };
    final active = j.phase == TransferPhase.sending || j.phase == TransferPhase.waiting;
    Widget action(String tip, IconData i, void Function(int) f) => IconButton(
          tooltip: tip,
          icon: Icon(i, size: 18, color: Kit.muted),
          onPressed: () => f(j.id),
        );
    return Container(
      padding: const EdgeInsets.fromLTRB(Kit.s3, Kit.s2, Kit.s1, Kit.s2),
      decoration: BoxDecoration(
        color: Kit.glass,
        borderRadius: BorderRadius.circular(Kit.radius),
      ),
      child: Row(
        children: [
          Icon(icon, size: 20, color: failed ? Kit.coral : Kit.muted),
          const SizedBox(width: Kit.s3),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(j.name,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: Kit.paper, fontSize: 15)),
                const SizedBox(height: Kit.s1),
                Text(j.status,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: Kit.muted, fontSize: 13)),
                if (j.phase == TransferPhase.sending)
                  Padding(
                    padding: const EdgeInsets.only(top: Kit.s2),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(2),
                      child: LinearProgressIndicator(
                        value: j.fraction,
                        minHeight: 4,
                        color: Kit.coral,
                        backgroundColor: Kit.line,
                      ),
                    ),
                  ),
              ],
            ),
          ),
          if (j.phase == TransferPhase.paused) action('Resume', Icons.play_arrow, onResume),
          active || j.phase == TransferPhase.paused
              ? action('Stop', Icons.close, onCancel)
              : action('Clear', Icons.close, onRemove),
        ],
      ),
    );
  }
}
