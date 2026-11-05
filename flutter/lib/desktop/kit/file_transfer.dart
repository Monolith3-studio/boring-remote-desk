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
    this.delete = false,
    this.speed = 0,
    this.averageSpeed,
  });

  final int id;
  final String name;
  final bool toThisMac;
  final TransferPhase phase;
  final int finished;
  final int total;
  final String error;

  /// A delete (the engine's deleteFile / deleteDir job), not a transfer. For a delete,
  /// [toThisMac] means the file was on that Mac (the engine's isRemote).
  final bool delete;

  /// What the engine reports while sending, in bytes per second.
  final double speed;

  /// The whole run's average, once it's done. See [TransferClock].
  final double? averageSpeed;

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
    bool delete = false,
    double speed = 0,
    double? averageSpeed,
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
      delete: delete,
      speed: speed,
      averageSpeed: averageSpeed,
    );
  }

  double get fraction => total > 0 ? (finished / total).clamp(0.0, 1.0) : 0;

  String get status {
    if (delete) return _deleteStatus;
    switch (phase) {
      case TransferPhase.waiting:
        return 'Waiting';
      case TransferPhase.sending:
        final percent = '${(fraction * 100).round()}%';
        return speed > 0 ? '$percent · ${kitSpeed(speed)}' : percent;
      case TransferPhase.paused:
        return 'Paused';
      case TransferPhase.done:
        final average = averageSpeed ?? 0;
        return average > 0 ? 'Done · ${kitSpeed(average)} average' : 'Done';
      case TransferPhase.failed:
        return error == 'cancel' ? 'Cancelled' : "Didn't send: $error. Drag it across to try again.";
    }
  }

  String get _deleteStatus {
    final where = toThisMac ? 'that computer' : 'this ${KitWords.one}';
    switch (phase) {
      case TransferPhase.done:
        return 'Deleted from $where';
      case TransferPhase.failed:
        return error == 'cancel' ? 'Cancelled' : "Didn't delete: $error";
      default:
        return 'Deleting from $where…';
    }
  }
}

/// 108 MB/s, the decimal megabytes the OS's own file windows count in.
String kitSpeed(double bytesPerSecond) {
  if (bytesPerSecond >= 1e9) return '${(bytesPerSecond / 1e9).toStringAsFixed(1)} GB/s';
  if (bytesPerSecond >= 1e6) return '${(bytesPerSecond / 1e6).round()} MB/s';
  return '${(bytesPerSecond / 1e3).round()} KB/s';
}

/// Works out a job's average speed from what the list sees of it. It starts timing at the first
/// bytes, so an overwrite question before them doesn't count, and Resume starts a new run.
class TransferClock {
  final _runs = <int, _TransferRun>{};

  /// Call on every look at the job. The average comes back once [state] is 'done'.
  double? observe(int id, String state, int finished, int total, DateTime now) {
    final run = _runs[id];
    if (state == 'inProgress') {
      if (finished <= 0) return null;
      if (run == null || run.ended != null) {
        _runs[id] = _TransferRun(now, finished);
      }
      return null;
    }
    if (state != 'done') {
      _runs.remove(id);
      return null;
    }
    if (run == null) return null;
    run.ended ??= now;
    final millis = run.ended!.difference(run.started).inMilliseconds;
    if (millis <= 0 || total <= run.startedAt) return null;
    return (total - run.startedAt) * 1000 / millis;
  }
}

class _TransferRun {
  _TransferRun(this.started, this.startedAt);
  final DateTime started;
  final int startedAt;
  DateTime? ended;
}

/// One thing the drive list can open.
class TransferDrive {
  const TransferDrive(this.label, this.path);
  final String label;
  final String path;
}

/// Where a computer keeps its list of drives, or null when it has no such place.
/// [platform] is the engine's name for it (kPeerPlatformWindows, kPeerPlatformMacOS).
String? transferDriveRoot(String platform) {
  switch (platform) {
    case 'Windows':
      return '/';
    case 'Mac OS':
      return '/Volumes';
  }
  return null;
}

/// The engine's listing of [transferDriveRoot] as drives. On a Mac the startup disk is the one
/// link in /Volumes, and it points at /.
List<TransferDrive> transferDrivesFrom(
    String platform, Iterable<({String name, bool directory, bool link})> entries) {
  final drives = <TransferDrive>[];
  for (final e in entries) {
    if (e.name.isEmpty || e.name.startsWith('.') || !e.directory) continue;
    if (platform == 'Windows') {
      drives.add(TransferDrive(e.name, '${e.name}\\'));
    } else {
      drives.add(TransferDrive(e.name, e.link ? '/' : '/Volumes/${e.name}'));
    }
  }
  return drives;
}

/// One side's drives, one click each. Each side has its own; [load] is asked again by its button.
class TransferDrives extends StatefulWidget {
  const TransferDrives({super.key, required this.load, required this.onOpen});

  final Future<List<TransferDrive>> Function() load;
  final void Function(String path) onOpen;

  @override
  State<TransferDrives> createState() => _TransferDrivesState();
}

class _TransferDrivesState extends State<TransferDrives> {
  var _drives = const <TransferDrive>[];

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    final List<TransferDrive> drives;
    try {
      drives = await widget.load();
    } catch (_) {
      return; // keeps what it had: typing a path in the location bar still works
    }
    if (mounted) setState(() => _drives = drives);
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: Kit.s2),
      child: Wrap(
        spacing: Kit.s2,
        runSpacing: Kit.s1,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          for (final d in _drives)
            TextButton.icon(
              onPressed: () => widget.onOpen(d.path),
              icon: const Icon(Icons.storage_outlined, size: 16, color: Kit.muted),
              label: Text(d.label, style: const TextStyle(color: Kit.paper, fontSize: 13)),
            ),
          IconButton(
            tooltip: 'Look for drives again',
            onPressed: _reload,
            icon: const Icon(Icons.refresh, size: 16, color: Kit.muted),
          ),
        ],
      ),
    );
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
                side == TransferSide.thisMac ? 'This ${KitWords.one}' : 'That computer',
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
        ? Center(
            child: Padding(
              padding: const EdgeInsets.all(Kit.s5),
              child: Text('Drag files from one computer to the other.',
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Kit.muted, fontSize: 15)),
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
      _ => j.delete ? Icons.delete_outline : (j.toThisMac ? Icons.arrow_back : Icons.arrow_forward),
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
