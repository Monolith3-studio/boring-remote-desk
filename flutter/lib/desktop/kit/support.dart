import 'package:flutter/material.dart';

import 'access.dart';
import 'kit.dart';

/// Every word Help and the crash notice show, in one place for review (humanizer).
class SupportWords {
  SupportWords._();
  static const title = 'Help';
  static const what = 'Something not working? Save a support file and send it to whoever helps you. '
      'Passwords and keys are left out.';
  static const save = 'Save a support file';
  static const saving = 'Saving…';
  static String saved(String name) => 'Saved to your Desktop: $name';
  static const failed = "Couldn't save the support file. Try again.";
  static const crashed = 'Boring Remote closed unexpectedly last time.';
  static const notNow = 'Not now';
}

/// The Access rows for the support file, one "label: yes|no" line each. A read that fails is no.
Future<String> accessReport(List<AccessCheck> checks) async {
  final ok = await Future.wait(checks.map((c) => c.read().catchError((_) => false)));
  return [for (var i = 0; i < checks.length; i++) '${checks[i].label}: ${ok[i] ? 'yes' : 'no'}'].join('\n');
}

String _fileName(String path) => path.split(RegExp(r'[/\\]')).last;

/// The Save button and what it says after. [save] makes the zip and returns its path, '' if it
/// failed. One zip at a time.
class _SaveButton extends StatefulWidget {
  final Future<String> Function() save;
  final VoidCallback? onSaved;
  final Widget? trailing;
  const _SaveButton({required this.save, this.onSaved, this.trailing});

  @override
  State<_SaveButton> createState() => _SaveButtonState();
}

class _SaveButtonState extends State<_SaveButton> {
  bool _saving = false;
  String? _said;

  Future<void> _go() async {
    if (_saving) return;
    setState(() {
      _saving = true;
      _said = null;
    });
    String path;
    try {
      path = await widget.save();
    } catch (e) {
      debugPrint('Support file: $e');
      path = '';
    }
    if (!mounted) return;
    setState(() {
      _saving = false;
      _said = path.isEmpty ? SupportWords.failed : SupportWords.saved(_fileName(path));
    });
    if (path.isNotEmpty) widget.onSaved?.call();
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Wrap(spacing: Kit.s2, runSpacing: Kit.s2, crossAxisAlignment: WrapCrossAlignment.center, children: [
      OutlinedButton(onPressed: _go, child: Text(_saving ? SupportWords.saving : SupportWords.save)),
      if (widget.trailing != null && _said == null) widget.trailing!,
      if (_said != null) Text(_said!, style: t.bodySmall),
    ]);
  }
}

/// Settings' Help: one line, one button. The zip lands on the Desktop.
class SupportSection extends StatelessWidget {
  final Future<String> Function() save;
  const SupportSection({super.key, required this.save});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(SupportWords.title, style: t.bodySmall),
      const SizedBox(height: Kit.s2),
      const Text(SupportWords.what),
      const SizedBox(height: Kit.s2),
      _SaveButton(save: save),
    ]);
  }
}

/// Home's notice after Boring Remote closed unexpectedly: one calm line and the Save button.
/// [crashed] is read once. Saving or Not now calls [onDone], so these crashes aren't offered again.
class CrashNotice extends StatefulWidget {
  final bool Function() crashed;
  final Future<String> Function() save;
  final VoidCallback onDone;
  const CrashNotice({super.key, required this.crashed, required this.save, required this.onDone});

  @override
  State<CrashNotice> createState() => _CrashNoticeState();
}

class _CrashNoticeState extends State<CrashNotice> {
  late bool _show = _read();

  bool _read() {
    try {
      return widget.crashed();
    } catch (e) {
      debugPrint('Crash notice: $e');
      return false;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!_show) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: Kit.s2),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          const Icon(Icons.info_outline, color: Kit.muted),
          const SizedBox(width: Kit.s2),
          const Expanded(child: Text(SupportWords.crashed)),
        ]),
        const SizedBox(height: Kit.s2),
        _SaveButton(
          save: widget.save,
          onSaved: widget.onDone,
          trailing: TextButton(
            onPressed: () {
              setState(() => _show = false);
              widget.onDone();
            },
            child: const Text(SupportWords.notNow),
          ),
        ),
      ]),
    );
  }
}
