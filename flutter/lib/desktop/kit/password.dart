import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'kit.dart';

/// Server option: "Y" while this computer's Unattended Password is one Boring Remote made
/// (src/password_lock.rs GENERATED_OPTION). Only then does it register with the Hosted servers,
/// so a Machine ID reaches it (1.8 ticket 09).
const kBoringPasswordGenerated = 'boring-password-generated';

/// Every word the password panel shows, in one place, for review (humanizer).
const passwordCopy = <String, String>{
  'make': 'Make a password',
  'remake': 'Make a new password',
  'typed': 'This computer has a password you typed in an older version. Make a new one here '
      'so your other computers can reach it from anywhere, not just on this network or over Tailscale.',
  'confirm.title': 'Replace the password?',
  'confirm.body': 'Every computer that saved the old one will need the new one.',
  'confirm.trusted': 'Also remove every Trusted Controller',
  'confirm.replace': 'Replace',
  'confirm.cancel': 'Cancel',
  'shown.title': 'Your new password',
  'shown.body': "Write it down or save it in your password manager now. It won't be shown again.",
  'copy': 'Copy',
  'copied': 'Copied. It leaves the clipboard in a minute.',
  'saved.button': "I've saved it",
  'saved': 'Password saved.',
  'failed': "Couldn't set the password. If someone is connected to this computer, "
      'try again after they disconnect.',
};

/// The Unattended Password (1.8 ticket 05): Boring Remote makes it (16+ characters from the OS's
/// random source), shows it here once with Copy, and keeps only its salted hash, so nobody can read
/// it back later. Replacing one asks first, and can remove every Trusted Controller with it.
/// Bridge-free: [generate] asks the service to set a new one and returns it, or '' if it said no.
class UnattendedPasswordPanel extends StatefulWidget {
  static const makeKey = Key('password-make');
  static const shownKey = Key('password-shown');

  /// A password is set now (made here, or typed in 1.7).
  final bool passwordSet;

  /// The one set now was made here (Hosted access is on).
  final bool generated;

  final Future<String> Function() generate;

  /// Replace's "Also remove every Trusted Controller"; null hides the choice.
  final Future<void> Function()? removeTrusted;

  /// After "I've saved it".
  final VoidCallback? onSaved;

  final Future<void> Function(String text) copyText;
  final Future<String?> Function() readClipboard;

  const UnattendedPasswordPanel({
    super.key,
    required this.passwordSet,
    required this.generated,
    required this.generate,
    this.removeTrusted,
    this.onSaved,
    this.copyText = _copy,
    this.readClipboard = _paste,
  });

  static Future<void> _copy(String text) => Clipboard.setData(ClipboardData(text: text));
  static Future<String?> _paste() async => (await Clipboard.getData(Clipboard.kTextPlain))?.text;

  @override
  State<UnattendedPasswordPanel> createState() => _UnattendedPasswordPanelState();
}

enum _Step { idle, confirm, shown, saved }

class _UnattendedPasswordPanelState extends State<UnattendedPasswordPanel> {
  _Step _step = _Step.idle;
  String _password = '';
  bool _removeTrusted = false, _copied = false, _busy = false;
  String? _error;
  Timer? _clear;

  @override
  void dispose() {
    _clear?.cancel();
    super.dispose();
  }

  bool get _set => widget.passwordSet || _step == _Step.saved;

  Future<void> _make() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final pass = await widget.generate();
    if (!mounted) return;
    if (pass.isEmpty) {
      setState(() {
        _busy = false;
        _step = _Step.idle;
        _error = passwordCopy['failed'];
      });
      return;
    }
    if (_removeTrusted) await widget.removeTrusted?.call();
    if (!mounted) return;
    setState(() {
      _busy = false;
      _password = pass;
      _copied = false;
      _step = _Step.shown;
    });
  }

  /// Copies it, then empties the clipboard after a minute if it still holds it.
  Future<void> _copyIt() async {
    final pass = _password;
    await widget.copyText(pass);
    if (mounted) setState(() => _copied = true);
    _clear?.cancel();
    _clear = Timer(const Duration(seconds: 60), () async {
      if (await widget.readClipboard() == pass) await widget.copyText('');
    });
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final w = passwordCopy;
    switch (_step) {
      case _Step.shown:
        return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(w['shown.title']!, style: t.titleMedium),
          const SizedBox(height: Kit.s2),
          SelectableText(_password, key: UnattendedPasswordPanel.shownKey,
              style: t.headlineSmall?.copyWith(fontFamily: 'monospace')),
          const SizedBox(height: Kit.s2),
          Text(w['shown.body']!),
          if (_copied) ...[const SizedBox(height: Kit.s2), Text(w['copied']!, style: t.bodySmall)],
          const SizedBox(height: Kit.s3),
          Row(children: [
            OutlinedButton(onPressed: _copyIt, child: Text(w['copy']!)),
            const SizedBox(width: Kit.s2),
            FilledButton(
              onPressed: () {
                setState(() {
                  _password = '';
                  _step = _Step.saved;
                });
                widget.onSaved?.call();
              },
              child: Text(w['saved.button']!),
            ),
          ]),
        ]);
      case _Step.confirm:
        return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(w['confirm.title']!, style: t.titleMedium),
          const SizedBox(height: Kit.s2),
          Text(w['confirm.body']!),
          if (widget.removeTrusted != null)
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              value: _removeTrusted,
              onChanged: (v) => setState(() => _removeTrusted = v ?? false),
              title: Text(w['confirm.trusted']!),
            ),
          const SizedBox(height: Kit.s2),
          Row(children: [
            FilledButton(onPressed: _busy ? null : _make, child: Text(w['confirm.replace']!)),
            const SizedBox(width: Kit.s2),
            TextButton(
              onPressed: _busy ? null : () => setState(() => _step = _Step.idle),
              child: Text(w['confirm.cancel']!),
            ),
          ]),
        ]);
      case _Step.idle:
      case _Step.saved:
        return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          if (_step == _Step.saved)
            Row(children: [
              const Icon(Icons.check_circle, color: Kit.ok),
              const SizedBox(width: Kit.s2),
              Text(w['saved']!),
            ])
          else if (widget.passwordSet && !widget.generated)
            Text(w['typed']!),
          if (_error != null) ...[const SizedBox(height: Kit.s2), Text(_error!, style: t.bodyMedium)],
          const SizedBox(height: Kit.s3),
          Align(
            alignment: Alignment.centerLeft,
            child: (_set ? OutlinedButton.new : FilledButton.new)(
              key: UnattendedPasswordPanel.makeKey,
              onPressed: _busy
                  ? null
                  : () {
                      _removeTrusted = false;
                      if (_set) {
                        setState(() => _step = _Step.confirm);
                      } else {
                        _make();
                      }
                    },
              child: Text(_set ? w['remake']! : w['make']!),
            ),
          ),
        ]);
    }
  }
}
