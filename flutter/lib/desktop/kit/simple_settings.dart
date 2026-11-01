import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'kit.dart';

/// Where a buyer gets Boring Remote for another computer (ticket 15).
const kDownloadUrl = 'https://theboringremote.com/download';

/// One row under Advanced: a label and where it goes.
class SettingsLink {
  final String label;
  final VoidCallback onTap;
  const SettingsLink({required this.label, required this.onTap});
}

/// Settings (v1.7): one page. This Mac's name, Unattended Password, start at login, updates;
/// everything else sits behind Advanced. Bridge-free; the settings page passes data and callbacks.
class SimpleSettings extends StatefulWidget {
  static const nameKey = Key('simple-settings-name');
  static const passwordKey = Key('simple-settings-password');

  /// Same rule as the full settings' password dialog. A blank or default password never ships (ADR 0002).
  static bool strongEnough(String p) =>
      p.length >= 8 &&
      p.contains(RegExp(r'[0-9]')) &&
      p.contains(RegExp(r'[A-Z]')) &&
      p.contains(RegExp(r'[a-z]'));

  final String macName;
  final Future<void> Function(String name) onRename;

  final bool passwordSet;
  final Future<bool> Function(String password) setPassword;

  final bool startAtLogin;
  final void Function(bool on) onStartAtLogin;

  final bool checkUpdates;
  final void Function(bool on) onCheckUpdates;

  /// Advanced entries, in order (all settings, Trusted Controllers, tabs vs windows...).
  final List<SettingsLink> advanced;

  /// Opens Setup again (v1.7 t06); null hides the button.
  final VoidCallback? onRunSetup;

  /// Opens a web page (the download page); null hides the Download button.
  final void Function(String url)? openUrl;

  const SimpleSettings({
    super.key,
    required this.macName,
    required this.onRename,
    required this.passwordSet,
    required this.setPassword,
    required this.startAtLogin,
    required this.onStartAtLogin,
    required this.checkUpdates,
    required this.onCheckUpdates,
    this.advanced = const [],
    this.onRunSetup,
    this.openUrl,
  });

  @override
  State<SimpleSettings> createState() => _SimpleSettingsState();
}

class _SimpleSettingsState extends State<SimpleSettings> {
  late final _name = TextEditingController(text: widget.macName);
  final _password = TextEditingController();
  bool _editingPassword = false;
  bool? _savedPassword; // set once a save here succeeds, until the page passes a new passwordSet
  String? _passwordError;
  bool _confirmStop = false; // Start at login off: say what it stops before it does
  bool _linkCopied = false;

  @override
  void didUpdateWidget(SimpleSettings old) {
    super.didUpdateWidget(old);
    if (old.passwordSet != widget.passwordSet) _savedPassword = null;
  }

  @override
  void dispose() {
    _name.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _savePassword() async {
    final p = _password.text;
    if (!SimpleSettings.strongEnough(p)) {
      setState(() => _passwordError = 'At least 8 characters, with a capital, a small letter and a number.');
      return;
    }
    final ok = await widget.setPassword(p);
    if (!mounted) return;
    setState(() {
      if (ok) {
        _password.clear();
        _editingPassword = false;
        _savedPassword = true;
        _passwordError = null;
      } else {
        _passwordError = "Couldn't save that password. Try again.";
      }
    });
  }

  Widget _passwordSection(TextTheme t) {
    final isSet = _savedPassword ?? widget.passwordSet;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Unattended Password', style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        Text(isSet
            ? 'Set. Your other ${KitWords.many} can get in with it when no one is here.'
            : 'Not set. Someone has to be at this ${KitWords.one} to click Allow each time.'),
        const SizedBox(height: Kit.s2),
        if (!_editingPassword)
          OutlinedButton(
            onPressed: () => setState(() => _editingPassword = true),
            child: Text(isSet ? 'Change password' : 'Set password'),
          )
        else ...[
          TextField(
            key: SimpleSettings.passwordKey,
            controller: _password,
            obscureText: true,
            autofocus: true,
            decoration: const InputDecoration(hintText: 'New Unattended Password'),
            onSubmitted: (_) => _savePassword(),
          ),
          if (_passwordError != null) ...[
            const SizedBox(height: Kit.s2),
            Text(_passwordError!, style: t.bodySmall),
          ],
          const SizedBox(height: Kit.s2),
          Row(children: [
            OutlinedButton(onPressed: _savePassword, child: const Text('Save password')),
            const SizedBox(width: Kit.s2),
            TextButton(
              onPressed: () => setState(() {
                _password.clear();
                _editingPassword = false;
                _passwordError = null;
              }),
              child: const Text('Cancel'),
            ),
          ]),
        ],
      ],
    );
  }

  /// Ticket 15: get Boring Remote onto the next computer in a couple of minutes.
  Widget _anotherSection(TextTheme t) {
    final one = KitWords.one;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Set up another $one', style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        Text('1. On the other $one, open theboringremote.com/download and download Boring Remote.'),
        const SizedBox(height: Kit.s1),
        const Text('2. Open it and follow the three setup steps.'),
        const SizedBox(height: Kit.s1),
        Text("3. You'll see it by name on this $one's Home screen when both are on the same network."),
        const SizedBox(height: Kit.s3),
        Wrap(spacing: Kit.s2, runSpacing: Kit.s2, crossAxisAlignment: WrapCrossAlignment.center, children: [
          if (widget.openUrl != null)
            OutlinedButton(onPressed: () => widget.openUrl!(kDownloadUrl), child: const Text('Download Boring Remote')),
          TextButton(
            onPressed: () async {
              await Clipboard.setData(const ClipboardData(text: kDownloadUrl));
              if (mounted) setState(() => _linkCopied = true);
            },
            child: const Text('Copy the link'),
          ),
          if (_linkCopied) Text('Link copied.', style: t.bodySmall),
        ]),
      ],
    );
  }

  void _rename(String text) {
    final n = text.trim();
    if (n.isNotEmpty) widget.onRename(n);
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return ListView(
      padding: const EdgeInsets.all(Kit.s6),
      children: [
        Text('Settings', style: t.headlineSmall),
        const SizedBox(height: Kit.s5),
        Text("This ${KitWords.one}'s name", style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        TextField(
          key: SimpleSettings.nameKey,
          controller: _name,
          decoration: InputDecoration(hintText: 'The name other ${KitWords.many} see'),
          onSubmitted: _rename,
        ),
        const SizedBox(height: Kit.s6),
        _passwordSection(t),
        const SizedBox(height: Kit.s5),
        SwitchListTile(
          title: const Text('Start at login'),
          subtitle: Text('Keeps this ${KitWords.one} open to your other ${KitWords.many}, even after a restart.',
              style: t.bodySmall),
          value: widget.startAtLogin && !_confirmStop,
          onChanged: (on) => on ? widget.onStartAtLogin(true) : setState(() => _confirmStop = true),
          contentPadding: EdgeInsets.zero,
        ),
        if (_confirmStop) ...[
          // Off stops the service now, not just at the next login: there is no way to drop only the
          // login item (v1.7 review), so the buyer reads exactly that before it happens.
          Text("If you turn this off, your other ${KitWords.many} can't get into this one any more, starting now. "
              'Turn it back on to let them in again. Your ${KitWords.one} may ask you to confirm, and Boring Remote '
              'may close and open again.'),
          const SizedBox(height: Kit.s2),
          Row(children: [
            OutlinedButton(
              onPressed: () {
                setState(() => _confirmStop = false);
                widget.onStartAtLogin(false);
              },
              child: const Text('Turn off'),
            ),
            const SizedBox(width: Kit.s2),
            TextButton(onPressed: () => setState(() => _confirmStop = false), child: const Text('Keep it on')),
          ]),
          const SizedBox(height: Kit.s3),
        ],
        SwitchListTile(
          title: const Text('Check for updates'),
          value: widget.checkUpdates,
          onChanged: widget.onCheckUpdates,
          contentPadding: EdgeInsets.zero,
        ),
        if (widget.onRunSetup != null) ...[
          const SizedBox(height: Kit.s3),
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton(onPressed: widget.onRunSetup, child: const Text('Run Setup again')),
          ),
        ],
        const SizedBox(height: Kit.s6),
        _anotherSection(t),
        if (widget.advanced.isNotEmpty) ...[
          const SizedBox(height: Kit.s5),
          Text('Advanced', style: t.bodySmall),
          const SizedBox(height: Kit.s2),
          for (final l in widget.advanced)
            ListTile(
              title: Text(l.label),
              trailing: const Icon(Icons.chevron_right),
              contentPadding: EdgeInsets.zero,
              hoverColor: Kit.glass,
              onTap: l.onTap,
            ),
        ],
      ],
    );
  }
}
