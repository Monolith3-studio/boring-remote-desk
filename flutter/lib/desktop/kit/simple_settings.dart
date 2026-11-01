import 'package:flutter/material.dart';

import 'kit.dart';

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
            ? 'Set. Trusted people can get in with no one here.'
            : 'Not set. Someone has to approve each connection here.'),
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
          subtitle: Text('Reachable after a restart, before anyone opens the app.', style: t.bodySmall),
          value: widget.startAtLogin,
          onChanged: widget.onStartAtLogin,
          contentPadding: EdgeInsets.zero,
        ),
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
