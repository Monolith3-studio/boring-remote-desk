import 'package:flutter/material.dart';

import 'kit.dart';

/// Every word the Windows install screen shows, in one place for review (v1.7 review).
class InstallWords {
  InstallWords._();
  static const title = 'Install Boring Remote';
  static const body = 'It installs like any other app. '
      'When Windows asks if Boring Remote can make changes to this computer, click Yes.';
  static const where = 'Install in';
  static const change = 'Change…';
  static const startMenu = 'Add it to the Start menu';
  static const desktopIcon = 'Put an icon on the desktop';
  static const printer = 'Add the Boring Remote printer';
  static const printerWhy = 'Someone controlling this computer can print on the printer where they sit.';
  static const licence = 'Installing means you agree to the license.';
  static const readLicence = 'Read the license';
  static const install = 'Install';
  static const cancel = 'Cancel';
  static const tryIt = 'Try it without installing';
  static const installing = 'Installing… If Windows asks, click Yes.';
}

/// The Windows install screen in the kit. Bridge-free: install_page.dart passes the path field,
/// the three choices and what each button does.
class InstallScreen extends StatelessWidget {
  static const installKey = Key('install-screen-install');

  final TextEditingController path;
  final VoidCallback onChangePath;
  final bool startMenu;
  final ValueChanged<bool> onStartMenu;
  final bool desktopIcon;
  final ValueChanged<bool> onDesktopIcon;
  final bool printer;
  final ValueChanged<bool> onPrinter;

  /// True once Install is pressed: every control is off and the progress line shows.
  final bool installing;
  final bool canTryWithoutInstalling;
  final VoidCallback onInstall;
  final VoidCallback onCancel;
  final VoidCallback onTryWithoutInstalling;
  final VoidCallback onLicence;

  const InstallScreen({
    super.key,
    required this.path,
    required this.onChangePath,
    required this.startMenu,
    required this.onStartMenu,
    required this.desktopIcon,
    required this.onDesktopIcon,
    required this.printer,
    required this.onPrinter,
    required this.installing,
    required this.canTryWithoutInstalling,
    required this.onInstall,
    required this.onCancel,
    required this.onTryWithoutInstalling,
    required this.onLicence,
  });

  Widget _choice(String label, bool value, ValueChanged<bool> onChanged, [String? why]) => CheckboxListTile(
        value: value,
        onChanged: installing ? null : (v) => onChanged(v ?? false),
        controlAffinity: ListTileControlAffinity.leading,
        contentPadding: EdgeInsets.zero,
        dense: true,
        title: Text(label, style: const TextStyle(color: Kit.paper, fontSize: 15)),
        subtitle: why == null ? null : Text(why, style: const TextStyle(color: Kit.muted, fontSize: 13)),
      );

  @override
  Widget build(BuildContext context) {
    final off = installing;
    return Material(
      color: Kit.ink,
      child: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: Kit.s7, vertical: Kit.s6),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text(InstallWords.title,
                style: TextStyle(color: Kit.paper, fontSize: 24, fontWeight: FontWeight.w800)),
            const SizedBox(height: Kit.s2),
            const Text(InstallWords.body, style: TextStyle(color: Kit.paper, fontSize: 15, height: 1.4)),
            const SizedBox(height: Kit.s5),
            const Text(InstallWords.where, style: TextStyle(color: Kit.muted, fontSize: 13)),
            const SizedBox(height: Kit.s2),
            Row(children: [
              Expanded(child: TextField(controller: path, readOnly: true)),
              const SizedBox(width: Kit.s2),
              OutlinedButton(onPressed: off ? null : onChangePath, child: const Text(InstallWords.change)),
            ]),
            const SizedBox(height: Kit.s4),
            _choice(InstallWords.startMenu, startMenu, onStartMenu),
            _choice(InstallWords.desktopIcon, desktopIcon, onDesktopIcon),
            _choice(InstallWords.printer, printer, onPrinter, InstallWords.printerWhy),
            const SizedBox(height: Kit.s4),
            Row(children: [
              const Flexible(child: Text(InstallWords.licence, style: TextStyle(color: Kit.muted, fontSize: 13))),
              TextButton(onPressed: onLicence, child: const Text(InstallWords.readLicence)),
            ]),
            const SizedBox(height: Kit.s4),
            if (off) ...[
              const LinearProgressIndicator(),
              const SizedBox(height: Kit.s2),
              const Text(InstallWords.installing, style: TextStyle(color: Kit.paper, fontSize: 15)),
              const SizedBox(height: Kit.s4),
            ],
            Wrap(spacing: Kit.s2, runSpacing: Kit.s2, children: [
              FilledButton(
                key: installKey,
                onPressed: off ? null : onInstall,
                child: const Text(InstallWords.install),
              ),
              OutlinedButton(onPressed: off ? null : onCancel, child: const Text(InstallWords.cancel)),
              if (canTryWithoutInstalling)
                TextButton(onPressed: off ? null : onTryWithoutInstalling, child: const Text(InstallWords.tryIt)),
            ]),
          ]),
        ),
      ),
    );
  }
}
