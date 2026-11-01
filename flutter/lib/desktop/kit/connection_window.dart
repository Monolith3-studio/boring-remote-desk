import 'package:flutter/material.dart';

import 'kit.dart';

/// The connection window in the kit (v1.7 review): who is in, what they may do, and the buttons.
/// Bridge-free: server_page.dart passes the client's state and what each control does.

/// What a connected Controller is doing on this Mac.
enum ConnectedKind { control, files, camera, terminal, forward }

/// Every word the connection window's card shows, in one place for review.
class ConnectedWords {
  ConnectedWords._();

  static String doing(ConnectedKind k) => switch (k) {
        ConnectedKind.control => 'Controlling this ${KitWords.one}',
        ConnectedKind.files => 'Sending files',
        ConnectedKind.camera => "Watching this ${KitWords.one}'s camera",
        ConnectedKind.terminal => 'Using the terminal',
        ConnectedKind.forward => 'Using a connection through this ${KitWords.one}',
      };

  static String status({required bool allowed, required bool ended}) =>
      !allowed ? 'Asking to come in' : (ended ? 'Disconnected' : 'Connected');

  static String get unnamed => 'A ${KitWords.one} on this network';
  static const permissionsTitle = 'What they can do';
  static const messages = 'Messages';
  static const fileActivity = 'File activity';

  /// Keyed by the names cmSwitchPermission takes; shown in this order.
  static Map<String, String> get permissions => {
        'keyboard': 'Use the mouse and keyboard',
        'clipboard': 'Copy and paste',
        'audio': "Hear this ${KitWords.one}'s sound",
        'file': 'Copy and paste files',
        'restart': 'Restart this ${KitWords.one}',
        'recording': 'Record the screen',
        'block_input': "Lock out this ${KitWords.one}'s keyboard and mouse",
        'privacy_mode': 'Black out this screen',
      };
}

String _clock(Duration d) {
  final m = d.inMinutes.remainder(60).toString().padLeft(2, '0');
  final s = d.inSeconds.remainder(60).toString().padLeft(2, '0');
  return d.inHours > 0 ? '${d.inHours}:$m:$s' : '${d.inMinutes}:$s';
}

/// Who is connected: name, what they're doing, connected or not and for how long. No ID.
class ConnectedHeader extends StatelessWidget {
  final String name;
  final ConnectedKind kind;
  final bool allowed;
  final bool ended;
  final Duration connectedFor;

  /// Opens the chat (or the file activity); null hides the button.
  final VoidCallback? onChat;
  final bool chatIsFiles;

  const ConnectedHeader({
    super.key,
    required this.name,
    required this.kind,
    required this.allowed,
    required this.ended,
    this.connectedFor = Duration.zero,
    this.onChat,
    this.chatIsFiles = false,
  });

  @override
  Widget build(BuildContext context) {
    final who = name.trim().isNotEmpty ? name.trim() : ConnectedWords.unnamed;
    final status = ConnectedWords.status(allowed: allowed, ended: ended);
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: Kit.s1, vertical: Kit.s2),
      padding: const EdgeInsets.all(Kit.s3),
      decoration: BoxDecoration(
        color: Kit.panel,
        border: Border.all(color: Kit.line),
        borderRadius: BorderRadius.circular(Kit.radius),
      ),
      child: Row(children: [
        Container(
          width: 40,
          height: 40,
          alignment: Alignment.center,
          decoration: const BoxDecoration(color: Kit.glass, shape: BoxShape.circle),
          child: Text(who.characters.first.toUpperCase(),
              style: const TextStyle(color: Kit.paper, fontSize: 18, fontWeight: FontWeight.w700)),
        ),
        const SizedBox(width: Kit.s3),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(who,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(color: Kit.paper, fontSize: 16, fontWeight: FontWeight.w700)),
            Text(ConnectedWords.doing(kind), style: const TextStyle(color: Kit.muted, fontSize: 13)),
            Text(allowed && !ended ? '$status · ${_clock(connectedFor)}' : status,
                style: const TextStyle(color: Kit.muted, fontSize: 13)),
          ]),
        ),
        if (onChat != null)
          IconButton(
            tooltip: chatIsFiles ? ConnectedWords.fileActivity : ConnectedWords.messages,
            color: Kit.muted,
            icon: Icon(chatIsFiles ? Icons.folder_outlined : Icons.chat_bubble_outline, size: 20),
            onPressed: onChat,
          ),
      ]),
    );
  }
}

/// What the other side may do, as plain switches. Names outside ConnectedWords.permissions are skipped.
class PermissionSwitches extends StatelessWidget {
  final Map<String, bool> values;
  final bool canChange;
  final void Function(String name, bool on) onChanged;

  const PermissionSwitches({super.key, required this.values, required this.canChange, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    final words = ConnectedWords.permissions;
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: Kit.s1),
      padding: const EdgeInsets.fromLTRB(Kit.s3, Kit.s2, Kit.s1, Kit.s2),
      decoration: BoxDecoration(
        color: Kit.panel,
        border: Border.all(color: Kit.line),
        borderRadius: BorderRadius.circular(Kit.radius),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
        const Text(ConnectedWords.permissionsTitle, style: TextStyle(color: Kit.muted, fontSize: 13)),
        const SizedBox(height: Kit.s1),
        ConstrainedBox(
          constraints: const BoxConstraints(maxHeight: 224),
          child: ListView(shrinkWrap: true, children: [
            for (final e in values.entries)
              if (words.containsKey(e.key))
                SizedBox(
                  height: 32,
                  child: Row(children: [
                    Expanded(
                      child: Text(words[e.key]!,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(color: Kit.paper, fontSize: 14)),
                    ),
                    Transform.scale(
                      scale: 0.75,
                      child: Switch(
                        value: e.value,
                        onChanged: canChange ? (on) => onChanged(e.key, on) : null,
                      ),
                    ),
                  ]),
                ),
          ]),
        ),
      ]),
    );
  }
}

/// A connection window button. Primary ones (Accept, Disconnect, Close) are paper with ink text.
class CmButton extends StatelessWidget {
  /// The upstream button keys that are the window's main action.
  static const primaryKeys = {'Accept', 'Disconnect', 'Close'};

  final String label;
  final IconData? icon;
  final bool primary;
  final VoidCallback? onTap;
  final GestureTapDownCallback? onTapDown;

  const CmButton({super.key, required this.label, this.icon, this.primary = false, this.onTap, this.onTapDown});

  @override
  Widget build(BuildContext context) {
    final fg = primary ? Kit.ink : Kit.paper;
    final shape = RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(Kit.radius),
      side: primary ? BorderSide.none : const BorderSide(color: Kit.line),
    );
    return Padding(
      padding: const EdgeInsets.all(Kit.s1),
      child: Material(
        color: primary ? Kit.paper : Kit.panel,
        shape: shape,
        child: InkWell(
          customBorder: shape,
          hoverColor: primary ? Kit.muted.withOpacity(0.25) : Kit.glass,
          onTap: onTap,
          onTapDown: onTapDown,
          child: SizedBox(
            height: 36,
            child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
              if (icon != null) ...[Icon(icon, size: 16, color: fg), const SizedBox(width: Kit.s2)],
              Flexible(
                child: Text(label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(color: fg, fontSize: 14, fontWeight: FontWeight.w600)),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}
