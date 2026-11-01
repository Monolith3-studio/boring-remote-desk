import 'package:flutter/material.dart';

import 'kit.dart';

/// How this session reaches the other Mac. Tickets 03/05 feed the real value; until then it is unknown.
enum LinkState { unknown, local, localHighEfficiency, viaInternet }

/// Link Badge: the small session label naming Direct Link vs Relay. Shows nothing while unknown.
class LinkBadge extends StatelessWidget {
  final LinkState link;
  const LinkBadge({super.key, this.link = LinkState.unknown});

  static String? label(LinkState link) => switch (link) {
        LinkState.unknown => null,
        LinkState.local => 'Local',
        LinkState.localHighEfficiency => 'Local · High Efficiency',
        LinkState.viaInternet => 'Via internet',
      };

  @override
  Widget build(BuildContext context) {
    final text = label(link);
    if (text == null) return const SizedBox.shrink();
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: Kit.s3, vertical: Kit.s1),
      decoration: BoxDecoration(
        color: Kit.glass,
        border: Border.all(color: Kit.line),
        borderRadius: BorderRadius.circular(Kit.radius),
      ),
      child: Text(text, style: const TextStyle(color: Kit.paper, fontSize: 13)),
    );
  }
}

/// Session Toolbar (v1.7): Link Badge, Send files, display pick, quality, Disconnect.
/// Everything else RustDesk offered lives behind More. Bridge-free; the remote page passes data and callbacks.
class SessionToolbar extends StatefulWidget {
  static const moreKey = Key('session-toolbar-more');

  final LinkState link;
  final VoidCallback onSendFiles;
  final int displays;
  final int display;
  final void Function(int index) onPickDisplay;

  /// Current quality key, and every pickable key with its label (first is the default, "Auto").
  final String quality;
  final Map<String, String> qualities;
  final void Function(String key) onQuality;
  final VoidCallback onDisconnect;

  /// The rare actions, shown only after More is pressed.
  final List<Widget> more;

  const SessionToolbar({
    super.key,
    this.link = LinkState.unknown,
    required this.onSendFiles,
    required this.displays,
    required this.display,
    required this.onPickDisplay,
    required this.quality,
    required this.qualities,
    required this.onQuality,
    required this.onDisconnect,
    this.more = const [],
  });

  @override
  State<SessionToolbar> createState() => _SessionToolbarState();
}

class _SessionToolbarState extends State<SessionToolbar> {
  bool _open = false;

  @override
  Widget build(BuildContext context) {
    final w = widget;
    final qualityLabel = w.qualities[w.quality] ?? w.qualities.values.first;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: Kit.s2, vertical: Kit.s1),
      decoration: BoxDecoration(
        color: Kit.panel,
        border: Border.all(color: Kit.line),
        borderRadius: BorderRadius.circular(Kit.radius),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(mainAxisSize: MainAxisSize.min, children: [
        LinkBadge(link: w.link),
        _Action('Send files', Icons.upload_file, w.onSendFiles),
        _Pick<int>(
          label: 'Display ${w.display + 1}',
          icon: Icons.desktop_mac,
          options: {for (var i = 0; i < w.displays; i++) i: 'Display ${i + 1}'},
          current: w.display,
          onPick: w.onPickDisplay,
        ),
        _Pick<String>(
          label: 'Quality: $qualityLabel',
          icon: Icons.tune,
          options: w.qualities,
          current: w.quality,
          onPick: w.onQuality,
        ),
        _Action('Disconnect', Icons.close, w.onDisconnect),
        if (w.more.isNotEmpty)
          IconButton(
            key: SessionToolbar.moreKey,
            tooltip: _open ? 'Less' : 'More',
            color: Kit.muted,
            icon: Icon(_open ? Icons.chevron_left : Icons.more_horiz, size: 18),
            onPressed: () => setState(() => _open = !_open),
          ),
        if (_open && w.more.isNotEmpty) ...[
          Container(width: 1, height: 20, color: Kit.line),
          ...w.more,
        ],
        ]),
      ),
    );
  }
}

class _Action extends StatelessWidget {
  final String label;
  final IconData icon;
  final VoidCallback? onPressed;
  const _Action(this.label, this.icon, this.onPressed);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(left: Kit.s1),
        child: TextButton.icon(
          style: TextButton.styleFrom(
            foregroundColor: Kit.paper,
            iconColor: Kit.muted,
            padding: const EdgeInsets.symmetric(horizontal: Kit.s3, vertical: Kit.s2),
          ),
          onPressed: onPressed,
          icon: Icon(icon, size: 18),
          label: Text(label, style: const TextStyle(fontSize: 13)),
        ),
      );
}

/// A primary action that opens a short list (displays, quality) and reports the pick.
class _Pick<T> extends StatelessWidget {
  final String label;
  final IconData icon;
  final Map<T, String> options;
  final T current;
  final void Function(T) onPick;
  const _Pick({
    super.key,
    required this.label,
    required this.icon,
    required this.options,
    required this.current,
    required this.onPick,
  });

  @override
  Widget build(BuildContext context) => PopupMenuButton<T>(
        tooltip: '',
        color: Kit.panel,
        shape: RoundedRectangleBorder(
          side: const BorderSide(color: Kit.line),
          borderRadius: BorderRadius.circular(Kit.radius),
        ),
        onSelected: onPick,
        itemBuilder: (_) => [
          for (final e in options.entries)
            CheckedPopupMenuItem<T>(
              value: e.key,
              checked: e.key == current,
              child: Text(e.value, style: const TextStyle(color: Kit.paper)),
            ),
        ],
        child: IgnorePointer(child: _Action(label, icon, () {})),
      );
}
