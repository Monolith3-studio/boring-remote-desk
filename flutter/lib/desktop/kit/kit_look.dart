import 'package:flutter/material.dart';

import 'kit.dart';

/// The kit over the upstream widgets Mac and Windows still show (v1.7 review: "nothing left in
/// the RustDesk look"): dialogs, toolbar menus, cards, buttons, checkboxes, switches, radios,
/// sliders, tooltips and tabs. Coral only marks a selection, never text or a fill under text.
ThemeData kitLook(ThemeData base) {
  const none = Colors.transparent;
  WidgetStateProperty<Color> pick(Color on, Color off) =>
      WidgetStateProperty.resolveWith((s) => s.contains(WidgetState.selected) ? on : off);
  final round = RoundedRectangleBorder(borderRadius: BorderRadius.circular(Kit.radius));
  final edged = RoundedRectangleBorder(
    borderRadius: BorderRadius.circular(Kit.radius),
    side: const BorderSide(color: Kit.line),
  );
  const label = TextStyle(fontSize: 14, fontWeight: FontWeight.w600);
  final filled = ButtonStyle(
    backgroundColor: WidgetStateProperty.resolveWith(
        (s) => s.contains(WidgetState.disabled) ? Kit.glass : Kit.paper),
    foregroundColor: WidgetStateProperty.resolveWith(
        (s) => s.contains(WidgetState.disabled) ? Kit.muted : Kit.ink),
    iconColor: const WidgetStatePropertyAll(Kit.ink),
    overlayColor: const WidgetStatePropertyAll(Kit.line),
    elevation: const WidgetStatePropertyAll(0),
    shape: WidgetStatePropertyAll(round),
    textStyle: const WidgetStatePropertyAll(label),
  );
  return base.copyWith(
    hoverColor: Kit.glass,
    highlightColor: none,
    splashColor: none,
    splashFactory: NoSplash.splashFactory,
    cardColor: Kit.panel,
    dialogBackgroundColor: Kit.panel,
    iconTheme: const IconThemeData(color: Kit.muted),
    cardTheme: CardTheme(color: Kit.panel, surfaceTintColor: none, elevation: 0, shape: edged),
    dialogTheme: DialogTheme(
      backgroundColor: Kit.panel,
      surfaceTintColor: none,
      elevation: 8,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Kit.radius * 1.6),
        side: const BorderSide(color: Kit.line),
      ),
      titleTextStyle: const TextStyle(color: Kit.paper, fontSize: 18, fontWeight: FontWeight.w700),
      contentTextStyle: const TextStyle(color: Kit.paper, fontSize: 15),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(style: filled),
    filledButtonTheme: FilledButtonThemeData(style: filled),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: Kit.paper,
        disabledForegroundColor: Kit.muted,
        backgroundColor: none,
        side: const BorderSide(color: Kit.line),
        shape: round,
        textStyle: label,
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(foregroundColor: Kit.paper, disabledForegroundColor: Kit.muted, shape: round),
    ),
    checkboxTheme: CheckboxThemeData(
      fillColor: pick(Kit.paper, none),
      checkColor: const WidgetStatePropertyAll(Kit.ink),
      side: const BorderSide(color: Kit.muted, width: 1.5),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
      splashRadius: 0,
    ),
    radioTheme: RadioThemeData(fillColor: pick(Kit.paper, Kit.muted), splashRadius: 0),
    switchTheme: SwitchThemeData(
      thumbColor: pick(Kit.ink, Kit.muted),
      trackColor: pick(Kit.paper, Kit.glass),
      trackOutlineColor: pick(Kit.paper, Kit.line),
      splashRadius: 0,
    ),
    sliderTheme: const SliderThemeData(
      activeTrackColor: Kit.paper,
      inactiveTrackColor: Kit.line,
      thumbColor: Kit.paper,
      overlayColor: none,
    ),
    progressIndicatorTheme: const ProgressIndicatorThemeData(
      color: Kit.paper,
      linearTrackColor: Kit.line,
      circularTrackColor: none,
    ),
    menuTheme: MenuThemeData(
      style: MenuStyle(
        backgroundColor: const WidgetStatePropertyAll(Kit.panel),
        surfaceTintColor: const WidgetStatePropertyAll(none),
        side: const WidgetStatePropertyAll(BorderSide(color: Kit.line)),
        shape: WidgetStatePropertyAll(round),
      ),
    ),
    menuBarTheme: const MenuBarThemeData(
      style: MenuStyle(
        backgroundColor: WidgetStatePropertyAll(Kit.panel),
        surfaceTintColor: WidgetStatePropertyAll(none),
        elevation: WidgetStatePropertyAll(0),
      ),
    ),
    menuButtonTheme: MenuButtonThemeData(
      style: MenuItemButton.styleFrom(
        foregroundColor: Kit.paper,
        iconColor: Kit.muted,
        disabledForegroundColor: Kit.muted,
        textStyle: const TextStyle(fontSize: 14),
      ),
    ),
    popupMenuTheme: PopupMenuThemeData(
      color: Kit.panel,
      surfaceTintColor: none,
      shape: edged,
      textStyle: const TextStyle(color: Kit.paper, fontSize: 14),
    ),
    tooltipTheme: TooltipThemeData(
      decoration: BoxDecoration(
        color: Kit.glass,
        border: Border.all(color: Kit.line),
        borderRadius: BorderRadius.circular(6),
      ),
      textStyle: const TextStyle(color: Kit.paper, fontSize: 13),
      waitDuration: const Duration(milliseconds: 600),
    ),
    dividerTheme: const DividerThemeData(color: Kit.line, space: 1, thickness: 1),
    tabBarTheme: const TabBarTheme(
      labelColor: Kit.paper,
      unselectedLabelColor: Kit.muted,
      indicatorColor: Kit.coral,
      dividerColor: Kit.line,
    ),
    scrollbarTheme: const ScrollbarThemeData(thumbColor: WidgetStatePropertyAll(Kit.line)),
  );
}

/// A titled group of settings (All settings, v1.7 review): a panel card with a kit heading.
class KitSection extends StatelessWidget {
  final String title;
  final List<Widget> trailing;
  final List<Widget> children;
  final double width;

  const KitSection({
    super.key,
    required this.title,
    this.trailing = const [],
    required this.children,
    this.width = 540,
  });

  @override
  Widget build(BuildContext context) => Row(children: [
        Flexible(
          child: Container(
            width: width,
            margin: const EdgeInsets.only(left: Kit.s4, top: Kit.s4),
            padding: const EdgeInsets.fromLTRB(Kit.s1, Kit.s3, 0, Kit.s3),
            decoration: BoxDecoration(
              color: Kit.panel,
              border: Border.all(color: Kit.line),
              borderRadius: BorderRadius.circular(Kit.radius),
            ),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: Kit.s3),
                child: Row(children: [
                  Expanded(
                    child: Text(title,
                        style: const TextStyle(color: Kit.paper, fontSize: 16, fontWeight: FontWeight.w700)),
                  ),
                  ...trailing,
                ]),
              ),
              const SizedBox(height: Kit.s2),
              for (final c in children)
                Padding(padding: const EdgeInsets.only(top: Kit.s1, right: Kit.s3), child: c),
            ]),
          ),
        ),
      ]);
}

/// One row of All settings' tab list. The selected row gets a glass fill and a coral bar (a mark).
class KitTabRow extends StatelessWidget {
  final String label;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;

  const KitTabRow({
    super.key,
    required this.label,
    required this.icon,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final fg = selected ? Kit.paper : Kit.muted;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: Kit.s2, vertical: 2),
      child: Material(
        type: MaterialType.transparency,
        child: InkWell(
          onTap: onTap,
          hoverColor: Kit.glass,
          borderRadius: BorderRadius.circular(Kit.radius),
          child: Ink(
            height: 40,
            decoration: BoxDecoration(
              color: selected ? Kit.glass : null,
              borderRadius: BorderRadius.circular(Kit.radius),
            ),
            child: Row(children: [
              Container(width: 3, height: 18, color: selected ? Kit.coral : null),
              const SizedBox(width: Kit.s3),
              Icon(icon, size: 18, color: fg),
              const SizedBox(width: Kit.s3),
              Expanded(
                child: Text(label,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                        color: fg, fontSize: 15, fontWeight: selected ? FontWeight.w600 : FontWeight.w400)),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}

/// A message in plain words: what happened, and on an error the one thing to do next.
class KitMessageWords {
  final String title;

  /// Null keeps the upstream text (already plain, or not ours to word).
  final String? body;
  final String? next;
  const KitMessageWords(this.title, [this.body, this.next]);
}

String _w(String s) => s.replaceAll('{Mac}', KitWords.one).replaceAll('{Macs}', KitWords.many);

const _couldNot = "Couldn't connect";
const _checkOn = "Make sure that {Mac} is awake and Boring Remote is open on it, then try again.";

/// Keyed by the text Rust sends (src/client.rs, src/client/io_loop.rs, src/server/connection.rs,
/// libs/base/src/direct_link.rs). "{Mac}" is KitWords.one when shown.
const _byText = <String, (String, String?, String?)>{
  'Connection in progress. Please wait.': ('Connecting…', 'This takes a few seconds.', null),
  'Connected, waiting for image...': ('Connected', 'Waiting for the first picture of the screen.', null),
  'Please wait for the remote side to accept your session request...':
      ('Waiting for Allow', 'Someone at that {Mac} needs to click Allow.', null),
  'Do you want to enter again?':
      ("That password didn't work", "Type it again. It's the Unattended Password set on that {Mac}.", null),
  'Timeout': (_couldNot, "That {Mac} didn't answer in time.", _checkOn),
  'Remote desktop is offline': (_couldNot, 'That {Mac} is offline.', _checkOn),
  'Offline': (_couldNot, 'That {Mac} is offline.', _checkOn),
  'Reset by the peer':
      ('Disconnected', 'That {Mac} ended the connection.', 'Connect again. If it keeps happening, restart Boring Remote on that {Mac}.'),
  'Connection not allowed':
      (_couldNot, "That {Mac} didn't let this one in.", 'Ask someone there to click Allow, then connect again.'),
  'Too many wrong attempts':
      ('Too many tries', 'That {Mac} stopped taking passwords for a minute.', 'Wait a minute, then try again.'),
  'Please try 1 minute later':
      ('Too many tries', 'That {Mac} stopped taking passwords for a minute.', 'Wait a minute, then try again.'),
  // Direct Link's own errors (libs/base/src/direct_link.rs, Mac and Windows wording) already say
  // what to do next: shown as they are, under a plain title. check.py keeps this list in step.
  "Couldn't find a Mac with that name. Pick it from the list, or check the spelling and try again.":
      (_couldNot, null, null),
  "Couldn't find a computer with that name. Pick it from the list, or check the spelling and try again.":
      (_couldNot, null, null),
  "Couldn't reach that Mac. Make sure it's awake and on the same network as this one, then try again.":
      (_couldNot, null, null),
  "Couldn't reach that computer. Make sure it's awake and on the same network as this one, then try again.":
      (_couldNot, null, null),
  "Boring Remote doesn't know where that Mac is yet. Type its name or address in the box, then try again.":
      (_couldNot, null, null),
  "Boring Remote doesn't know where that computer is yet. Type its name or address in the box, then try again.":
      (_couldNot, null, null),
  "That Mac needs the latest Boring Remote. Update Boring Remote on that Mac, then try again.":
      (_couldNot, null, null),
  "That computer needs the latest Boring Remote. Update Boring Remote on that computer, then try again.":
      (_couldNot, null, null),
  "This isn't the Mac you connected to before, so Boring Remote stopped. If that Mac was reinstalled, open Settings, click Trusted list, click Forget next to it, then try again.":
      (_couldNot, null, null),
  "This isn't the computer you connected to before, so Boring Remote stopped. If that computer was reinstalled, open Settings, click Trusted list, click Forget next to it, then try again.":
      (_couldNot, null, null),
};

/// Plain words for a message box a Controller sees while connecting (Dumb-proof standard). Null
/// means "show the upstream text as it is". An unknown error still gets one next step.
KitMessageWords? kitMessageWords(String type, String title, String text) {
  if (title == 'Restarting remote device') {
    return KitMessageWords(_w('Restarting that {Mac}…'), "It connects again on its own when it's back.");
  }
  final known = _byText[text];
  if (known != null) {
    return KitMessageWords(_w(known.$1), known.$2 == null ? null : _w(known.$2!), known.$3 == null ? null : _w(known.$3!));
  }
  if (title == 'Connection Error') return KitMessageWords(_couldNot, null, _w(_checkOn));
  if (type.contains('error')) {
    return KitMessageWords(title, null, _w('Try again. If it keeps happening, restart Boring Remote on both {Macs}.'));
  }
  return null;
}

/// True for the messages that mean "still working on it": they get a small spinner.
bool kitMessageWaits(String type, String text) =>
    type == 'connecting' ||
    type.startsWith('restarting') ||
    type == 'wait-remote-accept-nook' ||
    text == 'Connected, waiting for image...';

/// A message box's content in the kit: title, plain body, and the next step on its own line.
class KitMessage extends StatelessWidget {
  final String title;
  final String body;
  final String? next;
  final bool waiting;

  const KitMessage({super.key, required this.title, required this.body, this.next, this.waiting = false});

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: Kit.s3),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              if (waiting) ...[
                const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)),
                const SizedBox(width: Kit.s3),
              ],
              Expanded(
                child: Text(title,
                    style: const TextStyle(color: Kit.paper, fontSize: 18, fontWeight: FontWeight.w700)),
              ),
            ]),
            if (body.isNotEmpty) ...[
              const SizedBox(height: Kit.s2),
              Text(body, style: const TextStyle(color: Kit.paper, fontSize: 15, height: 1.35)),
            ],
            if (next != null) ...[
              const SizedBox(height: Kit.s3),
              Text(next!,
                  style: const TextStyle(color: Kit.paper, fontSize: 15, height: 1.35, fontWeight: FontWeight.w600)),
            ],
          ],
        ),
      );
}

/// The Controller's password prompt in plain words (v1.7 review).
class KitPasswordWords {
  KitPasswordWords._();
  static String get title => 'Password for that ${KitWords.one}';
  static String get body => 'Type the Unattended Password that was set on that ${KitWords.one}.';
  static String get remember => 'Remember it on this ${KitWords.one}';
}
