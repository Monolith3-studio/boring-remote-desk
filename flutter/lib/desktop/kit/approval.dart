import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'kit.dart';
import 'trust.dart';

/// Allow / Don't allow in the middle of the main window (v1.7 t04). The ask comes from the
/// connection window's process; src/boring_approval.rs carries these three messages between the
/// two windows. Bridge-free: the wiring passes the overlay, the window and the send.
const kApprovalAsk = 'boring-approval-ask:';
const kApprovalDone = 'boring-approval-done:';
const kApprovalAnswer = 'boring-approval-answer:';

/// The page event both windows get (src/boring_approval.rs `EVENT`).
const kApprovalEvent = 'boring_approval';

enum ApprovalKind { ask, done, answer }

class ApprovalMsg {
  final ApprovalKind kind;
  final int id;
  final String name; // ask only
  // Ask only (audit H1): 'new', 'removed' or '' (unknown), the start of its Trusted Controllers key
  // (libs/base/src/trust.rs AskInfo) and its address. Settings matches on the key, never the name.
  final String trust;
  final String key;
  final String ip;
  final bool allow; // answer only
  const ApprovalMsg(this.kind, this.id,
      {this.name = '', this.trust = '', this.key = '', this.ip = '', this.allow = false});
}

/// `ask:<id>:<trust>:<key>:<ip>:<name>`, ip and name percent-encoded (an IPv6 address has colons).
String approvalAsk(int id, String name, {String trust = '', String key = '', String ip = ''}) =>
    '$kApprovalAsk$id:${Uri.encodeComponent(trust)}:${Uri.encodeComponent(key)}:'
    '${Uri.encodeComponent(ip)}:${Uri.encodeComponent(name)}';
String approvalDone(int id) => '$kApprovalDone$id';
String approvalAnswer(int id, bool allow) => '$kApprovalAnswer$id:${allow ? 'allow' : 'deny'}';

ApprovalMsg? parseApproval(String msg) {
  for (final (prefix, kind) in [
    (kApprovalAsk, ApprovalKind.ask),
    (kApprovalDone, ApprovalKind.done),
    (kApprovalAnswer, ApprovalKind.answer),
  ]) {
    if (!msg.startsWith(prefix)) continue;
    final rest = msg.substring(prefix.length);
    final i = rest.indexOf(':');
    final id = int.tryParse(i < 0 ? rest : rest.substring(0, i));
    if (id == null) return null;
    final tail = i < 0 ? '' : rest.substring(i + 1);
    switch (kind) {
      case ApprovalKind.ask:
        String dec(String s) {
          try {
            return Uri.decodeComponent(s);
          } catch (_) {
            return '';
          }
        }
        final f = tail.split(':');
        if (f.length != 4) return ApprovalMsg(kind, id, name: dec(tail));
        return ApprovalMsg(kind, id, trust: dec(f[0]), key: dec(f[1]), ip: dec(f[2]), name: dec(f[3]));
      case ApprovalKind.done:
        return ApprovalMsg(kind, id);
      case ApprovalKind.answer:
        if (tail != 'allow' && tail != 'deny') return null;
        return ApprovalMsg(kind, id, allow: tail == 'allow');
    }
  }
  return null;
}

/// The ask, filling the main window: the question large, two big buttons. It scrolls rather than
/// clips when the window is small, and the buttons stack when it is narrow.
class ApprovalRequestView extends StatelessWidget {
  final String name;
  final String trust;
  final String ip;
  final VoidCallback onAllow;
  final VoidCallback onDeny;

  const ApprovalRequestView(
      {super.key, required this.name, this.trust = '', this.ip = '', required this.onAllow, required this.onDeny});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    const big = Size.fromHeight(56);
    final deny = OutlinedButton(
      key: const ValueKey('approval-deny'),
      style: OutlinedButton.styleFrom(
        minimumSize: big,
        foregroundColor: Kit.paper,
        side: const BorderSide(color: Kit.muted),
        textStyle: const TextStyle(fontSize: 17, fontWeight: FontWeight.w600),
      ),
      onPressed: onDeny,
      child: const Text("Don't allow"),
    );
    final allow = FilledButton(
      key: const ValueKey('approval-allow'),
      style: FilledButton.styleFrom(
        minimumSize: big,
        backgroundColor: Kit.paper,
        foregroundColor: Kit.ink,
        textStyle: const TextStyle(fontSize: 17, fontWeight: FontWeight.w700),
      ),
      onPressed: onAllow,
      child: const Text('Allow'),
    );
    return Material(
      color: Kit.ink.withOpacity(0.94),
      child: LayoutBuilder(builder: (context, box) {
        final narrow = box.maxWidth < 380;
        final pad = narrow ? Kit.s4 : Kit.s6;
        return SingleChildScrollView(
          padding: EdgeInsets.all(pad),
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: (box.maxHeight - 2 * pad).clamp(0, double.infinity)),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 520),
                child: Container(
                  padding: EdgeInsets.all(pad),
                  decoration: BoxDecoration(
                    color: Kit.panel,
                    borderRadius: BorderRadius.circular(Kit.radius * 2),
                    border: Border.all(color: Kit.line),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Text(approvalQuestion(name),
                          textAlign: TextAlign.center,
                          style: t.headlineSmall?.copyWith(height: 1.25)),
                      if (approvalWho(trust, ip).isNotEmpty) ...[
                        const SizedBox(height: Kit.s2),
                        Text(approvalWho(trust, ip), textAlign: TextAlign.center, style: t.titleMedium),
                      ],
                      const SizedBox(height: Kit.s3),
                      Text(kApprovalWhy,
                          textAlign: TextAlign.center,
                          style: t.bodyMedium?.copyWith(color: Kit.muted)),
                      const SizedBox(height: Kit.s5),
                      if (narrow) ...[
                        allow,
                        const SizedBox(height: Kit.s3),
                        deny,
                      ] else
                        Row(children: [
                          Expanded(child: deny),
                          const SizedBox(width: Kit.s3),
                          Expanded(child: allow),
                        ]),
                    ],
                  ),
                ),
              ),
            ),
          ),
        );
      }),
    );
  }
}

/// The main window's side: shows each ask over everything, one at a time, brings the window to
/// the front, sends the answer back, and drops an ask the connection window settled itself.
class ApprovalDesk {
  /// The main window's desk, made on its first ask (models/model.dart).
  static ApprovalDesk? main;

  final OverlayState? Function() overlay;
  final Future<void> Function() toFront;
  final void Function(int id, bool allow) answer;

  ApprovalDesk({required this.overlay, required this.toFront, required this.answer});

  /// Who is waiting right now, for Settings (Access, Trusted Controllers). Empty until an ask.
  static final waitingNow = ValueNotifier<List<WaitingAsk>>(const []);

  final _waiting = <int, ApprovalMsg>{}; // id → its ask, in arrival order
  OverlayEntry? _entry;
  int? _showing;

  int? get showing => _showing;

  void take(ApprovalMsg m) {
    switch (m.kind) {
      case ApprovalKind.ask:
        _waiting[m.id] = m;
        _publish();
        toFront();
        _show();
      case ApprovalKind.done:
        _waiting.remove(m.id);
        _publish();
        if (_showing == m.id) _hide();
        _show();
      case ApprovalKind.answer:
        break; // the connection window's to handle
    }
  }

  /// Allow or Don't allow, from the middle of the window or from Settings: the same answer.
  void decide(int id, bool allow) {
    if (_waiting.remove(id) == null) return;
    _publish();
    if (_showing == id) _hide();
    answer(id, allow);
    _show();
  }

  void _publish() => waitingNow.value = [
        for (final m in _waiting.values) WaitingAsk(m.id, m.name, trust: m.trust, key: m.key, ip: m.ip)
      ];

  void _hide() {
    _entry?.remove();
    _entry = null;
    _showing = null;
  }

  void _show() {
    if (_entry != null || _waiting.isEmpty) return;
    final o = overlay();
    if (o == null) {
      // The main window is still starting: try again in a moment.
      Future.delayed(const Duration(milliseconds: 300), _show);
      return;
    }
    final ask = _waiting.values.first;
    final id = ask.id;
    _showing = id;
    _entry = OverlayEntry(
      builder: (context) => Theme(
        data: Kit.theme(),
        child: ApprovalRequestView(
          name: ask.name,
          trust: ask.trust,
          ip: ask.ip,
          onAllow: () => decide(id, true),
          onDeny: () => decide(id, false),
        ),
      ),
    );
    o.insert(_entry!);
  }
}

class WaitingAsk {
  final int id;
  final String name;
  final String trust;
  final String key;
  final String ip;
  const WaitingAsk(this.id, this.name, {this.trust = '', this.key = '', this.ip = ''});
}

/// Settings → Trusted list → Allow on removed [c]: the waiting asks that presented its token
/// (removed, and its key starts with theirs). Never by name: the Controller picks its own (audit H1).
List<int> waitingFrom(TrustedController c, List<WaitingAsk> waiting) => [
      for (final w in waiting)
        if (w.trust == 'removed' && w.key.length >= kTrustKeyPrefixLen && c.key.startsWith(w.key)) w.id
    ];

/// Settings' rows for whoever is waiting right now (Access, Trusted Controllers): the question
/// and big Allow / Don't allow buttons. Nothing when no one is waiting.
class WaitingApprovals extends StatelessWidget {
  final ValueListenable<List<WaitingAsk>> waiting;
  final void Function(int id, bool allow) onDecide;

  const WaitingApprovals({super.key, required this.waiting, required this.onDecide});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return ValueListenableBuilder<List<WaitingAsk>>(
      valueListenable: waiting,
      builder: (context, list, _) => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          for (final w in list)
            Container(
              margin: const EdgeInsets.only(bottom: Kit.s3),
              padding: const EdgeInsets.all(Kit.s4),
              decoration: BoxDecoration(
                color: Kit.panel,
                borderRadius: BorderRadius.circular(Kit.radius),
                border: Border.all(color: Kit.line),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(approvalQuestion(w.name), style: t.titleMedium),
                  if (approvalWho(w.trust, w.ip).isNotEmpty) Text(approvalWho(w.trust, w.ip), style: t.bodyMedium),
                  const SizedBox(height: Kit.s3),
                  Row(children: [
                    Expanded(
                      child: OutlinedButton(
                        style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(48)),
                        onPressed: () => onDecide(w.id, false),
                        child: const Text("Don't allow"),
                      ),
                    ),
                    const SizedBox(width: Kit.s3),
                    Expanded(
                      child: FilledButton(
                        style: FilledButton.styleFrom(
                          minimumSize: const Size.fromHeight(48),
                          backgroundColor: Kit.paper,
                          foregroundColor: Kit.ink,
                        ),
                        onPressed: () => onDecide(w.id, true),
                        child: const Text('Allow'),
                      ),
                    ),
                  ]),
                ],
              ),
            ),
        ],
      ),
    );
  }
}
