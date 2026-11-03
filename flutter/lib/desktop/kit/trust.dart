import 'dart:convert';

import 'package:flutter/material.dart';

import 'kit.dart';

/// LAN trust in the kit (v1.7 t04, ADRs 0002, 0005). Bridge-free: the settings page and the
/// connection window pass the option JSON and callbacks. Formats match libs/base/src/trust.rs
/// (Trusted Controllers, Target side) and direct_link.rs (Macs this Mac has met, Controller side).

/// Server option on the Target: who it trusts. Each entry holds a hash of a token, never the token.
const kTrustedControllersOption = 'boring-trusted-controllers';

/// Local options on the Controller: the Target keys it pinned, and the tokens Targets issued it.
const kDirectLinkKnownOption = 'boring-direct-link-known';
const kTrustTokensOption = 'boring-trust-tokens';

class TrustedController {
  final String key;
  final String name;
  final int added; // seconds since 1970
  const TrustedController({required this.key, required this.name, this.added = 0});
}

List<TrustedController> parseTrusted(String json) {
  try {
    final list = jsonDecode(json);
    if (list is! List) return [];
    return [
      for (final e in list)
        if (e is Map && e['key'] is String && e['removed'] != true)
          TrustedController(
            key: e['key'] as String,
            name: (e['name'] as String?) ?? '',
            added: (e['added'] as num?)?.toInt() ?? 0,
          ),
    ];
  } catch (_) {
    return [];
  }
}

/// The Trusted Controllers JSON with `key` removed. Removing revokes: that Controller is asked
/// again on this Mac, password or not, until someone clicks Allow here. The entry stays, hidden
/// (`removed`), so this Mac still knows the token when it comes back (trust.rs `Trusted::remove`).
String removeTrusted(String json, String key) {
  try {
    final list = jsonDecode(json);
    if (list is! List) return '[]';
    return jsonEncode([
      for (final e in list)
        if (e is Map && e['key'] == key) {...e, 'removed': true} else e
    ]);
  } catch (_) {
    return '[]';
  }
}

/// The removed ones: Settings offers Allow next to each.
List<TrustedController> parseRemoved(String json) {
  try {
    final list = jsonDecode(json);
    if (list is! List) return [];
    return [
      for (final e in list)
        if (e is Map && e['key'] is String && e['removed'] == true)
          TrustedController(
            key: e['key'] as String,
            name: (e['name'] as String?) ?? '',
            added: (e['added'] as num?)?.toInt() ?? 0,
          ),
    ];
  } catch (_) {
    return [];
  }
}

/// Allow in Settings for a removed Controller: its token is Trusted again, as Allow on the prompt
/// does (trust.rs `Trusted::reinstate`: not removed, added now). The settings page writes it with
/// the server option, over ipc to the service, as Remove does.
String reinstateTrusted(String json, String key, {int? now}) {
  try {
    final list = jsonDecode(json);
    if (list is! List) return '[]';
    final at = now ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return jsonEncode([
      for (final e in list)
        if (e is Map && e['key'] == key)
          {for (final f in e.entries) if (f.key != 'removed') f.key: f.value, 'added': at}
        else
          e
    ]);
  } catch (_) {
    return '[]';
  }
}

/// A Target this Mac pinned the key of on its first encrypted Direct Link.
class KnownMac {
  final String id;
  final String address; // where it last answered (this network, else Tailscale), without the port
  const KnownMac({required this.id, required this.address});
}

List<KnownMac> parseKnown(String json) {
  try {
    final map = jsonDecode(json);
    if (map is! Map) return [];
    return [
      for (final e in map.entries)
        KnownMac(
          id: '${e.key}',
          address: _host(e.value is Map
              ? ('${e.value['lan'] ?? ''}'.isNotEmpty ? '${e.value['lan']}' : '${e.value['tailscale'] ?? ''}')
              : ''),
        ),
    ];
  } catch (_) {
    return [];
  }
}

String _host(String addr) {
  final i = addr.lastIndexOf(':');
  final h = i > 0 ? addr.substring(0, i) : addr;
  return h.replaceAll('[', '').replaceAll(']', '');
}

/// The JSON map without `id` (used for both the pinned keys and the tokens).
String forgetId(String json, String id) {
  try {
    final map = jsonDecode(json);
    if (map is! Map) return '{}';
    map.remove(id);
    return jsonEncode(map);
  } catch (_) {
    return '{}';
  }
}

/// Settings → Advanced → Trusted Controllers. Who can get into this Mac without asking, and
/// which Macs' keys this Mac remembers. Remove and Forget take effect at once.
class TrustedControllersPage extends StatefulWidget {
  final List<TrustedController> trusted;
  final List<KnownMac> known;
  final Future<void> Function(String key) onRemove;
  final Future<void> Function(String id) onForget;

  /// Removed ones, each with Allow ([onAllow] trusts it again, and lets in a live ask from it).
  final List<TrustedController> removed;
  final Future<void> Function(TrustedController c)? onAllow;

  /// Whoever is waiting right now (kit/approval.dart WaitingApprovals); null shows nothing.
  final Widget? waiting;

  const TrustedControllersPage({
    super.key,
    required this.trusted,
    required this.known,
    required this.onRemove,
    required this.onForget,
    this.removed = const [],
    this.onAllow,
    this.waiting,
  });

  @override
  State<TrustedControllersPage> createState() => _TrustedControllersPageState();
}

class _TrustedControllersPageState extends State<TrustedControllersPage> {
  late final _trusted = [...widget.trusted];
  late final _known = [...widget.known];
  late final _removed = [...widget.removed];

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return ListView(
      padding: const EdgeInsets.all(Kit.s6),
      children: [
        Text('Trusted Controllers', style: t.headlineSmall),
        const SizedBox(height: Kit.s2),
        if (widget.waiting != null) widget.waiting!,
        Text('These ${KitWords.many} get into this one without asking. Remove one and it has to ask again.',
            style: t.bodySmall),
        const SizedBox(height: Kit.s4),
        if (_trusted.isEmpty) Text('None yet. A ${KitWords.one} lands here once you allow it in.'),
        for (final c in _trusted)
          ListTile(
            contentPadding: EdgeInsets.zero,
            title: Text(c.name.isNotEmpty ? c.name : 'A ${KitWords.one} with no name'),
            trailing: TextButton(
              onPressed: () async {
                await widget.onRemove(c.key);
                if (mounted) setState(() => _trusted.remove(c));
              },
              child: const Text('Remove'),
            ),
          ),
        if (_removed.isNotEmpty && widget.onAllow != null) ...[
          const SizedBox(height: Kit.s6),
          Text('Removed', style: t.titleMedium),
          const SizedBox(height: Kit.s2),
          Text('These have to ask before they get in. Allow one and it gets in without asking again.',
              style: t.bodySmall),
          const SizedBox(height: Kit.s3),
          for (final c in _removed)
            Padding(
              padding: const EdgeInsets.only(bottom: Kit.s3),
              child: Row(children: [
                Expanded(child: Text(c.name.isNotEmpty ? c.name : 'A ${KitWords.one} with no name')),
                const SizedBox(width: Kit.s3),
                FilledButton(
                  style: FilledButton.styleFrom(
                    minimumSize: const Size(120, 48),
                    backgroundColor: Kit.paper,
                    foregroundColor: Kit.ink,
                  ),
                  onPressed: () async {
                    await widget.onAllow!(c);
                    if (mounted) {
                      setState(() {
                        _removed.remove(c);
                        _trusted.add(c);
                      });
                    }
                  },
                  child: const Text('Allow'),
                ),
              ]),
            ),
        ],
        const SizedBox(height: Kit.s6),
        Text('${KitWords.cap(KitWords.many)} this one has connected to', style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        Text(
            "If one of these was reinstalled, it won't connect. Click Forget next to it, "
            'then connect to it again.',
            style: t.bodySmall),
        const SizedBox(height: Kit.s4),
        if (_known.isEmpty) const Text('None yet.'),
        for (final m in _known)
          ListTile(
            contentPadding: EdgeInsets.zero,
            title: Text(m.address.isNotEmpty ? m.address : 'A ${KitWords.one} you connected to'),
            trailing: TextButton(
              onPressed: () async {
                await widget.onForget(m.id);
                if (mounted) setState(() => _known.remove(m));
              },
              child: const Text('Forget'),
            ),
          ),
      ],
    );
  }
}

/// The ask in plain words: who, and what it wants (the connection window and the main window).
String approvalQuestion(String name) {
  final who = name.trim().isNotEmpty ? name.trim() : 'A ${KitWords.one} on this network';
  return '$who wants to control this ${KitWords.one}.';
}

const kApprovalWhy = "If you allow it, it can get in next time without asking. You can remove it in Settings.";

/// What the Target shows when an unknown Mac asks to come in. Plain words, two choices.
/// It scrolls rather than clips when the connection window is short.
class ApprovalPrompt extends StatelessWidget {
  final String name;
  final VoidCallback onAllow;
  final VoidCallback onDeny;

  const ApprovalPrompt({super.key, required this.name, required this.onAllow, required this.onDeny});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(Kit.s4),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(approvalQuestion(name), style: t.titleMedium),
          const SizedBox(height: Kit.s2),
          Text(kApprovalWhy, style: t.bodySmall),
          const SizedBox(height: Kit.s4),
          Row(children: [
            Expanded(
              child: OutlinedButton(onPressed: onDeny, child: const Text("Don't allow")),
            ),
            const SizedBox(width: Kit.s2),
            Expanded(
              child: FilledButton(
                style: FilledButton.styleFrom(backgroundColor: Kit.paper, foregroundColor: Kit.ink),
                onPressed: onAllow,
                child: const Text('Allow'),
              ),
            ),
          ]),
        ],
      ),
    );
  }
}
