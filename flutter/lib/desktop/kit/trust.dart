import 'dart:convert';

import 'package:flutter/material.dart';

import 'kit.dart';

/// LAN trust in the kit (v1.7 t04, ADRs 0002, 0005). Bridge-free: the settings page and the
/// connection window pass the option JSON and callbacks. Formats match libs/base/src/trust.rs
/// (Trusted Controllers, Target side) and direct_link.rs (Macs this Mac has met, Controller side).

/// Server option on the Target: who it trusts. Each entry holds a hash of a token, never the token.
const kTrustedControllersOption = 'boring-trusted-controllers';

/// Server option on the Target: "New computers always ask for password" ("Y"), trust.rs
/// NEW_ALWAYS_ASK_OPTION. Settings is its only writer.
const kNewAlwaysAskOption = 'boring-new-computers-always-ask';

/// Every change to the Trusted list is the service's (trust.rs `edit`, one locked write there):
/// Remove, Allow and "Always ask for password" send what to do, over ipc, and show its answer.
String trustEdit(String op, String key, {bool? on, String? password}) =>
    jsonEncode({'op': op, 'key': key, if (on != null) 'on': on, if (password != null) 'password': password});

/// The service's answer: null when it saved, else why not, in its words. No answer is not saved.
String? trustEditError(String answer) {
  try {
    final a = jsonDecode(answer);
    if (a is Map && a['ok'] == true) return null;
    if (a is Map && a['error'] is String && (a['error'] as String).isNotEmpty) return a['error'] as String;
  } catch (_) {}
  return kTrustNoAnswer;
}

const kTrustNoAnswer = "Boring Remote's background service didn't answer, so nothing was changed.";

/// Local options on the Controller: the Target keys it pinned, and the tokens Targets issued it.
const kDirectLinkKnownOption = 'boring-direct-link-known';
const kTrustTokensOption = 'boring-trust-tokens';

class TrustedController {
  final String key;
  final String name;
  final int added; // seconds since 1970
  final bool alwaysAsk; // "Always ask for password" (trust.rs `always_ask`; absent = off)
  const TrustedController({required this.key, required this.name, this.added = 0, this.alwaysAsk = false});
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
            alwaysAsk: e['always_ask'] == true,
          ),
    ];
  } catch (_) {
    return [];
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
            alwaysAsk: e['always_ask'] == true,
          ),
    ];
  } catch (_) {
    return [];
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

/// boring-remote (v1.7 t26): who a recent on Home is. A Known entry's pinned key (its Target ID
/// when it has none) under the Target ID and each address it last answered on, no port. An address
/// with no entry here is one nothing is stored for now (Known keeps what it last listed).
Map<String, String> identitiesFromKnown(String json) {
  final who = <String, String>{};
  try {
    final map = jsonDecode(json);
    if (map is! Map) return who;
    for (final e in map.entries) {
      final t = e.value is Map ? e.value as Map : const {};
      final pk = '${t['pk'] ?? ''}';
      final key = pk.isNotEmpty ? pk : '${e.key}';
      who['${e.key}'] = key;
      for (final at in [t['lan'], t['tailscale']]) {
        final host = _host('${at ?? ''}');
        if (host.isNotEmpty) who[host] = key;
      }
      // boring-remote (v1.7 t25): every LAN address it listed is the same machine.
      final addrs = t['addrs'];
      if (addrs is List) {
        for (final a in addrs) {
          final ip = a is Map ? '${a['ip'] ?? ''}' : '';
          if (ip.isNotEmpty) who[ip] = key;
        }
      }
    }
  } catch (_) {}
  return who;
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
/// which Macs' keys this Mac remembers. Remove and Forget take effect at once. Remove, Allow and
/// "Always ask for password" return null once the service saved them, else why not (shown here,
/// and the page stays as saved).
class TrustedControllersPage extends StatefulWidget {
  final List<TrustedController> trusted;
  final List<KnownMac> known;
  final Future<String?> Function(String key) onRemove;
  final Future<void> Function(String id) onForget;

  /// "Always ask for password" switched for one. On carries the Unattended Password typed here:
  /// the service checks it and turns its salt over (trust.rs `rotate_salt`). Null shows no switch.
  final Future<String?> Function(String key, bool on, String password)? onAlwaysAsk;

  /// "New computers always ask for password" (kNewAlwaysAskOption). Null shows no switch.
  final bool newAlwaysAsk;
  final Future<void> Function(bool on)? onNewAlwaysAsk;

  /// Removed ones, each with Allow ([onAllow] trusts it again, and lets in a live ask from it).
  final List<TrustedController> removed;
  final Future<String?> Function(TrustedController c)? onAllow;

  /// Whoever is waiting right now (kit/approval.dart WaitingApprovals); null shows nothing.
  final Widget? waiting;

  const TrustedControllersPage({
    super.key,
    required this.trusted,
    required this.known,
    required this.onRemove,
    required this.onForget,
    this.onAlwaysAsk,
    this.newAlwaysAsk = false,
    this.onNewAlwaysAsk,
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
  late final _alwaysAsk = {for (final c in [...widget.trusted, ...widget.removed]) c.key: c.alwaysAsk};
  late bool _newAlwaysAsk = widget.newAlwaysAsk;
  String? _error; // the service's last refusal, shown until the next change saves

  /// Runs one change; on success applies it here, else shows why and leaves the page as saved.
  Future<void> _save(Future<String?> saving, VoidCallback applied) async {
    final error = await saving;
    if (!mounted) return;
    setState(() {
      _error = error;
      if (error == null) applied();
    });
  }

  /// The Unattended Password, typed here, to turn "Always ask for password" on; null if cancelled.
  Future<String?> _askPassword() {
    final typed = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Always ask for password'),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(alwaysAskAsk()),
          const SizedBox(height: Kit.s3),
          TextField(
            controller: typed,
            obscureText: true,
            autofocus: true,
            onSubmitted: (v) => Navigator.of(context).pop(v),
          ),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Kit.paper, foregroundColor: Kit.ink),
            onPressed: () => Navigator.of(context).pop(typed.text),
            child: const Text('Turn on'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return ListView(
      padding: const EdgeInsets.all(Kit.s6),
      children: [
        Text(kTrustedTitle, style: t.headlineSmall),
        const SizedBox(height: Kit.s2),
        if (widget.waiting != null) widget.waiting!,
        Text('These computers get into this one without asking. Remove one and it has to ask again.',
            style: t.bodySmall),
        if (widget.onNewAlwaysAsk != null)
          SwitchListTile(
            key: const ValueKey('new-always-ask'),
            title: const Text('New computers always ask for password'),
            subtitle: Text(kNewAlwaysAskWhy, style: t.bodySmall),
            value: _newAlwaysAsk,
            onChanged: (on) async {
              await widget.onNewAlwaysAsk!(on);
              if (mounted) setState(() => _newAlwaysAsk = on);
            },
            contentPadding: EdgeInsets.zero,
          ),
        if (_error != null) ...[
          const SizedBox(height: Kit.s2),
          Text(_error!, style: t.bodyMedium),
        ],
        const SizedBox(height: Kit.s4),
        if (_trusted.isEmpty) Text('None yet. A computer lands here once you allow it in.'),
        for (final c in _trusted) ...[
          ListTile(
            contentPadding: EdgeInsets.zero,
            title: Text(c.name.isNotEmpty ? c.name : 'A computer with no name'),
            trailing: TextButton(
              onPressed: () => _save(widget.onRemove(c.key), () => _trusted.remove(c)),
              child: const Text('Remove'),
            ),
          ),
          if (widget.onAlwaysAsk != null)
            SwitchListTile(
              key: ValueKey('always-ask-${c.key}'),
              title: const Text('Always ask for password'),
              subtitle: Text(alwaysAskWhy(), style: t.bodySmall),
              value: _alwaysAsk[c.key] ?? false,
              onChanged: (on) async {
                final password = on ? await _askPassword() : '';
                if (password == null || !mounted) return;
                await _save(widget.onAlwaysAsk!(c.key, on, password), () => _alwaysAsk[c.key] = on);
              },
              contentPadding: EdgeInsets.zero,
            ),
        ],
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
                Expanded(child: Text(c.name.isNotEmpty ? c.name : 'A computer with no name')),
                const SizedBox(width: Kit.s3),
                FilledButton(
                  style: FilledButton.styleFrom(
                    minimumSize: const Size(120, 48),
                    backgroundColor: Kit.paper,
                    foregroundColor: Kit.ink,
                  ),
                  onPressed: () => _save(widget.onAllow!(c), () {
                    _removed.remove(c);
                    _trusted.add(c);
                  }),
                  child: const Text('Allow'),
                ),
              ]),
            ),
        ],
        const SizedBox(height: Kit.s6),
        Text('Computers this one has connected to', style: t.bodySmall),
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
            title: Text(m.address.isNotEmpty ? m.address : 'A computer you connected to'),
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

/// The helper line under each "Always ask for password" switch.
String alwaysAskWhy() => "It needs this ${KitWords.one}'s Unattended Password every time it connects. "
    'Turning it on makes every computer that saved the password type it again.';

/// What turning it on asks for.
String alwaysAskAsk() => "Type this ${KitWords.one}'s Unattended Password to turn this on.";

const kNewAlwaysAskWhy = 'Computers let in from now on start with Always ask for password on.';

/// The Settings link and page title for who gets in without asking ("Controller" stays internal).
const kTrustedTitle = 'Trusted list';

/// The ask in plain words: who, and what it wants (the connection window and the main window).
/// boring-remote (v1.7 t29): [files] is a transfer-only connection, which has no screen to control.
String approvalQuestion(String name, {bool files = false}) {
  final who = name.trim().isNotEmpty ? name.trim() : 'A computer on this network';
  return files ? '$who wants to transfer files with this ${KitWords.one}.' : '$who wants to control this ${KitWords.one}.';
}

/// What the ask knows about who it is (audit H1): new or removed earlier, and its address.
/// Nothing for a Trusted one, which never asks. Unknown counts as new.
String approvalWho(String trust, String ip) {
  final at = ip.trim().isNotEmpty ? ', at ${ip.trim()}.' : '.';
  switch (trust) {
    case 'trusted':
      return '';
    case 'removed':
      return 'Removed earlier from the Trusted list$at';
    default:
      return 'New computer$at';
  }
}

/// Hex characters of a Trusted Controllers key an ask carries (libs/base/src/trust.rs KEY_PREFIX_LEN).
const kTrustKeyPrefixLen = 16;

const kApprovalWhy = "If you allow it, it can get in next time without asking. You can remove it in Settings.";

/// What the Target shows when an unknown Mac asks to come in. Plain words, two choices.
/// It scrolls rather than clips when the connection window is short.
class ApprovalPrompt extends StatelessWidget {
  final String name;
  final String trust;
  final String ip;
  final bool files; // a transfer-only connection (v1.7 t29)
  final VoidCallback onAllow;
  final VoidCallback onDeny;

  const ApprovalPrompt(
      {super.key,
      required this.name,
      this.trust = '',
      this.ip = '',
      this.files = false,
      required this.onAllow,
      required this.onDeny});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(Kit.s4),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(approvalQuestion(name, files: files), style: t.titleMedium),
          if (approvalWho(trust, ip).isNotEmpty) Text(approvalWho(trust, ip), style: t.bodyMedium),
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
