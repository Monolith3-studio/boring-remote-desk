import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'kit.dart';
import 'lan_macs.dart';

/// One Mac on Home: the name a buyer sees, and the opaque target the caller connects to.
class MacEntry {
  final String name;
  final String target;

  /// The Target's pinned trust key when it has one (trust.dart [identitiesFromKnown]), else ''.
  final String identity;
  const MacEntry({required this.name, required this.target, this.identity = ''});
}

/// boring-remote (v1.7 t26): "Used before" shows each machine once. A session's PeerConfig is saved
/// under the address dialled, so one machine has one entry per name, Wi-Fi IP, wired IP and
/// Tailscale IP. [newestFirst] is in recents order, so the first entry seen is the newest address.
/// Same trust key = same machine; an entry with no key joins the machine of that display name; a
/// nameless one with no key stays apart, since nothing says it is the same machine. Different keys
/// under one name are two machines. This only narrows what Home shows: nothing leaves disk, and any
/// older address still connects when typed.
List<MacEntry> oneEntryPerMachine(List<MacEntry> newestFirst) {
  final kept = <MacEntry>[];
  final keys = <String>[]; // the trust key each kept row stands for, '' while it has none
  String named(MacEntry e) => e.name.trim().toLowerCase();
  for (final e in newestFirst) {
    final sameName = e.name == KitWords.unnamed
        ? const <int>[]
        : [for (var i = 0; i < kept.length; i++) if (named(kept[i]) == named(e)) i];
    if (e.identity.isEmpty) {
      if (sameName.isNotEmpty) continue;
    } else {
      if (keys.contains(e.identity)) continue;
      final noKey = sameName.where((i) => keys[i].isEmpty);
      if (noKey.isNotEmpty) {
        keys[noKey.first] = e.identity; // the newer row of this name is this machine
        continue;
      }
    }
    kept.add(e);
    keys.add(e.identity);
  }
  return kept;
}

/// Mac Home (v1.7): one Address box and the Macs list. Bridge-free; the home page passes data and callbacks.
class MacHome extends StatefulWidget {
  static const addressKey = Key('mac-home-address');
  static const addressTransferKey = Key('mac-home-address-transfer');

  /// boring-remote (v1.7 t29): the button that opens a transfer-only connection, with no remote screen.
  static const transferFiles = 'Transfer files';

  /// What Home says while no other Boring Remote has answered on this network (ticket 21).
  static List<String> emptyLines() => [
        'No other computers found on this network yet.',
        '1. Open Boring Remote on the other computer and finish its Setup.',
        '2. Check both are on the same Wi-Fi or network.',
        "It shows up here by itself within a few seconds.",
      ];
  static const emptyTypeIt = 'Or type its address above, like 192.168.1.20.';

  /// One LAN Discovery cycle listens ~3 s; asking again every 6 s keeps the list live.
  static const discoverEvery = Duration(seconds: 6);

  final List<MacEntry> macs;

  /// Macs that answered LAN Discovery on this network.
  final List<LanMac> lan;

  /// Starts a LAN Discovery cycle; called on open and every [discoverEvery].
  final VoidCallback? discover;

  /// This computer's Tailscale address for the outside-the-building sheet (ADR 0004), null when
  /// Tailscale isn't up here. The page passes tailscale.dart's [thisTailscaleAddress].
  final Future<String?> Function() tailscaleAddress;
  final void Function(String target) onConnect;

  /// boring-remote (v1.7 t29): opens File Transfer alone for a machine. Null hides the buttons.
  final void Function(String target)? onTransferFiles;

  /// Page-level notices (the update banner), shown above the Address box.
  final List<Widget> notices;

  /// 1.8 (ADR 0005, ticket 07): this computer's Machine ID, what another computer types to reach it
  /// through the Hosted servers from anywhere; null or empty hides it. [hostedOn]: it has a
  /// password made in Settings, so the Hosted servers know it (ticket 09).
  final String? machineId;
  final bool hostedOn;

  const MacHome({
    super.key,
    required this.macs,
    required this.tailscaleAddress,
    required this.onConnect,
    this.onTransferFiles,
    this.notices = const [],
    this.lan = const [],
    this.discover,
    this.machineId,
    this.hostedOn = false,
  });

  @override
  State<MacHome> createState() => _MacHomeState();
}

class _MacHomeState extends State<MacHome> {
  final _address = TextEditingController();
  Timer? _discovery;

  @override
  void initState() {
    super.initState();
    final discover = widget.discover;
    if (discover != null) {
      discover();
      _discovery = Timer.periodic(MacHome.discoverEvery, (_) => discover());
    }
  }

  @override
  void dispose() {
    _discovery?.cancel();
    _address.dispose();
    super.dispose();
  }

  /// What the Address box dials: the Mac whose name matches (any case), one on this network first
  /// (its IP), then a recent one, else whatever was typed (an IP).
  String _typedTarget(String text) {
    final q = text.trim();
    // 1.8: a Machine ID typed in groups ("123 456 789") is the Machine ID.
    final digits = q.replaceAll(RegExp(r'[\s-]'), '');
    if (digits.isNotEmpty && RegExp(r'^\d+$').hasMatch(digits)) return digits;
    final low = q.toLowerCase();
    final here = widget.lan.where((m) => m.name.toLowerCase() == low);
    final recent = widget.macs.where((m) => m.name.toLowerCase() == low);
    return here.isNotEmpty ? here.first.ip : (recent.isNotEmpty ? recent.first.target : q);
  }

  void _submit(String text) {
    if (text.trim().isNotEmpty) widget.onConnect(_typedTarget(text));
  }

  /// boring-remote (v1.7 t29): the row or the box means control; this button means transfer only.
  /// Coral marks keyboard focus, as it does on the Address box.
  Widget? _transferButton(String Function() target, {Key? key}) {
    final open = widget.onTransferFiles;
    if (open == null) return null;
    return OutlinedButton(
      key: key,
      style: ButtonStyle(
        side: WidgetStateProperty.resolveWith((states) => BorderSide(
            color: states.contains(WidgetState.focused) ? Kit.coral : Kit.muted,
            width: states.contains(WidgetState.focused) ? 1.5 : 1)),
      ),
      onPressed: () => open(target()),
      child: const Text(MacHome.transferFiles),
    );
  }

  @override
  Widget build(BuildContext context) {
    final q = _address.text.trim().toLowerCase();
    final shown = widget.macs.where((m) => m.name.toLowerCase().contains(q)).toList();
    final here = filterLanMacs(widget.lan, q);
    final typedIp = isBareIp(q) && !widget.lan.any((m) => m.ip == q) ? q : null;
    return Padding(
      padding: const EdgeInsets.all(Kit.s6),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ...widget.notices,
          Text('Connect to a computer', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: Kit.s4),
          TextField(
            key: MacHome.addressKey,
            controller: _address,
            autofocus: true,
            decoration: InputDecoration(
              hintText: "Type a computer's name or Machine ID",
              prefixIcon: const Icon(Icons.search, color: Kit.muted),
              // boring-remote (v1.7 t29): Return is control, this is transfer, for the same target.
              suffixIcon: q.isEmpty || widget.onTransferFiles == null
                  ? null
                  : Padding(
                      padding: const EdgeInsets.only(right: Kit.s2),
                      child: _transferButton(() => _typedTarget(_address.text), key: MacHome.addressTransferKey),
                    ),
            ),
            onChanged: (_) => setState(() {}),
            onSubmitted: _submit,
          ),
          const SizedBox(height: Kit.s5),
          Text('Computers', style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: Kit.s2),
          Expanded(
            child: ListView(
              children: [
                if (typedIp != null)
                  ListTile(
                    leading: const Icon(Icons.arrow_forward),
                    title: Text('Connect to $typedIp'),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Kit.radius)),
                    hoverColor: Kit.glass,
                    onTap: () => widget.onConnect(typedIp),
                  ),
                if (here.isNotEmpty) ...[
                  Text('On this network', style: Theme.of(context).textTheme.bodySmall),
                  for (final m in here)
                    ListTile(
                      leading: const Icon(Icons.lan_outlined),
                      title: Text(m.name),
                      subtitle: Text(m.ip, style: const TextStyle(color: Kit.muted)),
                      trailing: _transferButton(() => m.ip),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Kit.radius)),
                      hoverColor: Kit.glass,
                      onTap: () => widget.onConnect(m.ip),
                    ),
                ],
                if (widget.lan.isEmpty && q.isEmpty) ...[
                  Text('On this network', style: Theme.of(context).textTheme.bodySmall),
                  const SizedBox(height: Kit.s2),
                  for (final line in MacHome.emptyLines()) ...[Text(line), const SizedBox(height: Kit.s2)],
                  Text(MacHome.emptyTypeIt, style: Theme.of(context).textTheme.bodySmall),
                  const SizedBox(height: Kit.s4),
                ],
                if (shown.isNotEmpty) Text('Used before', style: Theme.of(context).textTheme.bodySmall),
                for (final m in shown)
                  ListTile(
                    leading: const Icon(Icons.desktop_mac_outlined),
                    title: Text(m.name),
                    trailing: _transferButton(() => m.target),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Kit.radius)),
                    hoverColor: Kit.glass,
                    onTap: () => widget.onConnect(m.target),
                  ),
              ],
            ),
          ),
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton.icon(
              icon: const Icon(Icons.public, size: 18),
              label: const Text('Connect from outside the building'),
              onPressed: () => showModalBottomSheet<void>(
                context: context,
                isScrollControlled: true,
                builder: (_) => OutsideBuildingSheet(
                    tailscaleAddress: widget.tailscaleAddress, machineId: widget.machineId, hostedOn: widget.hostedOn),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// For a computer that isn't on this network: the way in is Tailscale (ADR 0004), so the thing to
/// type over there is this computer's Tailscale address. No Tailscale here: how to get it.
/// 1.8: a Machine ID shown in groups of three, as people read it out.
String machineIdGroups(String id) {
  final b = StringBuffer();
  for (var i = 0; i < id.length; i++) {
    if (i > 0 && (id.length - i) % 3 == 0) b.write(' ');
    b.write(id[i]);
  }
  return b.toString();
}

class OutsideBuildingSheet extends StatefulWidget {
  final Future<String?> Function() tailscaleAddress;

  /// 1.8: this computer's Machine ID (the Hosted servers' way in); null or empty hides it.
  final String? machineId;
  final bool hostedOn;
  const OutsideBuildingSheet({super.key, required this.tailscaleAddress, this.machineId, this.hostedOn = false});

  @override
  State<OutsideBuildingSheet> createState() => _OutsideBuildingSheetState();
}

class _OutsideBuildingSheetState extends State<OutsideBuildingSheet> {
  late Future<String?> _address = widget.tailscaleAddress();
  bool _copied = false, _idCopied = false;

  /// 1.8: the Machine ID first; Tailscale is the backup path below it.
  List<Widget> _machineId(TextTheme t, String one) {
    final id = widget.machineId ?? '';
    if (id.isEmpty) return const [];
    return [
      Text('From anywhere, type this $one\'s Machine ID on the other computer:'),
      const SizedBox(height: Kit.s3),
      Row(children: [
        Flexible(child: SelectableText(machineIdGroups(id), style: t.headlineSmall)),
        const SizedBox(width: Kit.s4),
        OutlinedButton(
          onPressed: () async {
            await Clipboard.setData(ClipboardData(text: id));
            if (mounted) setState(() => _idCopied = true);
          },
          child: Text(_idCopied ? 'Copied' : 'Copy'),
        ),
      ]),
      const SizedBox(height: Kit.s3),
      if (!widget.hostedOn)
        Text('It works once this $one has a password made in Settings.', style: t.bodySmall)
      else
        Text('The other computer also needs this $one\'s password, and someone here clicks Allow the first time.',
            style: t.bodySmall),
      const SizedBox(height: Kit.s5),
      Text('Or use Tailscale', style: t.titleMedium),
      const SizedBox(height: Kit.s3),
    ];
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final one = KitWords.one; // this machine; the other end is a computer (t26)
    return SingleChildScrollView(
      padding: const EdgeInsets.all(Kit.s6),
      child: FutureBuilder<String?>(
        future: _address,
        builder: (context, snap) {
          final address = snap.data;
          return Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Connect from outside the building', style: t.titleLarge),
              const SizedBox(height: Kit.s4),
              ..._machineId(t, one),
              if (snap.connectionState != ConnectionState.done)
                Text('Checking…', style: t.bodySmall)
              else if (address != null) ...[
                Text('From another network, type this on the other computer:'),
                const SizedBox(height: Kit.s3),
                Row(children: [
                  Flexible(child: SelectableText(address, style: t.headlineSmall)),
                  const SizedBox(width: Kit.s4),
                  OutlinedButton(
                    onPressed: () async {
                      await Clipboard.setData(ClipboardData(text: address));
                      if (mounted) setState(() => _copied = true);
                    },
                    child: Text(_copied ? 'Copied' : 'Copy'),
                  ),
                ]),
                const SizedBox(height: Kit.s3),
                Text('It works while Tailscale is open on both computers. '
                    'Tailscale is a free app that links your computers over the internet.',
                    style: t.bodySmall),
              ] else ...[
                Text('To reach this $one from another network, both computers need Tailscale. '
                    'Tailscale is a free app that links your computers over the internet.'),
                const SizedBox(height: Kit.s3),
                Text('1. Get Tailscale from tailscale.com. Install it on this $one and on the other one.'),
                const SizedBox(height: Kit.s2),
                Text('2. Open Tailscale on both and sign in with the same account.'),
                const SizedBox(height: Kit.s2),
                Text("3. Click Check again. You'll see what to type on the other computer."),
                const SizedBox(height: Kit.s3),
                OutlinedButton(
                  onPressed: () => setState(() {
                    _address = widget.tailscaleAddress();
                  }),
                  child: const Text('Check again'),
                ),
              ],
              const SizedBox(height: Kit.s5),
              Text('On the same network? Just pick this $one by name.', style: t.bodySmall),
            ],
          );
        },
      ),
    );
  }
}
