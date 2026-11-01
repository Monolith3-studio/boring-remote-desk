import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'kit.dart';
import 'lan_macs.dart';

/// One Mac on Home: the name a buyer sees, and the opaque target the caller connects to.
class MacEntry {
  final String name;
  final String target;
  const MacEntry({required this.name, required this.target});
}

/// Mac Home (v1.7): one Address box and the Macs list. Bridge-free; the home page passes data and callbacks.
class MacHome extends StatefulWidget {
  static const addressKey = Key('mac-home-address');

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

  /// Page-level notices (the update banner), shown above the Address box.
  final List<Widget> notices;

  const MacHome({
    super.key,
    required this.macs,
    required this.tailscaleAddress,
    required this.onConnect,
    this.notices = const [],
    this.lan = const [],
    this.discover,
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

  /// Return connects to the Mac whose name matches (any case): one on this network first (its IP),
  /// then a recent one, else to whatever was typed (an IP).
  void _submit(String text) {
    final q = text.trim();
    if (q.isEmpty) return;
    final low = q.toLowerCase();
    final here = widget.lan.where((m) => m.name.toLowerCase() == low);
    final recent = widget.macs.where((m) => m.name.toLowerCase() == low);
    widget.onConnect(here.isNotEmpty ? here.first.ip : (recent.isNotEmpty ? recent.first.target : q));
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
          Text('Connect to a ${KitWords.one}', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: Kit.s4),
          TextField(
            key: MacHome.addressKey,
            controller: _address,
            autofocus: true,
            decoration: InputDecoration(
              hintText: "Type a ${KitWords.one}'s name",
              prefixIcon: const Icon(Icons.search, color: Kit.muted),
            ),
            onChanged: (_) => setState(() {}),
            onSubmitted: _submit,
          ),
          const SizedBox(height: Kit.s5),
          Text(KitWords.cap(KitWords.many), style: Theme.of(context).textTheme.bodySmall),
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
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Kit.radius)),
                      hoverColor: Kit.glass,
                      onTap: () => widget.onConnect(m.ip),
                    ),
                ],
                if (widget.macs.isEmpty && widget.lan.isEmpty) ...[
                  Text(
                      'No other ${KitWords.many} found yet. Open Boring Remote on the other ${KitWords.one}. '
                      "You'll see it here once both are on the same network."),
                  const SizedBox(height: Kit.s2),
                  Text('Or type its address above, like 192.168.1.20.',
                      style: Theme.of(context).textTheme.bodySmall),
                ],
                if (shown.isNotEmpty) Text('Used before', style: Theme.of(context).textTheme.bodySmall),
                for (final m in shown)
                  ListTile(
                    leading: const Icon(Icons.desktop_mac_outlined),
                    title: Text(m.name),
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
                builder: (_) => OutsideBuildingSheet(tailscaleAddress: widget.tailscaleAddress),
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
class OutsideBuildingSheet extends StatefulWidget {
  final Future<String?> Function() tailscaleAddress;
  const OutsideBuildingSheet({super.key, required this.tailscaleAddress});

  @override
  State<OutsideBuildingSheet> createState() => _OutsideBuildingSheetState();
}

class _OutsideBuildingSheetState extends State<OutsideBuildingSheet> {
  late Future<String?> _address = widget.tailscaleAddress();
  bool _copied = false;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final one = KitWords.one, many = KitWords.many;
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
              if (snap.connectionState != ConnectionState.done)
                Text('Checking…', style: t.bodySmall)
              else if (address != null) ...[
                Text('From another network, type this on the other $one:'),
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
                Text('It works while Tailscale is open on both $many. '
                    'Tailscale is a free app that links your computers over the internet.',
                    style: t.bodySmall),
              ] else ...[
                Text('To reach this $one from another network, both $many need Tailscale. '
                    'Tailscale is a free app that links your computers over the internet.'),
                const SizedBox(height: Kit.s3),
                Text('1. Get Tailscale from tailscale.com. Install it on this $one and on the other one.'),
                const SizedBox(height: Kit.s2),
                Text('2. Open Tailscale on both and sign in with the same account.'),
                const SizedBox(height: Kit.s2),
                Text("3. Click Check again. You'll see what to type on the other $one."),
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
