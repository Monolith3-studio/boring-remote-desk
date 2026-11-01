import 'package:flutter/material.dart';

import 'kit.dart';

/// One Mac on Home: the name a buyer sees, and the opaque target the caller connects to.
class MacEntry {
  final String name;
  final String target;
  const MacEntry({required this.name, required this.target});
}

/// Mac Home (v1.7): one Address box and the Macs list. Bridge-free; the home page passes data and callbacks.
class MacHome extends StatefulWidget {
  static const addressKey = Key('mac-home-address');

  final List<MacEntry> macs;
  final String myId;
  final void Function(String target) onConnect;

  /// Page-level notices (the update banner), shown above the Address box.
  final List<Widget> notices;

  const MacHome({
    super.key,
    required this.macs,
    required this.myId,
    required this.onConnect,
    this.notices = const [],
  });

  @override
  State<MacHome> createState() => _MacHomeState();
}

class _MacHomeState extends State<MacHome> {
  final _address = TextEditingController();

  @override
  void dispose() {
    _address.dispose();
    super.dispose();
  }

  /// Return connects to the one Mac whose name matches exactly, else to whatever was typed (an IP).
  void _submit(String text) {
    final q = text.trim();
    if (q.isEmpty) return;
    final hit = widget.macs.where((m) => m.name.toLowerCase() == q.toLowerCase());
    widget.onConnect(hit.isEmpty ? q : hit.first.target);
  }

  @override
  Widget build(BuildContext context) {
    final q = _address.text.trim().toLowerCase();
    final shown = widget.macs.where((m) => m.name.toLowerCase().contains(q)).toList();
    return Padding(
      padding: const EdgeInsets.all(Kit.s6),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ...widget.notices,
          Text('Connect to a Mac', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: Kit.s4),
          TextField(
            key: MacHome.addressKey,
            controller: _address,
            autofocus: true,
            decoration: const InputDecoration(
              hintText: 'Mac name or IP address',
              prefixIcon: Icon(Icons.search, color: Kit.muted),
            ),
            onChanged: (_) => setState(() {}),
            onSubmitted: _submit,
          ),
          const SizedBox(height: Kit.s5),
          Text('Macs', style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: Kit.s2),
          Expanded(
            child: ListView(
              children: [
                if (widget.macs.isEmpty)
                  Text('No Macs yet. Type a Mac name or IP above.',
                      style: Theme.of(context).textTheme.bodySmall),
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
                builder: (_) => OutsideBuildingSheet(id: widget.myId),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// The only place the numeric ID shows: for a Controller that isn't on this network.
class OutsideBuildingSheet extends StatelessWidget {
  final String id;
  const OutsideBuildingSheet({super.key, required this.id});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.all(Kit.s6),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Connect from outside the building', style: t.titleLarge),
          const SizedBox(height: Kit.s2),
          Text('On another network? Give them this ID. On the same network, they just pick this Mac by name.',
              style: t.bodySmall),
          const SizedBox(height: Kit.s5),
          SelectableText(id, style: t.headlineSmall),
        ],
      ),
    );
  }
}
