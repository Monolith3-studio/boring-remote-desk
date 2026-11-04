import 'dart:convert';
import 'dart:io';

import 'kit.dart';

/// A Boring Remote Mac that answered LAN Discovery on this network.
class LanMac {
  final String name;
  final String ip;

  /// boring-remote (v1.7 t25): its Target ID. The same computer stays one row when its best address changes.
  final String id;
  const LanMac({required this.name, required this.ip, this.id = ''});
}

/// Reads the `load_lan_peers` JSON (get_lan_peers in src/ui_interface.rs).
/// A peer with no allowed IP can't be reached Direct, so it isn't listed.
List<LanMac> lanMacsFromJson(String json) {
  try {
    final list = jsonDecode(json) as List<dynamic>;
    return [
      for (final p in list.cast<Map<String, dynamic>>())
        if ((p['ip'] ?? '').toString().isNotEmpty)
          LanMac(
            name: (p['hostname'] ?? '').toString().isNotEmpty ? p['hostname'].toString() : KitWords.unnamed,
            ip: p['ip'].toString(),
            id: (p['id'] ?? '').toString(),
          ),
    ];
  } catch (_) {
    return [];
  }
}

/// When a listed Mac last answered. Keyed by Target ID, else IP, in [keepRecentLanMacs]'s memory.
typedef LanSeen = ({LanMac mac, DateTime at});

/// One LAN Discovery round can miss a reply; without this the row blinks out under the cursor.
/// Keeps each Mac listed, in first-seen order, until it has been silent for [grace].
List<LanMac> keepRecentLanMacs(Map<String, LanSeen> memory, List<LanMac> fresh, DateTime now,
    {Duration grace = const Duration(seconds: 20)}) {
  for (final m in fresh) {
    memory[m.id.isNotEmpty ? m.id : m.ip] = (mac: m, at: now);
  }
  memory.removeWhere((_, s) => now.difference(s.at) > grace);
  return [for (final s in memory.values) s.mac];
}

/// Name substring (any case) or IP prefix.
List<LanMac> filterLanMacs(List<LanMac> macs, String query) {
  final q = query.trim().toLowerCase();
  return macs.where((m) => m.name.toLowerCase().contains(q) || m.ip.startsWith(q)).toList();
}

bool isBareIp(String text) => InternetAddress.tryParse(text.trim()) != null;
