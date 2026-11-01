import 'dart:convert';
import 'dart:io';

import 'kit.dart';

/// A Boring Remote Mac that answered LAN Discovery on this network.
class LanMac {
  final String name;
  final String ip;
  const LanMac({required this.name, required this.ip});
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
            name: (p['hostname'] ?? '').toString().isNotEmpty ? p['hostname'].toString() : 'Unnamed ${KitWords.one}',
            ip: p['ip'].toString(),
          ),
    ];
  } catch (_) {
    return [];
  }
}

/// Name substring (any case) or IP prefix.
List<LanMac> filterLanMacs(List<LanMac> macs, String query) {
  final q = query.trim().toLowerCase();
  return macs.where((m) => m.name.toLowerCase().contains(q) || m.ip.startsWith(q)).toList();
}

bool isBareIp(String text) => InternetAddress.tryParse(text.trim()) != null;
