import 'dart:io';

/// The way in from outside the building is Tailscale (ADR 0004). This computer's Tailscale address
/// is what the other computer types on Home; same ranges as rebrand.TAILNET.
bool isTailscaleAddress(InternetAddress a) {
  final b = a.rawAddress;
  if (a.type == InternetAddressType.IPv4) return b[0] == 100 && (b[1] & 0xc0) == 64; // 100.64.0.0/10
  return a.type == InternetAddressType.IPv6 &&
      b[0] == 0xfd && b[1] == 0x7a && b[2] == 0x11 && b[3] == 0x5c && b[4] == 0xa1 && b[5] == 0xe0; // fd7a:115c:a1e0::/48
}

/// The address to give out: IPv4 first (shorter to type), else IPv6, else null.
String? tailscaleAddressIn(Iterable<InternetAddress> addresses) {
  final ts = addresses.where(isTailscaleAddress).toList();
  if (ts.isEmpty) return null;
  final v4 = ts.where((a) => a.type == InternetAddressType.IPv4);
  return (v4.isNotEmpty ? v4.first : ts.first).address;
}

/// This computer's Tailscale address, read from its network interfaces; null when Tailscale is not up.
Future<String?> thisTailscaleAddress() async {
  try {
    final interfaces = await NetworkInterface.list(includeLoopback: false, type: InternetAddressType.any);
    return tailscaleAddressIn(interfaces.expand((i) => i.addresses));
  } catch (_) {
    return null;
  }
}
