import 'package:flutter/material.dart';

/// Local option the key lives in (written by src/license_key_run.rs).
const String kBoringLicenseKeyOption = 'boring-license-key';

/// Status word from the Rust bridge `mainSetLicenseKey` → what the buyer reads.
/// "network" and "busy" say the key's state is not known; they never call it invalid.
const Map<String, String> kLicenseKeyStatusText = {
  'valid': 'Key is valid.',
  'revoked': 'This key was revoked.',
  'refunded': 'This key was refunded.',
  'unknown': "We don't know this key. Check it against your purchase email.",
  'busy': 'Too many checks. Try again in a minute.',
  'network': "Couldn't reach the store. Your key is saved; check your connection.",
  'none': 'No key saved.',
};

/// Settings field: paste the License key once, press Check. [setKey] wraps the
/// bridge (stores the key, then asks fulfillment); injected so tests need no bridge.
class LicenseKeyField extends StatefulWidget {
  final String initialKey;
  final Future<String> Function(String) setKey;

  const LicenseKeyField({super.key, required this.initialKey, required this.setKey});

  @override
  State<LicenseKeyField> createState() => _LicenseKeyFieldState();
}

class _LicenseKeyFieldState extends State<LicenseKeyField> {
  late final TextEditingController _c = TextEditingController(text: widget.initialKey);
  String? _status;
  bool _busy = false;

  Future<void> _check() async {
    setState(() => _busy = true);
    String s;
    try {
      s = await widget.setKey(_c.text);
    } catch (_) {
      s = 'network';
    }
    if (mounted) setState(() {
      _busy = false;
      _status = s;
    });
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final status = _busy ? 'Checking…' : kLicenseKeyStatusText[_status];
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        Expanded(
          child: TextField(
            controller: _c,
            decoration: const InputDecoration(labelText: 'License key'),
          ),
        ),
        TextButton(onPressed: _busy ? null : _check, child: const Text('Check')),
      ]),
      if (status != null) Text(status, style: const TextStyle(fontSize: 14)),
    ]);
  }
}
