import 'dart:async';

import 'package:flutter/material.dart';

// ASSUMPTION (unconfirmed by Jason, spec "Assumptions"): the page that tells
// buyers to use the Download Link in their purchase email. Confirm before
// this ships. This is the only place the URL lives.
const kBoringUpdatePageUrl = 'https://boringlabs.online/remote/update';

/// Local option that turns the check off when set to "N" (read in src/update_notice_run.rs).
const String kBoringUpdateCheckOption = 'boring-update-check';

// UI re-check cadence; the Rust side gates the real network fetch to once per 24 h.
const Duration kBoringUpdateRecheckInterval = Duration(hours: 1);

/// Notice only (ADR 0003): shows "Boring Remote X.Y.Z is out." and a button
/// that opens a web page. Never downloads or installs anything.
/// [check] wraps the Rust bridge `mainCheckUpdateNotice`; [isEnabled] reads the
/// `boring-update-check` local option. Both are injected so tests need no bridge.
class UpdateNoticeBanner extends StatefulWidget {
  final Future<String?> Function() check;
  final bool Function() isEnabled;
  final Future<void> Function(Uri) openUrl;

  const UpdateNoticeBanner({
    super.key,
    required this.check,
    required this.isEnabled,
    required this.openUrl,
  });

  @override
  State<UpdateNoticeBanner> createState() => _UpdateNoticeBannerState();
}

class _UpdateNoticeBannerState extends State<UpdateNoticeBanner> {
  Timer? _timer;
  String? _version;

  @override
  void initState() {
    super.initState();
    _run();
    _timer = Timer.periodic(kBoringUpdateRecheckInterval, (_) => _run());
  }

  Future<void> _run() async {
    if (!widget.isEnabled()) {
      if (_version != null && mounted) setState(() => _version = null);
      return;
    }
    String? v;
    try {
      v = await widget.check();
    } catch (_) {
      return; // keep last good answer
    }
    if (mounted) setState(() => _version = v);
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final v = _version;
    if (v == null) return const SizedBox.shrink();
    final onFill = Theme.of(context).colorScheme.onPrimary;
    return Container(
      margin: const EdgeInsets.only(top: 20),
      padding: const EdgeInsets.all(20),
      color: Theme.of(context).colorScheme.primary,
      child: Row(children: [
        Expanded(
          child: Text('Boring Remote $v is out.',
              style: TextStyle(color: onFill, fontSize: 14)),
        ),
        TextButton(
          onPressed: () => widget.openUrl(Uri.parse(kBoringUpdatePageUrl)),
          child: Text('Get update', style: TextStyle(color: onFill)),
        ),
      ]),
    );
  }
}
