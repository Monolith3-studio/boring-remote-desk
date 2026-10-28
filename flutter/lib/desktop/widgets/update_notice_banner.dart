import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';

// ASSUMPTION (unconfirmed by Jason, spec "Assumptions"): the page that tells
// buyers to use the Download Link in their purchase email. Confirm before
// this ships. This is the only place the URL lives.
const kBoringUpdatePageUrl = 'https://boringlabs.online/remote/update';

/// Local option that turns the check off when set to "N" (read in src/update_notice_run.rs).
const String kBoringUpdateCheckOption = 'boring-update-check';

// UI re-check cadence; the Rust side gates the real network fetch to once per 24 h.
const Duration kBoringUpdateRecheckInterval = Duration(hours: 1);

/// One answer from the Rust check: the newer version, and whether this build is
/// below the version file's Minimum version (then the banner can't be dismissed).
class UpdateNotice {
  final String version;
  final bool belowMin;
  const UpdateNotice(this.version, {this.belowMin = false});

  /// Parses `main_check_update_notice`'s `{"version","below_min"}` JSON; null on none or junk.
  static UpdateNotice? fromBridge(String? json) {
    if (json == null) return null;
    try {
      final m = jsonDecode(json);
      final v = m['version'];
      if (v is! String) return null;
      return UpdateNotice(v, belowMin: m['below_min'] == true);
    } catch (_) {
      return null;
    }
  }
}

/// Notice only (ADR 0003): shows "Boring Remote X.Y.Z is out." and a button
/// that opens a web page. Never downloads or installs anything.
/// [check] wraps the Rust bridge `mainCheckUpdateNotice`; [isEnabled] reads the
/// `boring-update-check` local option. Both are injected so tests need no bridge.
class UpdateNoticeBanner extends StatefulWidget {
  final Future<UpdateNotice?> Function() check;
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
  UpdateNotice? _notice;
  // Version the user dismissed this run; a newer one shows again.
  String? _dismissed;

  @override
  void initState() {
    super.initState();
    _run();
    _timer = Timer.periodic(kBoringUpdateRecheckInterval, (_) => _run());
  }

  Future<void> _run() async {
    if (!widget.isEnabled()) {
      if (_notice != null && mounted) setState(() => _notice = null);
      return;
    }
    UpdateNotice? v;
    try {
      v = await widget.check();
    } catch (_) {
      return; // keep last good answer
    }
    if (mounted) setState(() => _notice = v);
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final n = _notice;
    if (n == null || (!n.belowMin && _dismissed == n.version)) {
      return const SizedBox.shrink();
    }
    final v = n.version;
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
        // Below the Minimum version the notice can't be dismissed.
        if (!n.belowMin)
          IconButton(
            tooltip: 'Dismiss',
            icon: Icon(Icons.close, color: onFill, size: 18),
            onPressed: () => setState(() => _dismissed = v),
          ),
      ]),
    );
  }
}
