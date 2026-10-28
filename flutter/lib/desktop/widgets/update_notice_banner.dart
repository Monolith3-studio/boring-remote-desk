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

// Re-read live session state this often while the banner is up.
const Duration kBoringSessionPoll = Duration(seconds: 5);

// What a failed `main_install_update` word means to the user.
// TODO(humanizer): run these past the humanizer before ship.
const Map<String, String> kBoringInstallErrorText = {
  'no-key': 'Add your License key in Settings first.',
  'live-session': 'Finish your session to update.',
  'no-release': 'This update can only be downloaded from your purchase email.',
  'download': "Couldn't download the update. Try again later.",
  'timeout': 'The download took too long. Try again later.',
  'sha256': "The download didn't match. Nothing was changed.",
  'signature': "The update isn't signed by us. Nothing was changed.",
  'script': "The update didn't install. Nothing was changed.",
};

/// One answer from the Rust check: the newer version, and whether this build is
/// below the version file's Minimum version (then the banner can't be dismissed).
/// With [failedTo] set, an update to that version was rolled back and [version]
/// is the one still running (spec slice 7); Rust reports it only once.
class UpdateNotice {
  final String version;
  final bool belowMin;
  final String? failedTo;
  const UpdateNotice(this.version, {this.belowMin = false, this.failedTo});

  /// Parses `main_check_update_notice`'s `{"version","below_min"}` or
  /// `{"failed","running"}` JSON; null on none or junk.
  static UpdateNotice? fromBridge(String? json) {
    if (json == null) return null;
    try {
      final m = jsonDecode(json);
      final f = m['failed'], r = m['running'];
      if (f is String && r is String) return UpdateNotice(r, failedTo: f);
      final v = m['version'];
      if (v is! String) return null;
      return UpdateNotice(v, belowMin: m['below_min'] == true);
    } catch (_) {
      return null;
    }
  }
}

/// Shows "Boring Remote X.Y.Z is out." With a License key ([hasKey]) the button
/// is "Install update" ([install] wraps `main_install_update`, ADR 0004); during
/// a live session it is disabled with "Finish your session to update". Without
/// a key it is "Get update", which opens a web page (ADR 0003).
/// [check] wraps the Rust bridge `mainCheckUpdateNotice`; [isEnabled] reads the
/// `boring-update-check` local option. Both are injected so tests need no bridge.
class UpdateNoticeBanner extends StatefulWidget {
  final Future<UpdateNotice?> Function() check;
  final bool Function() isEnabled;
  final Future<void> Function(Uri) openUrl;
  final bool Function()? hasKey;
  final Future<bool> Function()? liveSession;
  final Future<String> Function()? install;

  const UpdateNoticeBanner({
    super.key,
    required this.check,
    required this.isEnabled,
    required this.openUrl,
    this.hasKey,
    this.liveSession,
    this.install,
  });

  @override
  State<UpdateNoticeBanner> createState() => _UpdateNoticeBannerState();
}

class _UpdateNoticeBannerState extends State<UpdateNoticeBanner> {
  Timer? _timer;
  Timer? _sessionTimer;
  UpdateNotice? _notice;
  bool _live = false;
  bool _installing = false;
  String? _error;
  // Version the user dismissed this run; a newer one shows again.
  String? _dismissed;

  @override
  void initState() {
    super.initState();
    _run();
    _timer = Timer.periodic(kBoringUpdateRecheckInterval, (_) => _run());
    if (widget.liveSession != null) {
      _poll();
      _sessionTimer = Timer.periodic(kBoringSessionPoll, (_) => _poll());
    }
  }

  Future<void> _poll() async {
    if (_notice == null && _live == false) return;
    bool live;
    try {
      live = await widget.liveSession!();
    } catch (_) {
      return;
    }
    if (mounted && live != _live) setState(() => _live = live);
  }

  Future<void> _install() async {
    setState(() {
      _installing = true;
      _error = null;
    });
    String r;
    try {
      r = await widget.install!();
    } catch (_) {
      r = 'script';
    }
    if (!mounted) return;
    setState(() {
      _installing = false;
      _error = r == 'ok' ? null : (kBoringInstallErrorText[r] ?? kBoringInstallErrorText['script']);
    });
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
    if (v != null && widget.liveSession != null) _poll();
  }

  @override
  void dispose() {
    _timer?.cancel();
    _sessionTimer?.cancel();
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
    if (n.failedTo != null) {
      // TODO(humanizer): run past the humanizer before ship.
      return Container(
        margin: const EdgeInsets.only(top: 20),
        padding: const EdgeInsets.all(20),
        color: Theme.of(context).colorScheme.primary,
        child: Row(children: [
          Expanded(
              child: Text('Update failed, still on $v.',
                  style: TextStyle(color: onFill, fontSize: 14))),
          IconButton(
            tooltip: 'Dismiss',
            icon: Icon(Icons.close, color: onFill, size: 18),
            onPressed: () => setState(() => _dismissed = v),
          ),
        ]),
      );
    }
    final canInstall = widget.install != null && (widget.hasKey?.call() ?? false);
    return Container(
      margin: const EdgeInsets.only(top: 20),
      padding: const EdgeInsets.all(20),
      color: Theme.of(context).colorScheme.primary,
      child: Row(children: [
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Boring Remote $v is out.',
                style: TextStyle(color: onFill, fontSize: 14)),
            if (_error != null)
              Text(_error!, style: TextStyle(color: onFill, fontSize: 13)),
          ]),
        ),
        if (canInstall)
          TextButton(
            onPressed: (_live || _installing) ? null : _install,
            child: Text(_live ? 'Finish your session to update' : 'Install update',
                style: TextStyle(color: onFill)),
          )
        else
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
