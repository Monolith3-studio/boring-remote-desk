import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import 'kit.dart';

export 'setup.dart' show kScreenRecordingPane, kAccessibilityPane, kInputMonitoringPane;

/// The per-user LaunchAgent that serves sessions (`--server`), and the port it listens on.
const kAgentLabel = 'io.boringlabs.remote.agent';
const kAgentPlist = '/Library/LaunchAgents/$kAgentLabel.plist';
const kDirectLinkPort = 21118;

/// launchctl's own line for the job, not its endpoints' (those say active).
final _agentUp = RegExp(r'^\tstate = running$', multiLine: true);
bool agentRunning(String launchctlPrint) => _agentUp.hasMatch(launchctlPrint);

typedef RunProcess = Future<ProcessResult> Function(String exe, List<String> args);

/// Start the agent (`--server`) and check it came up. `kickstart -k` alone is not enough: after
/// the app bundle is replaced, launchd can hold the job at "spawn failed" (EX_CONFIG 78, "needs
/// LWCR update"), and kickstart exits 0 without starting it. Only bootout + bootstrap clears that.
/// True once launchctl says running; false if it is still down after the bootstrap.
Future<bool> restartAgent(RunProcess run, String uid,
    {Future<void> Function(Duration) sleep = Future.delayed, int tries = 10}) async {
  final job = 'gui/$uid/$kAgentLabel';
  Future<ProcessResult> show() => run('launchctl', ['print', job]);
  Future<bool> cameUp() async {
    for (var i = 0; i < tries; i++) {
      final p = await show();
      if (p.exitCode == 0 && agentRunning('${p.stdout}')) return true;
      if (i < tries - 1) await sleep(const Duration(milliseconds: 500));
    }
    return false;
  }

  await run('launchctl', ['kickstart', '-k', job]);
  if (await cameUp()) return true;
  await run('launchctl', ['bootout', job]);
  for (var i = 0; i < tries && (await show()).exitCode == 0; i++) {
    await sleep(const Duration(milliseconds: 500)); // bootout returns before the job is gone
  }
  await run('launchctl', ['bootstrap', 'gui/$uid', kAgentPlist]);
  await run('launchctl', ['kickstart', job]); // loaded but not started
  return cameUp();
}

/// "Open Boring Remote at login" (Mac): a LaunchAgent of the user's own that opens the app.
/// It only opens the window; remote access is its own switch and never depends on it.
const kOpenAtLoginLabel = 'io.boringlabs.remote.open';
String openAtLoginPath(String home) => '$home/Library/LaunchAgents/$kOpenAtLoginLabel.plist';
String openAtLoginPlist(String bundleId) => '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$kOpenAtLoginLabel</string>
  <key>AssociatedBundleIdentifiers</key>
  <string>$bundleId</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/open</string>
    <string>-b</string>
    <string>$bundleId</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
''';

/// Every word the Access rows show, in one place for review (humanizer).
class AccessWords {
  AccessWords._();
  static String get title => 'Access';
  static String get ready => 'Ready. Your other ${KitWords.many} can connect.';
  static String notReady(String row) => 'Not ready: $row';
  static const fix = 'Fix';
  static const screen = 'Screen Recording';
  static const screenWhy = 'So people who connect can see this screen.';
  static const control = 'Accessibility';
  static const controlWhy = 'So they can use the mouse and keyboard.';
  static const input = 'Input Monitoring';
  static String get inputWhy => 'So keyboard shortcuts reach this ${KitWords.one}.';
  static String get on => 'Let your other ${KitWords.many} in';
  static const onWhy = 'Turned on in Settings.';
  static const running = 'Boring Remote running in the background';
  static const runningWhy = 'It takes sessions even with this window closed.';
  static const listening = 'Open for connections';
  static String get listeningWhy => 'Your other ${KitWords.many} can reach it on this network.';
  static String get reach => 'Let computers on this network reach Boring Remote';
  static const reachWhy = 'Windows asks once. Click “Yes”.';
}

/// One thing that has to be true before another computer can connect.
class AccessCheck {
  final String label;
  final String why;
  final Future<bool> Function() read;
  final Future<void> Function() fix;
  const AccessCheck({required this.label, required this.why, required this.read, required this.fix});
}

/// Index of the first check that is not met, or null when all are.
int? firstMissing(List<bool> ok) {
  final i = ok.indexOf(false);
  return i < 0 ? null : i;
}

/// Reads [checks] now, every [pollEvery] while shown, and when the window comes back to the front.
mixin _Polls<T extends StatefulWidget> on State<T>, WidgetsBindingObserver {
  List<AccessCheck> get checks;
  Duration get pollEvery;
  List<bool>? ok;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    read();
    _timer = Timer.periodic(pollEvery, (_) => read());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (s == AppLifecycleState.resumed) read();
  }

  Future<void> read() async {
    final r = await Future.wait(checks.map((c) => c.read().catchError((_) => false)));
    if (mounted) setState(() => ok = r);
  }

  Future<void> fix(AccessCheck c) async {
    await c.fix();
    await read();
  }

  @override
  void dispose() {
    _timer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }
}

Widget _summary(BuildContext context, List<AccessCheck> checks, List<bool> ok, Future<void> Function(AccessCheck) fix) {
  final i = firstMissing(ok);
  return Row(children: [
    Icon(i == null ? Icons.check_circle : Icons.error_outline, color: i == null ? Kit.ok : Kit.paper),
    const SizedBox(width: Kit.s2),
    Expanded(child: Text(i == null ? AccessWords.ready : AccessWords.notReady(checks[i].label))),
    if (i != null) OutlinedButton(onPressed: () => fix(checks[i]), child: const Text(AccessWords.fix)),
  ]);
}

/// Settings' Access section: a summary line, then one row per check, green or with a Fix button.
class AccessSection extends StatefulWidget {
  final List<AccessCheck> checks;
  final Duration pollEvery;
  const AccessSection({super.key, required this.checks, this.pollEvery = const Duration(seconds: 3)});

  @override
  State<AccessSection> createState() => _AccessSectionState();
}

class _AccessSectionState extends State<AccessSection> with WidgetsBindingObserver, _Polls<AccessSection> {
  @override
  List<AccessCheck> get checks => widget.checks;
  @override
  Duration get pollEvery => widget.pollEvery;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final r = ok;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(AccessWords.title, style: t.bodySmall),
      const SizedBox(height: Kit.s2),
      if (r != null) ...[
        _summary(context, checks, r, fix),
        const SizedBox(height: Kit.s2),
        for (var i = 0; i < checks.length; i++)
          ListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            leading: r[i] ? const Icon(Icons.check_circle, color: Kit.ok) : const Icon(Icons.circle_outlined, color: Kit.muted),
            title: Text(checks[i].label),
            subtitle: Text(checks[i].why, style: t.bodySmall),
            trailing: r[i] ? null : OutlinedButton(onPressed: () => fix(checks[i]), child: const Text(AccessWords.fix)),
          ),
      ],
    ]);
  }
}

/// Home's notice: the first missing check and its Fix; nothing at all once everything is ready.
class AccessSummary extends StatefulWidget {
  final List<AccessCheck> checks;
  final Duration pollEvery;
  const AccessSummary({super.key, required this.checks, this.pollEvery = const Duration(seconds: 5)});

  @override
  State<AccessSummary> createState() => _AccessSummaryState();
}

class _AccessSummaryState extends State<AccessSummary> with WidgetsBindingObserver, _Polls<AccessSummary> {
  @override
  List<AccessCheck> get checks => widget.checks;
  @override
  Duration get pollEvery => widget.pollEvery;

  @override
  Widget build(BuildContext context) {
    final r = ok;
    if (r == null || firstMissing(r) == null) return const SizedBox.shrink();
    return Padding(padding: const EdgeInsets.symmetric(vertical: Kit.s2), child: _summary(context, checks, r, fix));
  }
}
