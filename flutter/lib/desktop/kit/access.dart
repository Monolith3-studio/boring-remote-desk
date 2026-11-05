import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import 'kit.dart';

export 'setup.dart' show kScreenRecordingPane, kAccessibilityPane, kInputMonitoringPane, kSetupStepOption;

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

/// The bundle macOS keeps the switches under, and the only one [clearSwitches] ever names.
const kBundleId = 'io.boringlabs.remote.agent';

/// The three switches Setup asks for, in the names tccutil uses.
const kSwitchServices = ['Accessibility', 'ScreenCapture', 'ListenEvent'];

/// "Switch is on but still not working?" (v1.7 t31). A grant macOS holds for an older or ad-hoc
/// build shows on in System Settings and reads false here. Only a reset clears it. Needs no admin.
/// The arguments are fixed: without a bundle id tccutil resets every app on the Mac, so the id is a
/// constant and nothing a person or a caller passes reaches this list. Runs all three even if one
/// fails. True when all three worked.
Future<bool> clearSwitches(RunProcess run) async {
  var ok = true;
  for (final service in kSwitchServices) {
    try {
      final r = await run('/usr/bin/tccutil', ['reset', service, kBundleId]);
      ok = ok && r.exitCode == 0;
    } catch (_) {
      ok = false;
    }
  }
  return ok;
}

/// The IPC config name `--server` answers about itself, and the argument that makes a brand new
/// copy of the exe print the same line and exit (rebrand.py, boring_access_line).
const kServeAccessConfig = 'boring-serve-access';
const kFreshCheckArg = '--boring-access';

/// What one process can do, as macOS tells that process.
class MacAccess {
  /// This process is `--server`. False is the window standing in, so it says nothing about `--server`.
  final bool server;
  final bool screen, control, input;
  final int sessions;
  const MacAccess({this.server = false, required this.screen, required this.control, required this.input, this.sessions = 0});

  bool get all => screen && control && input;

  /// `server=Y screen=Y control=N input=Y sessions=0`. Null for anything else: no `--server`, or an
  /// older one that doesn't know the name.
  static MacAccess? parse(String line) {
    final f = {
      for (final kv in line.trim().split(RegExp(r'\s+')).map((w) => w.split('=')))
        if (kv.length == 2) kv[0]: kv[1],
    };
    if (!f.containsKey('screen') || !f.containsKey('control') || !f.containsKey('input')) return null;
    return MacAccess(
      server: f['server'] == 'Y',
      screen: f['screen'] == 'Y',
      control: f['control'] == 'Y',
      input: f['input'] == 'Y',
      sessions: int.tryParse(f['sessions'] ?? '') ?? 0,
    );
  }
}

/// Keeps "Ready" honest about `--server` (v1.7 t31). The window isn't what serves sessions, so:
/// - `--server` answers for itself over IPC. Every switch on there is the steady state, and costs one
///   IPC read.
/// - Anything off there, and a brand new copy of the exe reads the switches. macOS can keep a running
///   process's Screen Recording answer until it restarts, so neither the window nor `--server` can
///   be trusted to notice a switch going on. The window's own read is only the last resort. Every
///   [freshEvery] while someone is in Setup or just clicked Fix, else every [restEvery]: a Mac that
///   only ever controls others leaves these off for good, and shouldn't pay for it all day.
/// - A switch on that `--server` still reads as off means `--server` needs a restart, so restart it.
///   Never during a session, and at most [maxRestarts] times for one gap, so a read that never
///   clears can't turn into a restart loop on a machine in use.
class ServeWatch {
  final Future<MacAccess?> Function() askServer;
  final Future<MacAccess?> Function() askFresh;
  final MacAccess Function() askWindow;
  final Future<bool> Function() restart;
  final bool Function() mayRestart;
  final DateTime Function() now;
  final Duration freshEvery, restEvery, fastFor, restartEvery;
  final int maxRestarts;

  ServeWatch({
    required this.askServer,
    required this.askFresh,
    required this.askWindow,
    required this.restart,
    required this.mayRestart,
    this.now = DateTime.now,
    this.freshEvery = const Duration(seconds: 2),
    this.restEvery = const Duration(seconds: 60),
    this.fastFor = const Duration(minutes: 2),
    this.restartEvery = const Duration(seconds: 20),
    this.maxRestarts = 3,
  });

  /// `--server`'s last answer, when it was `--server` that answered.
  MacAccess? _server;

  /// The switches as macOS has them right now.
  MacAccess? switches;

  DateTime? _freshAt, _restartAt, _fastUntil;
  int _restarts = 0;
  Future<void>? _busy;

  /// Every Access row polls at once; they share one read.
  Future<void> read() => _busy ??= _read().whenComplete(() => _busy = null);

  Future<void> _ask() async {
    final a = await askServer();
    _server = a != null && a.server ? a : null;
  }

  Future<void> _read() async {
    await _ask();
    final s = _server;
    if (s != null && s.all) {
      switches = s;
      _restarts = 0;
      return;
    }
    final at = now();
    final last = _freshAt;
    final fast = _fastUntil != null && at.isBefore(_fastUntil!);
    if (switches == null || last == null || at.difference(last) >= (fast ? freshEvery : restEvery)) {
      _freshAt = at;
      switches = await askFresh() ?? askWindow();
    }
    if (s == null) return;
    final on = switches!;
    if (!((on.screen && !s.screen) || (on.control && !s.control) || (on.input && !s.input))) {
      _restarts = 0;
      return;
    }
    final since = _restartAt;
    if (s.sessions > 0 || !mayRestart() || _restarts >= maxRestarts) return;
    if (since != null && now().difference(since) < restartEvery) return;
    _restarts++;
    _restartAt = now();
    await restart();
    await _ask();
  }

  /// What `--server` can do, or the switches when there is no `--server` to ask (its own row says so).
  Future<bool> serves(bool Function(MacAccess) pick) async {
    await read();
    final a = _server ?? switches;
    return a != null && pick(a);
  }

  /// `--server` itself answered, not the window standing in.
  Future<bool> answering() async {
    await read();
    return _server != null;
  }

  /// Setup's read of the switches: moves on as soon as one is on, and keeps `--server` caught up.
  Future<MacAccess?> switchesNow() async {
    _fastUntil = now().add(fastFor);
    await read();
    return switches;
  }

  /// Start over after the switches were cleared or a Fix was clicked.
  void forget() {
    _server = null;
    switches = null;
    _freshAt = null;
    _restartAt = null;
    _restarts = 0;
    _fastUntil = now().add(fastFor);
  }
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
  static String get ready => 'Ready. Your other computers can connect.';
  static String notReady(String row) => 'Not ready: $row';
  static const fix = 'Fix';
  static const screen = 'Screen Recording';
  static const screenWhy = 'So people who connect can see this screen.';
  static const control = 'Accessibility';
  static const controlWhy = 'So people who connect can use the mouse and keyboard.';
  static const input = 'Input Monitoring';
  static String get inputWhy => 'So keyboard shortcuts reach this ${KitWords.one}.';
  static String get on => 'Let your other computers in';
  static const onWhy = 'The switch above.';
  static const running = 'Boring Remote running in the background';
  static String get runningWhy => 'So your other computers can get in with this window closed.';
  static const listening = 'Open for connections';
  static String get listeningWhy => 'So your other computers on this network can reach this one.';
  static String get reach => 'Let computers on this network reach Boring Remote';
  static const reachWhy = 'Windows asks once. Click “Yes”.';
  // v1.7 t31: Setup and Access, the way out when a switch is on and macOS still says no.
  static const stuckTitle = 'Switch is on but still not working?';
  static const stuckBody = 'Your Mac can hold on to an old copy of these switches. This clears all three for '
      'Boring Remote and leaves every other app alone. You\'ll need to turn them back on.';
  static const stuckButton = 'Clear them and start over';
  static const stuckDone = 'Cleared. All three are off now. Turn them back on, one at a time.';
  static const stuckFailed = "That didn't work. Quit Boring Remote, open it from Applications and try again.";
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

/// "Switch is on but still not working?": what it does, in words, and its one button.
class SwitchesStuck extends StatefulWidget {
  /// Clears the switches, asks macOS again, opens System Settings. True when it worked.
  final Future<bool> Function() clear;
  final VoidCallback? onCleared;
  const SwitchesStuck({super.key, required this.clear, this.onCleared});

  @override
  State<SwitchesStuck> createState() => _SwitchesStuckState();
}

class _SwitchesStuckState extends State<SwitchesStuck> {
  bool _busy = false;
  bool? _worked;

  Future<void> _go() async {
    setState(() => _busy = true);
    var ok = false;
    try {
      ok = await widget.clear();
    } catch (_) {}
    if (!mounted) return;
    setState(() {
      _busy = false;
      _worked = ok;
    });
    if (ok) widget.onCleared?.call();
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final worked = _worked;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(AccessWords.stuckTitle, style: t.bodyMedium),
      const SizedBox(height: Kit.s1),
      Text(AccessWords.stuckBody, style: t.bodySmall),
      const SizedBox(height: Kit.s2),
      OutlinedButton(onPressed: _busy ? null : _go, child: const Text(AccessWords.stuckButton)),
      if (worked != null) ...[
        const SizedBox(height: Kit.s2),
        Text(worked ? AccessWords.stuckDone : AccessWords.stuckFailed),
      ],
    ]);
  }
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

  /// The way out when a switch is on and macOS says no (v1.7 t31); null hides it (Windows).
  final Future<bool> Function()? clearSwitches;
  const AccessSection({super.key, required this.checks, this.pollEvery = const Duration(seconds: 3), this.clearSwitches});

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
        if (widget.clearSwitches != null) ...[
          const SizedBox(height: Kit.s3),
          SwitchesStuck(clear: widget.clearSwitches!, onCleared: read),
        ],
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

/// Setup's last screen (ticket 21): the summary line always, green "Ready" once everything is.
class AccessStatus extends StatefulWidget {
  final List<AccessCheck> checks;
  final Duration pollEvery;

  /// Offered while something is missing (v1.7 t31); null hides it (Windows).
  final Future<bool> Function()? clearSwitches;
  const AccessStatus({super.key, required this.checks, this.pollEvery = const Duration(seconds: 2), this.clearSwitches});

  @override
  State<AccessStatus> createState() => _AccessStatusState();
}

class _AccessStatusState extends State<AccessStatus> with WidgetsBindingObserver, _Polls<AccessStatus> {
  @override
  List<AccessCheck> get checks => widget.checks;
  @override
  Duration get pollEvery => widget.pollEvery;

  @override
  Widget build(BuildContext context) {
    final r = ok;
    if (r == null) return const SizedBox(height: 40);
    final stuck = widget.clearSwitches;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      _summary(context, checks, r, fix),
      if (stuck != null && firstMissing(r) != null) ...[
        const SizedBox(height: Kit.s3),
        SwitchesStuck(clear: stuck, onCleared: read),
      ],
    ]);
  }
}
