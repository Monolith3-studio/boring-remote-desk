import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'access.dart';
import 'kit.dart';
import 'simple_settings.dart';

/// Local option set to 'Y' once Setup finishes (or is skipped through to the end).
const kSetupDoneOption = 'boring-setup-done';

/// Local option holding the screen Setup was on, so a "Quit & Reopen" from macOS comes back to it.
const kSetupStepOption = 'boring-setup-step';

/// System Settings panes Setup and Settings' Access rows open (macOS 13+ resolves these old-style
/// ids; checked on macOS 26.6: "Screen & System Audio Recording", "Accessibility", "Input Monitoring").
const kScreenRecordingPane = 'x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture';
const kAccessibilityPane = 'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility';
const kInputMonitoringPane = 'x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent';

/// The inbound app rule the MSI installs (res/msi CustomActions, named for people since v1.7 t17):
/// any port, every network type, so it covers Direct Link (TCP 21118) and LAN Discovery (UDP 21119). v1.7 t12.
const kWindowsRuleName = 'Boring Remote Service';

/// `netsh` arguments that read the rule, with its program path; exit code 0 means a rule by that
/// name is there ([windowsRuleAllowsExe] says whether it is for this exe). Needs no admin.
List<String> windowsRuleShowArgs() =>
    ['advfirewall', 'firewall', 'show', 'rule', 'name=$kWindowsRuleName', 'dir=in', 'verbose'];

/// True when one of the rules [windowsRuleShowArgs] printed is for [exe], so a copy of Boring Remote
/// outside the installed folder doesn't read green on someone else's rule. Matches the value, not the
/// "Program:" label, which Windows translates. Paths compare without case, as Windows does.
bool windowsRuleAllowsExe(String netshOutput, String exe) {
  final want = exe.trim().toLowerCase();
  return netshOutput.split(RegExp(r'\r?\n')).any((line) {
    final i = line.indexOf(':');
    return i > 0 && line.substring(i + 1).trim().toLowerCase() == want;
  });
}

/// Windows' own computer name for Setup's screen 1 (v1.7 review): COMPUTERNAME, which Windows keeps
/// in capitals, so the host name stands in when it is the same name in the case it was typed.
String windowsComputerName(Map<String, String> environment, String hostName) {
  final name = (environment['COMPUTERNAME'] ?? '').trim();
  final host = hostName.trim();
  return name.isEmpty || host.toUpperCase() == name.toUpperCase() ? host : name;
}

/// `powershell` arguments that add the same rule for [exe] as administrator: Windows asks once.
List<String> windowsRuleAddArgs(String exe) {
  final rule = 'advfirewall firewall add rule name="$kWindowsRuleName" dir=in action=allow '
      'program="$exe" enable=yes profile=any';
  return [
    '-NoProfile',
    '-Command',
    "Start-Process -FilePath netsh -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '${rule.replaceAll("'", "''")}'",
  ];
}

/// Where the other computer gets Boring Remote, copied from Setup's last screen (ticket 21).
/// TODO(ticket 15): the download page's real address; Settings still says theboringremote.com/download.
const kSetupDownloadUrl = 'https://boringlabs.online/remote';

/// First launch only: Setup shows until it has been finished once.
bool setupNeeded(String doneOption) => doneOption != 'Y';

/// The screen to open on: the saved one if it is a real screen, else the first.
int setupStartStep(String saved, int screens) {
  final i = int.tryParse(saved) ?? 0;
  return i >= 0 && i < screens ? i : 0;
}

/// Every word a buyer reads in Setup, in one place, for review (ticket 15, humanizer).
/// Quoted names (“Boring Remote”, “Quit & Reopen”) are exactly what macOS shows; on Windows,
/// “Yes” and “Allow access” are exactly what Windows shows. A `key@windows` entry replaces
/// `key` on Windows (v1.7 ticket 12).
const setupCopy = <String, String>{
  'step': 'Step {n} of {total}',
  'next': 'Continue',
  'skip': 'Skip for now',
  'skip.confirm': 'Skip anyway',
  'skip.back': 'Go back',
  // Screen 1
  'name.title': 'Name this Mac',
  'name.body': 'Your other computers will list it by this name.',
  'name.hint': 'For example: Edit Bay 2',
  'name.seen': "You'll see this name in the list on your other computers.",
  'name.blank': 'Type a name first.',
  'name.title@windows': 'Name this computer',
  // Screen 2 (Mac)
  'allow.title': 'Let Boring Remote see and control this Mac',
  'allow.body': 'Click the button. System Settings opens. Turn on the switch next to “Boring Remote”.',
  'allow.progress': 'Switch {n} of {total}',
  'allow.screen': 'Let Boring Remote see this screen',
  'allow.screen.button': 'Open Screen Recording',
  'allow.control': 'Let Boring Remote use the mouse and keyboard',
  'allow.control.button': 'Open Accessibility',
  'allow.on': 'On',
  'allow.box': 'If a box pops up first, click “Open System Settings”.',
  'allow.password': "Your Mac may ask for your password or fingerprint. That's normal.",
  'allow.quit': 'If your Mac asks to quit Boring Remote, click “Quit & Reopen”. Setup comes back to this screen.',
  'allow.missing': 'No “Boring Remote” in the list? Click the + under the list, then pick Boring Remote in Applications.',
  'allow.waiting': "Waiting for that switch. This moves on by itself once it's on.",
  'allow.all': 'All the switches are on.',
  'allow.skip.why': "If you skip, people who connect won't see this Mac's screen or be able to click anything. "
      'You can finish this later in Settings.',
  // Screen 2 (Windows, ticket 12)
  'reach.title': 'Let your other computers reach this one',
  'reach.body': 'Windows keeps other computers out of Boring Remote until you say yes. Click Allow.',
  'reach.row': 'Let computers on this network reach Boring Remote',
  'reach.button': 'Allow',
  'reach.yes': 'Windows asks “Do you want to allow this app to make changes to your device?” Click “Yes”.',
  'reach.box': 'If Windows shows a box about Boring Remote, tick every box in it and click “Allow access”.',
  'reach.seen': "You'll see a green check once it's allowed.",
  'reach.failed': "That didn't work. Click Allow again, then click “Yes” when Windows asks.",
  'reach.skip.why': "If you skip, your other computers may not be able to reach this one. "
      'You can finish this later in Settings.',
  // Screen 3
  'password.title': 'Set a password for when no one is here',
  'password.body': 'Your other computers can get in with this password when no one is at this one.',
  'password.hint': 'Type a password',
  'password.rule': 'At least 8 characters, with a capital, a small letter and a number.',
  'password.failed': "Couldn't save that password. Try again.",
  'password.save': 'Save password',
  'password.seen': "You'll see “Password saved.” when it worked.",
  'password.saved': 'Password saved.',
  'password.already': 'A password is already set. Type a new one to change it, or click Finish.',
  'password.skip.why': 'If you skip, someone has to be at this Mac to click Allow every time. '
      'You can set it later in Settings.',
  'password.skip.why@windows': 'If you skip, someone has to be at this computer to click Allow every time. '
      'You can set it later in Settings.',
  'done': 'Finish',
  // Before step 1 (ticket 21)
  'welcome.title': 'Welcome to Boring Remote',
  'welcome.body': "Let's get this Mac ready so your other computers can reach it. It takes about a minute.",
  'welcome.body@windows': "Let's get this computer ready so your other computers can reach it. It takes about a minute.",
  'welcome.start': 'Get started',
  // Screen 2 (Mac), third switch (ticket 21)
  'allow.input': 'Let keyboard shortcuts reach this Mac',
  'allow.input.button': 'Open Input Monitoring',
  // After the last step (ticket 21)
  'ready.title': 'Now your other computer',
  'ready.ok': 'Ready.',
  'ready.other': 'On your other computer, open Boring Remote. This one shows up as “{name}”.',
  'ready.get': "Don't have Boring Remote there yet? Copy the download link and open it on that computer.",
  'ready.copy': 'Copy download link',
  'ready.copied': 'Copied',
  'ready.done': 'Done',
};

/// Which machine Setup runs on. Screen 2 depends on it: Mac asks for screen and control
/// (System Settings); Windows asks to let other computers reach it (ticket 12).
enum SetupPlatform { mac, windows }

enum _Screen { name, allow, reach, password }

List<_Screen> _screensFor(SetupPlatform p) => [
      _Screen.name,
      if (p == SetupPlatform.mac) _Screen.allow,
      if (p == SetupPlatform.windows) _Screen.reach,
      _Screen.password,
    ];

/// One switch in System Settings, and what Setup says about it.
class _MacSwitch {
  final String name, what, button, pane;
  final bool on;

  /// macOS shows “Quit & Reopen” after this one.
  final bool asksToQuit;
  const _MacSwitch(
      {required this.name, required this.what, required this.button, required this.pane, required this.on, this.asksToQuit = false});
}

/// Setup (v1.7): first launch walks three screens, one thing to do on each.
/// Bridge-free; the home page passes data and callbacks.
class SetupFlow extends StatefulWidget {
  static const nameKey = Key('setup-name');
  static const passwordKey = Key('setup-password');

  /// Screens Setup shows on [platform]; [startStep] and [onStep] count in these.
  static int screenCount(SetupPlatform platform) => _screensFor(platform).length;

  final SetupPlatform platform;

  /// The computer's own name, or the name already chosen when Setup is opened again.
  final Future<String> computerName;
  final Future<void> Function(String name) onName;

  /// Polled while screen 2 shows; a check turns green as soon as one reads true.
  final bool Function() canSeeScreen;
  final bool Function() canControl;
  /// The third Mac switch (Input Monitoring); null leaves it off screen 2.
  final bool Function()? canMonitorInput;
  final void Function(String url) openPane;
  final Duration pollEvery;

  /// A better read than the three above when there is one (kit/access.dart, ServeWatch): what macOS
  /// says now, not what this process was told when it started. Null keeps the three above.
  final Future<MacAccess?> Function()? switchesNow;

  /// "Switch is on but still not working?": clears the switches, asks again, opens System Settings.
  /// Null hides it.
  final Future<bool> Function()? clearSwitches;

  /// How long the last green check stays up before Setup moves on by itself.
  final Duration moveOnAfter;

  /// Windows: polled while screen 2 shows (the rule is there); [allowReach] asks Windows to add it.
  final Future<bool> Function() canBeReached;
  final Future<void> Function() allowReach;

  final bool passwordSet;
  final Future<bool> Function(String password) setPassword;

  final int startStep;
  final void Function(int step) onStep;
  final VoidCallback onDone;

  /// A welcome screen before step 1 (first launch). Not a numbered step.
  final bool welcome;

  /// A last screen after the numbered steps: the green Ready line (from [readyChecks], the same
  /// checks as Settings' Access), the name the other computer sees, and the download link.
  final bool ready;
  final List<AccessCheck> readyChecks;
  final Future<void> Function(String text) copyText;

  const SetupFlow({
    super.key,
    this.platform = SetupPlatform.mac,
    required this.computerName,
    required this.onName,
    required this.canSeeScreen,
    required this.canControl,
    required this.openPane,
    this.pollEvery = const Duration(seconds: 1),
    required this.canBeReached,
    required this.allowReach,
    required this.passwordSet,
    required this.setPassword,
    this.startStep = 0,
    required this.onStep,
    required this.onDone,
    this.canMonitorInput,
    this.switchesNow,
    this.clearSwitches,
    this.moveOnAfter = const Duration(milliseconds: 1200),
    this.welcome = true,
    this.ready = true,
    this.readyChecks = const [],
    this.copyText = _clipboard,
  });

  static Future<void> _clipboard(String text) => Clipboard.setData(ClipboardData(text: text));

  @override
  State<SetupFlow> createState() => _SetupFlowState();
}

class _SetupFlowState extends State<SetupFlow> {
  late final _screens = _screensFor(widget.platform);
  late int _step = widget.startStep.clamp(0, _screens.length - 1);
  final _name = TextEditingController();
  final _password = TextEditingController();
  String? _error;
  bool _confirmSkip = false;
  bool _saved = false;
  bool _seeScreen = false, _control = false, _input = false;
  String? _opened; // the pane the person clicked through to, for "Waiting for that switch"
  bool _sawMissing = false, _reading = false;
  Timer? _moveOn;
  late bool _welcome = widget.welcome && _step == 0;
  bool _ready = false, _copied = false;
  bool _reached = false, _reachFailed = false;
  Timer? _poll;

  _Screen get _screen => _screens[_step];

  String _copy(String key) =>
      (widget.platform == SetupPlatform.windows ? setupCopy['$key@windows'] : null) ?? setupCopy[key]!;

  @override
  void initState() {
    super.initState();
    widget.computerName.then((n) {
      if (mounted && _name.text.isEmpty) _name.text = n;
    });
    _enter();
  }

  @override
  void dispose() {
    _poll?.cancel();
    _moveOn?.cancel();
    _name.dispose();
    _password.dispose();
    super.dispose();
  }

  void _enter() {
    _poll?.cancel();
    _moveOn?.cancel();
    _moveOn = null;
    if (_screen == _Screen.allow) {
      _read();
      _afterRead();
      _poll = Timer.periodic(widget.pollEvery, (_) => _tick());
    }
    if (_screen == _Screen.reach) {
      _readReach();
      _poll = Timer.periodic(widget.pollEvery, (_) => _readReach());
    }
  }

  Future<bool> _readReach() async {
    final on = await widget.canBeReached();
    if (mounted && _screen == _Screen.reach) {
      setState(() {
        _reached = on;
        if (on) _reachFailed = false;
      });
    }
    return on;
  }

  Future<void> _allowReach() async {
    await widget.allowReach();
    final on = await _readReach();
    if (mounted && !on) setState(() => _reachFailed = true);
  }

  void _read() {
    _seeScreen = widget.canSeeScreen();
    _control = widget.canControl();
    _input = widget.canMonitorInput?.call() ?? true;
  }

  bool get _allOn => _seeScreen && _control && _input;

  /// Reads only. Nothing here opens a pane or raises a window: the person may be in the middle of
  /// System Settings, so the next switch waits for them to click.
  Future<void> _tick() async {
    if (widget.switchesNow == null) {
      setState(_read);
      _afterRead();
      return;
    }
    if (_reading) return;
    _reading = true;
    MacAccess? a;
    try {
      a = await widget.switchesNow!();
    } catch (_) {}
    _reading = false;
    if (!mounted || _welcome || _screen != _Screen.allow) return;
    setState(() {
      if (a == null) {
        _read();
      } else {
        _seeScreen = a.screen;
        _control = a.control;
        _input = widget.canMonitorInput == null || a.input;
      }
    });
    _afterRead();
  }

  /// Moves on by itself, but only after a switch went on while this screen was up. Opened with
  /// everything already on, it shows that and waits for Continue.
  void _afterRead() {
    if (!_allOn) {
      _sawMissing = true;
      _moveOn?.cancel();
      _moveOn = null;
    } else if (_sawMissing && _moveOn == null) {
      _moveOn = Timer(widget.moveOnAfter, () {
        _moveOn = null;
        if (mounted && _allOn && _screen == _Screen.allow) _advance();
      });
    }
  }

  void _openSwitch(_MacSwitch s) {
    setState(() => _opened = s.pane);
    widget.openPane(s.pane);
  }

  void _cleared() {
    setState(() {
      _seeScreen = _control = false;
      _input = widget.canMonitorInput == null;
      _opened = kScreenRecordingPane; // the clear already opened the first pane
    });
    _afterRead();
    _tick();
  }

  void _advance() {
    _moveOn?.cancel();
    _moveOn = null;
    if (_step == _screens.length - 1) {
      _poll?.cancel();
      if (widget.ready && !_ready) {
        setState(() => _ready = true);
        return;
      }
      widget.onDone();
      return;
    }
    setState(() {
      _step++;
      _error = null;
      _confirmSkip = false;
    });
    widget.onStep(_step);
    _enter();
  }

  Future<void> _saveName() async {
    final n = _name.text.trim();
    if (n.isEmpty) {
      setState(() => _error = _copy('name.blank'));
      return;
    }
    await widget.onName(n);
    if (mounted) _advance();
  }

  Future<void> _savePassword() async {
    final p = _password.text;
    if (!SimpleSettings.strongEnough(p)) {
      setState(() => _error = _copy('password.rule'));
      return;
    }
    final ok = await widget.setPassword(p);
    if (!mounted) return;
    setState(() {
      _error = ok ? null : _copy('password.failed');
      if (ok) {
        _saved = true;
        _password.clear();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    if (_welcome) return _page(t, _copy('welcome.title'), _welcomeScreen(t));
    if (_ready) return _page(t, _copy('ready.title'), _readyScreen(t));
    final (title, body) = switch (_screen) {
      _Screen.name => (_copy('name.title'), _nameScreen(t)),
      _Screen.allow => (_copy('allow.title'), _allowScreen(t)),
      _Screen.reach => (_copy('reach.title'), _reachScreen(t)),
      _Screen.password => (_copy('password.title'), _passwordScreen(t)),
    };
    return _page(t, title, body,
        step: _copy('step').replaceFirst('{n}', '${_step + 1}').replaceFirst('{total}', '${_screens.length}'));
  }

  Widget _page(TextTheme t, String title, Widget body, {String? step}) {
    return ListView(
      padding: const EdgeInsets.all(Kit.s7),
      children: [
        if (step != null) ...[Text(step, style: t.bodySmall), const SizedBox(height: Kit.s2)],
        Text(title, style: t.headlineSmall),
        const SizedBox(height: Kit.s5),
        body,
        if (_error != null) ...[
          const SizedBox(height: Kit.s3),
          Text(_error!, style: t.bodyMedium),
        ],
      ],
    );
  }

  Widget _primary(String label, VoidCallback? onPressed) => Align(
        alignment: Alignment.centerLeft,
        child: FilledButton(onPressed: onPressed, child: Text(label)),
      );

  /// Skip is a link; it only skips after the buyer has read what skipping costs.
  Widget _skip(TextTheme t, String why) {
    if (!_confirmSkip) {
      return Align(
        alignment: Alignment.centerLeft,
        child: TextButton(
          onPressed: () => setState(() => _confirmSkip = true),
          child: Text(_copy('skip')),
        ),
      );
    }
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(why),
      const SizedBox(height: Kit.s2),
      Row(children: [
        OutlinedButton(onPressed: _advance, child: Text(_copy('skip.confirm'))),
        const SizedBox(width: Kit.s2),
        TextButton(
          onPressed: () => setState(() => _confirmSkip = false),
          child: Text(_copy('skip.back')),
        ),
      ]),
    ]);
  }

  Widget _welcomeScreen(TextTheme t) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(_copy('welcome.body')),
          const SizedBox(height: Kit.s5),
          _primary(_copy('welcome.start'), () {
            setState(() => _welcome = false);
            _enter();
          }),
        ],
      );

  /// The name this computer was given on screen 1 (or already had, when Setup opened later).
  String get _shownAs => _name.text.trim();

  Widget _readyScreen(TextTheme t) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (widget.readyChecks.isEmpty)
            Row(children: [
              const Icon(Icons.check_circle, color: Kit.ok),
              const SizedBox(width: Kit.s2),
              Text(_copy('ready.ok')),
            ])
          else
            AccessStatus(checks: widget.readyChecks, clearSwitches: widget.clearSwitches),
          const SizedBox(height: Kit.s4),
          Text(_copy('ready.other').replaceFirst('{name}', _shownAs)),
          const SizedBox(height: Kit.s4),
          Text(_copy('ready.get'), style: t.bodySmall),
          const SizedBox(height: Kit.s2),
          Row(children: [
            Flexible(child: SelectableText(kSetupDownloadUrl, style: t.bodyMedium)),
            const SizedBox(width: Kit.s3),
            OutlinedButton(
              onPressed: () async {
                await widget.copyText(kSetupDownloadUrl);
                if (mounted) setState(() => _copied = true);
              },
              child: Text(_copy(_copied ? 'ready.copied' : 'ready.copy')),
            ),
          ]),
          const SizedBox(height: Kit.s5),
          _primary(_copy('ready.done'), widget.onDone),
        ],
      );

  Widget _nameScreen(TextTheme t) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(_copy('name.body')),
          const SizedBox(height: Kit.s4),
          TextField(
            key: SetupFlow.nameKey,
            controller: _name,
            autofocus: true,
            decoration: InputDecoration(hintText: _copy('name.hint')),
            onSubmitted: (_) => _saveName(),
          ),
          const SizedBox(height: Kit.s3),
          Text(_copy('name.seen'), style: t.bodySmall),
          const SizedBox(height: Kit.s5),
          _primary(_copy('next'), _saveName),
        ],
      );

  Widget _reachScreen(TextTheme t) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(_copy('reach.body')),
          const SizedBox(height: Kit.s4),
          _row(t, on: _reached, what: _copy('reach.row'), button: _copy('reach.button'), onPressed: _allowReach),
          if (_reachFailed && !_reached) ...[
            const SizedBox(height: Kit.s2),
            Text(_copy('reach.failed')),
          ],
          const SizedBox(height: Kit.s3),
          Text(_copy('reach.seen'), style: t.bodySmall),
          const SizedBox(height: Kit.s2),
          Text(_copy('reach.yes'), style: t.bodySmall),
          const SizedBox(height: Kit.s2),
          Text(_copy('reach.box'), style: t.bodySmall),
          const SizedBox(height: Kit.s5),
          _primary(_copy('next'), _reached ? _advance : null),
          if (!_reached) ...[const SizedBox(height: Kit.s2), _skip(t, _copy('reach.skip.why'))],
        ],
      );

  Widget _row(TextTheme t, {required bool on, required String what, required String button, required VoidCallback onPressed}) =>
      Container(
        padding: const EdgeInsets.all(Kit.s4),
        decoration: BoxDecoration(
          color: Kit.panel,
          borderRadius: BorderRadius.circular(Kit.radius),
          border: Border.all(color: on ? Kit.ok : Kit.line),
        ),
        child: Row(children: [
          Icon(on ? Icons.check_circle : Icons.radio_button_unchecked,
              color: on ? Kit.ok : Kit.muted, semanticLabel: on ? _copy('allow.on') : null),
          const SizedBox(width: Kit.s3),
          Expanded(child: Text(what)),
          if (on)
            Text(_copy('allow.on'), style: t.bodyMedium?.copyWith(color: Kit.ok))
          else
            OutlinedButton(onPressed: onPressed, child: Text(button)),
        ]),
      );

  List<_MacSwitch> get _switches => [
        _MacSwitch(
            name: AccessWords.screen,
            what: _copy('allow.screen'),
            button: _copy('allow.screen.button'),
            pane: kScreenRecordingPane,
            on: _seeScreen,
            asksToQuit: true),
        _MacSwitch(
            name: AccessWords.control,
            what: _copy('allow.control'),
            button: _copy('allow.control.button'),
            pane: kAccessibilityPane,
            on: _control),
        if (widget.canMonitorInput != null)
          _MacSwitch(
              name: AccessWords.input,
              what: _copy('allow.input'),
              button: _copy('allow.input.button'),
              pane: kInputMonitoringPane,
              on: _input,
              asksToQuit: true),
      ];

  /// Where this switch sits among the rest: done, this one, still to come.
  Widget _progress(TextTheme t, List<_MacSwitch> all, int at) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
              _copy('allow.progress').replaceFirst('{n}', '${at + 1}').replaceFirst('{total}', '${all.length}'),
              style: t.bodySmall),
          const SizedBox(height: Kit.s2),
          Wrap(spacing: Kit.s4, runSpacing: Kit.s1, children: [
            for (var i = 0; i < all.length; i++)
              Row(mainAxisSize: MainAxisSize.min, children: [
                Icon(
                    all[i].on
                        ? Icons.check_circle
                        : i == at
                            ? Icons.radio_button_checked
                            : Icons.radio_button_unchecked,
                    size: 16,
                    color: all[i].on
                        ? Kit.ok
                        : i == at
                            ? Kit.paper
                            : Kit.muted,
                    semanticLabel: all[i].on ? _copy('allow.on') : null),
                const SizedBox(width: Kit.s1),
                Text(all[i].name, style: t.bodySmall),
              ]),
          ]),
        ],
      );

  Widget _allowScreen(TextTheme t) {
    final all = _switches;
    final at = all.indexWhere((s) => !s.on);
    final clear = widget.clearSwitches;
    if (at < 0) {
      return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          const Icon(Icons.check_circle, color: Kit.ok),
          const SizedBox(width: Kit.s2),
          Text(_copy('allow.all')),
        ]),
        const SizedBox(height: Kit.s5),
        _primary(_copy('next'), _advance),
        if (clear != null) ...[
          const SizedBox(height: Kit.s6),
          SwitchesStuck(key: const ValueKey('switches-stuck'), clear: clear, onCleared: _cleared),
        ],
      ]);
    }
    final s = all[at];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _progress(t, all, at),
        const SizedBox(height: Kit.s5),
        Text(s.what, style: t.titleMedium),
        const SizedBox(height: Kit.s2),
        Text(_copy('allow.body')),
        const SizedBox(height: Kit.s4),
        Wrap(spacing: Kit.s4, runSpacing: Kit.s2, crossAxisAlignment: WrapCrossAlignment.center, children: [
          FilledButton(onPressed: () => _openSwitch(s), child: Text(s.button)),
          const _SwitchPicture(),
        ]),
        if (_opened == s.pane) ...[
          const SizedBox(height: Kit.s2),
          Text(_copy('allow.waiting'), style: t.bodySmall),
        ],
        const SizedBox(height: Kit.s4),
        Text(_copy('allow.box'), style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        Text(_copy('allow.password'), style: t.bodySmall),
        if (s.asksToQuit) ...[
          const SizedBox(height: Kit.s2),
          Text(_copy('allow.quit'), style: t.bodySmall),
        ],
        const SizedBox(height: Kit.s2),
        Text(_copy('allow.missing'), style: t.bodySmall),
        if (clear != null) ...[
          const SizedBox(height: Kit.s5),
          SwitchesStuck(key: const ValueKey('switches-stuck'), clear: clear, onCleared: _cleared),
        ],
        const SizedBox(height: Kit.s4),
        _skip(t, _copy('allow.skip.why')),
      ],
    );
  }

  Widget _passwordScreen(TextTheme t) {
    final isSet = _saved || widget.passwordSet;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(_copy('password.body')),
        if (widget.passwordSet && !_saved) ...[
          const SizedBox(height: Kit.s2),
          Text(_copy('password.already')),
        ],
        const SizedBox(height: Kit.s4),
        if (_saved)
          Row(children: [
            const Icon(Icons.check_circle, color: Kit.ok),
            const SizedBox(width: Kit.s2),
            Text(_copy('password.saved')),
          ])
        else ...[
          TextField(
            key: SetupFlow.passwordKey,
            controller: _password,
            obscureText: true,
            autofocus: true,
            decoration: InputDecoration(hintText: _copy('password.hint')),
            onSubmitted: (_) => _savePassword(),
          ),
          const SizedBox(height: Kit.s2),
          Text(_copy('password.rule'), style: t.bodySmall),
          const SizedBox(height: Kit.s2),
          Text(_copy('password.seen'), style: t.bodySmall),
          const SizedBox(height: Kit.s4),
          Align(
            alignment: Alignment.centerLeft,
            child: (isSet ? OutlinedButton.new : FilledButton.new)(
                onPressed: _savePassword, child: Text(_copy('password.save'))),
          ),
        ],
        const SizedBox(height: Kit.s4),
        if (isSet) _primary(_copy('done'), _advance) else _skip(t, _copy('password.skip.why')),
      ],
    );
  }
}

/// A picture of what to click in System Settings: the “Boring Remote” row with its switch on.
class _SwitchPicture extends StatelessWidget {
  const _SwitchPicture();

  static const _macSwitchOn = Color(0xFF0A84FF); // macOS's own switch blue, so the picture matches the screen

  @override
  Widget build(BuildContext context) => Container(
        width: 320,
        padding: const EdgeInsets.symmetric(horizontal: Kit.s3, vertical: Kit.s2),
        decoration: BoxDecoration(
          color: Kit.glass,
          borderRadius: BorderRadius.circular(Kit.radius),
          border: Border.all(color: Kit.line),
        ),
        child: Row(children: [
          Container(
            width: 24,
            height: 24,
            decoration: BoxDecoration(color: Kit.ink, borderRadius: BorderRadius.circular(6)),
          ),
          const SizedBox(width: Kit.s3),
          const Expanded(child: Text('Boring Remote')),
          Container(
            width: 38,
            height: 22,
            padding: const EdgeInsets.all(2),
            alignment: Alignment.centerRight,
            decoration: BoxDecoration(color: _macSwitchOn, borderRadius: BorderRadius.circular(11)),
            child: Container(
              width: 18,
              height: 18,
              decoration: const BoxDecoration(color: Kit.paper, shape: BoxShape.circle),
            ),
          ),
        ]),
      );
}
