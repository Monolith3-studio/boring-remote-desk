import 'dart:async';

import 'package:flutter/material.dart';

import 'kit.dart';
import 'simple_settings.dart';

/// Local option set to 'Y' once Setup finishes (or is skipped through to the end).
const kSetupDoneOption = 'boring-setup-done';

/// Local option holding the screen Setup was on, so a "Quit & Reopen" from macOS comes back to it.
const kSetupStepOption = 'boring-setup-step';

/// System Settings panes Setup opens (macOS 13+ resolves these old-style ids too).
const kScreenRecordingPane = 'x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture';
const kAccessibilityPane = 'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility';

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
  'name.body': 'Your other Macs will list it by this name.',
  'name.hint': 'For example: Edit Bay 2',
  'name.seen': "You'll see this name in the list on your other Macs.",
  'name.blank': 'Type a name first.',
  'name.title@windows': 'Name this computer',
  'name.body@windows': 'Your other computers will list it by this name.',
  'name.seen@windows': "You'll see this name in the list on your other computers.",
  // Screen 2 (Mac)
  'allow.title': 'Let Boring Remote see and control this Mac',
  'allow.body': 'Click each button. System Settings opens. Turn on the switch next to “Boring Remote”.',
  'allow.screen': 'Let Boring Remote see this screen',
  'allow.screen.button': 'Open Screen Recording',
  'allow.control': 'Let Boring Remote use the mouse and keyboard',
  'allow.control.button': 'Open Accessibility',
  'allow.on': 'On',
  'allow.picture': 'Turn this on:',
  'allow.box': 'If a box pops up first, click “Open System Settings”.',
  'allow.password': "Your Mac may ask for your password or fingerprint. That's normal.",
  'allow.quit': 'If your Mac asks to quit Boring Remote, click “Quit & Reopen”. Setup comes back to this screen.',
  'allow.missing': 'No “Boring Remote” in the list? Click the + under the list, then pick Boring Remote in Applications.',
  'allow.seen': "You'll see a green check next to each one once it's on.",
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
  'password.body': 'Your other Macs can get in with this password when no one is at this one.',
  'password.hint': 'Type a password',
  'password.rule': 'At least 8 characters, with a capital, a small letter and a number.',
  'password.failed': "Couldn't save that password. Try again.",
  'password.save': 'Save password',
  'password.seen': "You'll see “Password saved.” when it worked.",
  'password.saved': 'Password saved.',
  'password.already': 'A password is already set. Type a new one to change it, or click Finish.',
  'password.skip.why': 'If you skip, someone has to be at this Mac to click Allow every time. '
      'You can set it later in Settings.',
  'password.body@windows': 'Your other computers can get in with this password when no one is at this one.',
  'password.skip.why@windows': 'If you skip, someone has to be at this computer to click Allow every time. '
      'You can set it later in Settings.',
  'done': 'Finish',
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
  final void Function(String url) openPane;
  final Duration pollEvery;

  /// Windows: polled while screen 2 shows (the rule is there); [allowReach] asks Windows to add it.
  final Future<bool> Function() canBeReached;
  final Future<void> Function() allowReach;

  final bool passwordSet;
  final Future<bool> Function(String password) setPassword;

  final int startStep;
  final void Function(int step) onStep;
  final VoidCallback onDone;

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
  });

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
  bool _seeScreen = false, _control = false;
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
    _name.dispose();
    _password.dispose();
    super.dispose();
  }

  void _enter() {
    _poll?.cancel();
    if (_screen == _Screen.allow) {
      _read();
      _poll = Timer.periodic(widget.pollEvery, (_) => setState(_read));
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
  }

  void _advance() {
    if (_step == _screens.length - 1) {
      _poll?.cancel();
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
    final (title, body) = switch (_screen) {
      _Screen.name => (_copy('name.title'), _nameScreen(t)),
      _Screen.allow => (_copy('allow.title'), _allowScreen(t)),
      _Screen.reach => (_copy('reach.title'), _reachScreen(t)),
      _Screen.password => (_copy('password.title'), _passwordScreen(t)),
    };
    return ListView(
      padding: const EdgeInsets.all(Kit.s7),
      children: [
        Text(
            _copy('step')
                .replaceFirst('{n}', '${_step + 1}')
                .replaceFirst('{total}', '${_screens.length}'),
            style: t.bodySmall),
        const SizedBox(height: Kit.s2),
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

  Widget _allowRow(TextTheme t, {required bool on, required String what, required String button, required String pane}) =>
      _row(t, on: on, what: what, button: button, onPressed: () => widget.openPane(pane));

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

  Widget _allowScreen(TextTheme t) {
    final both = _seeScreen && _control;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(_copy('allow.body')),
        const SizedBox(height: Kit.s4),
        _allowRow(t,
            on: _seeScreen,
            what: _copy('allow.screen'),
            button: _copy('allow.screen.button'),
            pane: kScreenRecordingPane),
        const SizedBox(height: Kit.s2),
        _allowRow(t,
            on: _control,
            what: _copy('allow.control'),
            button: _copy('allow.control.button'),
            pane: kAccessibilityPane),
        const SizedBox(height: Kit.s4),
        Text(_copy('allow.picture'), style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        const _SwitchPicture(),
        const SizedBox(height: Kit.s3),
        Text(_copy('allow.seen'), style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        Text(_copy('allow.box'), style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        Text(_copy('allow.password'), style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        Text(_copy('allow.quit'), style: t.bodySmall),
        const SizedBox(height: Kit.s2),
        Text(_copy('allow.missing'), style: t.bodySmall),
        const SizedBox(height: Kit.s5),
        _primary(_copy('next'), both ? _advance : null),
        if (!both) ...[const SizedBox(height: Kit.s2), _skip(t, _copy('allow.skip.why'))],
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
