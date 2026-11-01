import 'package:flutter/material.dart';
import 'package:xterm/xterm.dart';

import 'kit.dart';

/// The kit for the extras (port forward, terminal, camera view). They sit inside upstream pages
/// that still call MyTheme.color(context), so the kit keeps the outer theme's extensions.
ThemeData kitThemeKeeping(BuildContext context) =>
    Kit.theme().copyWith(extensions: Theme.of(context).extensions.values);

/// Terminal in the kit: ink page, paper text, coral cursor. The 16 ANSI colours stay xterm's,
/// since the remote program picks them, not us.
const kitTerminalTheme = TerminalTheme(
  cursor: Kit.coral,
  selection: Kit.line,
  foreground: Kit.paper,
  background: Kit.ink,
  black: Color(0XFF000000),
  red: Color(0XFFCD3131),
  green: Color(0XFF0DBC79),
  yellow: Color(0XFFE5E510),
  blue: Color(0XFF2472C8),
  magenta: Color(0XFFBC3FBC),
  cyan: Color(0XFF11A8CD),
  white: Color(0XFFE5E5E5),
  brightBlack: Color(0XFF666666),
  brightRed: Color(0XFFF14C4C),
  brightGreen: Color(0XFF23D18B),
  brightYellow: Color(0XFFF5F543),
  brightBlue: Color(0XFF3B8EEA),
  brightMagenta: Color(0XFFD670D6),
  brightCyan: Color(0XFF29B8DB),
  brightWhite: Color(0XFFFFFFFF),
  searchHitBackground: Color(0XFFFFFF2B),
  searchHitBackgroundCurrent: Color(0XFF31FF26),
  searchHitForeground: Color(0XFF000000),
);
