import 'package:flutter/material.dart';

/// What the buyer calls a computer (v1.7 ticket 12): "Mac" on the Mac build, "computer" on
/// Windows. Set once at startup (main.dart, before any window is built); Mac is the default.
class KitWords {
  KitWords._();
  static String one = 'Mac';
  static String many = 'Macs';
  static void mac() {
    one = 'Mac';
    many = 'Macs';
  }

  static void windows() {
    one = 'computer';
    many = 'computers';
  }

  /// First letter capital, for a word that starts a label: "Computers", "Mac".
  static String cap(String s) => s.isEmpty ? s : s[0].toUpperCase() + s.substring(1);
}

/// The Boring Remote kit: every colour, type and spacing token the v1.7 UI uses.
/// Palette comes from the icon and DMG art (boring/art/icon.svg, boring/dmg/make_art.py).
/// Coral is for marks only (focus, cursor, selection): never text, never a fill under text.
class Kit {
  Kit._();

  static const Color ink = Color(0xFF0C0B11); // page
  static const Color panel = Color(0xFF19171A); // cards, sheet
  static const Color glass = Color(0xFF211D22); // fields, hover
  static const Color line = Color(0xFF2B2A2F); // borders
  static const Color paper = Color(0xFFF0EFEB); // text
  static const Color muted = Color(0xFF9B999D); // secondary text
  static const Color coral = Color(0xFFFF5949); // accent, non-text only
  static const Color ok = Color(0xFF0DBC79); // done / allowed: Setup's green checks

  // The app uses the platform UI font (SF Pro on Mac, Segoe UI on Windows): Jason, 2026-11-02.

  static const double s1 = 4, s2 = 8, s3 = 12, s4 = 16, s5 = 24, s6 = 32, s7 = 48;
  static const double radius = 10;

  static ThemeData theme() {
    final base = ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
    );
    final text = base.textTheme.apply(bodyColor: paper, displayColor: paper);
    final border = OutlineInputBorder(
      borderRadius: BorderRadius.circular(radius),
      borderSide: const BorderSide(color: line),
    );
    return base.copyWith(
      scaffoldBackgroundColor: ink,
      canvasColor: ink,
      dividerColor: line,
      colorScheme: const ColorScheme.dark(
        primary: paper,
        onPrimary: ink,
        secondary: coral,
        onSecondary: ink,
        surface: panel,
        onSurface: paper,
        outline: line,
      ),
      textTheme: text.copyWith(
        headlineSmall: text.headlineSmall?.copyWith(fontWeight: FontWeight.w800),
        bodyMedium: text.bodyMedium?.copyWith(fontSize: 15),
        bodySmall: text.bodySmall?.copyWith(color: muted, fontSize: 13),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: glass,
        hintStyle: const TextStyle(color: muted),
        contentPadding: const EdgeInsets.symmetric(horizontal: s4, vertical: s4),
        border: border,
        enabledBorder: border,
        focusedBorder: border.copyWith(borderSide: const BorderSide(color: coral, width: 1.5)),
      ),
      textSelectionTheme: const TextSelectionThemeData(cursorColor: coral),
      bottomSheetTheme: const BottomSheetThemeData(
        backgroundColor: panel,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(radius * 2))),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(foregroundColor: paper),
      ),
      listTileTheme: const ListTileThemeData(textColor: paper, iconColor: muted),
    );
  }
}
