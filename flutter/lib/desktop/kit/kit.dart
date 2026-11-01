import 'package:flutter/material.dart';

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

  // Boring Type is not ours to publish (public AGPL repo), so no font files are bundled.
  // These family names resolve only if installed; otherwise the system UI font is used.
  // CI could fetch the binaries into flutter/assets from a private store and declare them in pubspec.
  static const String fontUi = 'Neue Corp';
  static const String fontText = 'Söhne';
  static const List<String> fontFallback = [fontText, '.AppleSystemUIFont', 'Helvetica Neue', 'Segoe UI'];

  static const double s1 = 4, s2 = 8, s3 = 12, s4 = 16, s5 = 24, s6 = 32, s7 = 48;
  static const double radius = 10;

  static ThemeData theme() {
    final base = ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      fontFamily: fontUi,
      fontFamilyFallback: fontFallback,
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
