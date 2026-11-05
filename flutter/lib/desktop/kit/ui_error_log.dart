import 'package:flutter/foundation.dart';

/// boring-remote (v1.7 t28): sends every widget build or layout error to [sink], once per distinct
/// error. A release build logs none of these itself: it only draws a grey block.
void logUiErrors(void Function(String text) sink) {
  final seen = <String>{};
  final previous = FlutterError.onError;
  FlutterError.onError = (details) {
    try {
      final what = '${details.exceptionAsString()} (${details.context})';
      if (seen.add(what)) {
        final stack = (details.stack?.toString() ?? '').split('\n').take(12).join('\n');
        sink('$what\n$stack');
      }
    } catch (_) {
      // Logging must never throw from inside the error handler.
    }
    previous?.call(details);
  };
}
