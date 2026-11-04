import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/desktop/kit/ui_error_log.dart';
import 'package:flutter_test/flutter_test.dart';

class _Throws extends StatelessWidget {
  const _Throws();
  @override
  Widget build(BuildContext context) => throw StateError('no theme');
}

void main() {
  FlutterExceptionHandler? before;
  setUp(() => before = FlutterError.onError);
  tearDown(() => FlutterError.onError = before);

  testWidgets('a widget that throws in build reaches the log, once per error', (tester) async {
    final lines = <String>[];
    final inner = FlutterError.onError;
    logUiErrors(lines.add);
    await tester.pumpWidget(const Column(
        textDirection: TextDirection.ltr,
        children: [Expanded(child: _Throws()), Expanded(child: _Throws())]));
    // Two errors, so the binding reports a "Multiple exceptions" string rather than the StateError.
    expect(tester.takeException(), isNotNull);
    FlutterError.onError = inner;
    expect(lines, hasLength(1));
    expect(lines.single, contains('no theme'));
    expect(lines.single, contains('building _Throws'));
    expect(lines.single, contains('_Throws.build'));
  });

  test('a failing log never throws from the handler, and the old handler still runs', () {
    var called = 0;
    FlutterError.onError = (_) => called++;
    logUiErrors((_) => throw StateError('bridge not ready'));
    FlutterError.onError!(FlutterErrorDetails(exception: StateError('x')));
    expect(called, 1);
  });
}
