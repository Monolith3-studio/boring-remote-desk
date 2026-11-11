import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';

/// The generated permanent password, shown once. The daemon keeps only its salted hash, so
/// after this dialog closes nobody can read it back. It closes only on "I've saved it": not on
/// Esc, Enter or a click outside.
void showGeneratedPasswordOnce(String password) {
  gFFI.dialogManager.show((setState, close, context) => CustomAlertDialog(
        title: Text(translate('New password')),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SelectableText(password,
                style: const TextStyle(fontSize: 20, fontFamily: 'monospace')),
            const SizedBox(height: 12),
            Text(translate(
                "Write it down or copy it now. It won't be shown again.")),
          ],
        ),
        actions: [
          dialogButton('Copy',
              isOutline: true, onPressed: () => copyPasswordBriefly(password)),
          dialogButton("I've saved it", onPressed: close),
        ],
      ));
}

/// Copies the password, then clears the clipboard after a minute if it still holds it.
void copyPasswordBriefly(String password) {
  Clipboard.setData(ClipboardData(text: password));
  showToast(translate('Copied'));
  Timer(const Duration(seconds: 60), () async {
    final now = await Clipboard.getData(Clipboard.kTextPlain);
    if (now?.text == password) {
      await Clipboard.setData(const ClipboardData(text: ''));
    }
  });
}

/// Before replacing a password: null means cancel, otherwise whether to clear the trusted
/// Controllers as well (after a leak, an ID approved by mistake would stay trusted).
Future<bool?> confirmReplacePassword() {
  var clearTrusted = false;
  return gFFI.dialogManager.show<bool>((setState, close, context) =>
      CustomAlertDialog(
        title: Text(translate('Replace the password?')),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(translate('Every Controller will need the new password.')),
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              value: clearTrusted,
              onChanged: (v) => setState(() => clearTrusted = v ?? false),
              title: Text(translate('Also clear trusted Controllers')),
            ),
          ],
        ),
        actions: [
          dialogButton('Cancel', isOutline: true, onPressed: () => close(null)),
          dialogButton('Replace', onPressed: () => close(clearTrusted)),
        ],
        onCancel: () => close(null),
      ));
}
