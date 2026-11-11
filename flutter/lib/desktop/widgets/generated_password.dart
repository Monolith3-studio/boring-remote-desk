import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';

/// Ticket 05: the generated permanent password, shown once. The daemon keeps only its
/// salted hash, so after this dialog closes nobody can read it back.
void showGeneratedPasswordOnce(String password) {
  gFFI.dialogManager.show((setState, close, context) => CustomAlertDialog(
        title: const Text('New password'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SelectableText(password,
                style: const TextStyle(fontSize: 20, fontFamily: 'monospace')),
            const SizedBox(height: 12),
            const Text(
                "Write it down or copy it now. It won't be shown again."),
          ],
        ),
        actions: [
          dialogButton('Copy', isOutline: true, onPressed: () {
            Clipboard.setData(ClipboardData(text: password));
            showToast(translate('Copied'));
          }),
          dialogButton('Done', onPressed: close),
        ],
        onSubmit: close,
        onCancel: close,
      ));
}
