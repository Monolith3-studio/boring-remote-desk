import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/widgets/license_key_field.dart';

/// Activate link (ticket 14): status word from `mainActivateLink` → what the buyer reads.
/// `rejected`: the link wasn't a well-formed activate link, so nothing was stored.
String activateLinkText(String status) {
  if (status == 'valid') return "You're set.";
  if (status == 'rejected') {
    return "That link didn't work. Open Settings and paste the key from your purchase email.";
  }
  return kLicenseKeyStatusText[status] ?? kLicenseKeyStatusText['network']!;
}

/// Shows the activate result once. The key itself is never shown or logged here.
void showActivateLinkResult(String status) {
  windowOnTop(null);
  gFFI.dialogManager.show((setState, close, context) => CustomAlertDialog(
        title: const Text('Boring Remote'),
        content: Text(activateLinkText(status)),
        actions: [dialogButton('OK', onPressed: close)],
        onSubmit: close,
        onCancel: close,
      ));
}
