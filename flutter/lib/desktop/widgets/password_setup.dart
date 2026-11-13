import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/widgets/generated_password.dart';
import 'package:flutter_hbb/models/platform_model.dart';

/// Ticket 09: a Target with no Permanent password (a 1.7.x buyer after the 1.8.0 Update, or a
/// fresh install) is asked at launch to generate one. Until then the daemon keeps it off the
/// Hosted servers (password_lock::hosted_servers); Tailscale keeps working. Asked once per
/// launch while pending; once a password is set it never shows again.
var _askedThisLaunch = false;

Future<bool> permanentPasswordSet() async {
  return (await bind.mainGetCommon(key: "permanent-password-set")) == "true";
}

Future<void> showPasswordSetupIfNeeded() async {
  if (_askedThisLaunch || bind.isOutgoingOnly()) return;
  _askedThisLaunch = true;
  if (await permanentPasswordSet()) return;
  var errMsg = '';
  gFFI.dialogManager.show((setState, close, context) {
    generate() async {
      final pass = await bind.mainGeneratePermanentPassword();
      if (pass.isEmpty) {
        setState(() => errMsg = translate(
            "Couldn't set the password. If a remote session is open, end it and try again."));
        return;
      }
      close();
      showGeneratedPasswordOnce(pass);
    }

    return CustomAlertDialog(
      title: Text(translate('Set a Permanent password')),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(translate(
              'Connecting by Machine ID stays off on this computer until it has a Permanent password. Tailscale connections keep working.')),
          if (errMsg.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(errMsg, style: const TextStyle(color: Colors.red)),
          ],
        ],
      ),
      actions: [
        dialogButton('Later', isOutline: true, onPressed: close),
        dialogButton('Generate', onPressed: generate),
      ],
      onCancel: close,
    );
  });
}
