import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/widgets/generated_password.dart';
import 'package:flutter_hbb/desktop/widgets/trusted_controllers.dart';
import 'package:flutter_hbb/models/platform_model.dart';

/// Must match `password_lock::GENERATED_OPTION` in Rust. The daemon sets it only with a
/// password this app generated; a UI write can't (guard_options pins it).
const kBoringPasswordGenerated = 'boring-password-generated';

/// Ticket 09: a Target without an app-generated Permanent password (a 1.7.x buyer after the 1.8.0
/// Update, typed password or none, or a fresh install) is asked at launch to generate one. Until
/// then the daemon keeps it off the Hosted servers (password_lock::hosted_on); Tailscale keeps
/// working. Asked once per launch while pending; once one is generated it never shows again.
var _askedThisLaunch = false;

Future<bool> generatedPasswordSet() async {
  return bind.mainGetOption(key: kBoringPasswordGenerated) == 'Y';
}

Future<void> showPasswordSetupIfNeeded() async {
  if (_askedThisLaunch || bind.isOutgoingOnly()) return;
  _askedThisLaunch = true;
  if (await generatedPasswordSet()) return;
  var errMsg = '';
  gFFI.dialogManager.show((setState, close, context) {
    generate() async {
      // Checked on the click, not when the screen opened: a password set since (or a 1.7.x
      // typed one) is replaced only after the same question Reset asks.
      var clearTrusted = false;
      if ((await bind.mainGetCommon(key: "permanent-password-set")) == "true") {
        final go = await confirmReplacePassword();
        if (go == null) return;
        clearTrusted = go;
      }
      final pass = await bind.mainGeneratePermanentPassword();
      if (pass.isEmpty) {
        setState(() => errMsg = translate(
            "Couldn't set the password. If a remote session is open, end it and try again."));
        return;
      }
      if (clearTrusted) clearTrustedControllers();
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
              'Connecting by Machine ID stays off on this computer until it has a password made here with Generate. Tailscale connections keep working.')),
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
