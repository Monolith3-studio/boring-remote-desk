import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:url_launcher/url_launcher_string.dart';

import 'kit.dart';

/// Every word Legal shows, in one place for review (humanizer). AGPL 5(d) and 0 need all of them:
/// the copyright notice, no warranty, that it may be shared under the license, how to read it.
/// AGPL 6 and 13 need the source link. boring/check.py fails if any of them goes.
class LegalWords {
  LegalWords._();
  static const title = 'Legal';
  static const credit = 'Boring Remote is based on RustDesk, © Purslane Tech Pte. Ltd.';
  static const license = "It's licensed under the GNU AGPL, version 3. "
      'You may copy, change and share it under that license.';
  static const noWarranty = 'It comes with no warranty.';
  static const readLicense = 'Read the license';
  static const sourceSays = 'The source code for each version is here:';
  static const getSource = 'Get the source code';
  static const close = 'Close';
  static const licenseFailed = "Couldn't open the license. Read it at $licenseUrl";
  // boring/rebrand.py FORK_URL; check.py wants the two to match.
  static const sourceUrl = 'https://boringlabs.online/remote/source/';
  static const licenseUrl = 'https://www.gnu.org/licenses/agpl-3.0.html';
}

/// boring/rebrand.py LICENCE_ASSET, the LICENCE file copied in at build time.
const kLicenseAsset = 'assets/LICENCE.txt';

Future<String> _readBundledLicense() => rootBundle.loadString(kLicenseAsset);

/// The Legal dialog. [readLicense] and [openUrl] are for tests.
Future<void> showLegalDialog(BuildContext context,
        {Future<String> Function() readLicense = _readBundledLicense,
        void Function(String url) openUrl = launchUrlString}) =>
    showDialog<void>(
        context: context,
        builder: (_) => Theme(
            data: Kit.theme(),
            child: LegalDialog(readLicense: readLicense, openUrl: openUrl)));

Widget _sheet(double width, List<Widget> children) => Dialog(
    backgroundColor: Kit.panel,
    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Kit.radius * 2)),
    child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: width),
        child: Padding(
            padding: const EdgeInsets.all(Kit.s5),
            child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: children))));

class LegalDialog extends StatelessWidget {
  final Future<String> Function() readLicense;
  final void Function(String url) openUrl;
  const LegalDialog({super.key, required this.readLicense, required this.openUrl});

  @override
  Widget build(BuildContext context) {
    const gap = SizedBox(height: Kit.s3);
    return _sheet(460, [
      const Text(LegalWords.title, style: TextStyle(color: Kit.paper, fontSize: 20, fontWeight: FontWeight.w800)),
      const SizedBox(height: Kit.s4),
      Flexible(
          child: SingleChildScrollView(
              child: SelectionArea(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [
        Text(LegalWords.credit),
        gap,
        Text(LegalWords.license),
        gap,
        Text(LegalWords.noWarranty),
        gap,
        Text(LegalWords.sourceSays),
        Text(LegalWords.sourceUrl),
      ])))),
      const SizedBox(height: Kit.s4),
      Wrap(spacing: Kit.s2, runSpacing: Kit.s2, children: [
        OutlinedButton(
            onPressed: () => showDialog<void>(
                context: context,
                builder: (_) => Theme(data: Kit.theme(), child: LicenseTextDialog(read: readLicense))),
            child: const Text(LegalWords.readLicense)),
        OutlinedButton(
            onPressed: () => openUrl(LegalWords.sourceUrl), child: const Text(LegalWords.getSource)),
        TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text(LegalWords.close)),
      ]),
    ]);
  }
}

/// The license itself, from inside the app, so it works with no network.
class LicenseTextDialog extends StatefulWidget {
  final Future<String> Function() read;
  const LicenseTextDialog({super.key, required this.read});

  @override
  State<LicenseTextDialog> createState() => _LicenseTextDialogState();
}

class _LicenseTextDialogState extends State<LicenseTextDialog> {
  late final Future<String> _text = widget.read();

  @override
  Widget build(BuildContext context) => _sheet(640, [
        Flexible(
            child: FutureBuilder<String>(
                future: _text,
                builder: (_, snap) => snap.connectionState != ConnectionState.done
                    ? const Center(child: CircularProgressIndicator())
                    : SingleChildScrollView(
                        child: SelectableText(snap.hasError ? LegalWords.licenseFailed : snap.data ?? '',
                            style: const TextStyle(color: Kit.paper, fontSize: 13))))),
        const SizedBox(height: Kit.s4),
        Align(
            alignment: Alignment.centerRight,
            child: TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text(LegalWords.close))),
      ]);
}
