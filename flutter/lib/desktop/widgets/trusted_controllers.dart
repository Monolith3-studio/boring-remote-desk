import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/platform_model.dart';

/// Must match `trust_policy::TRUSTED_OPTION` and `REMOVE_OPTION` in Rust.
const kBoringTrustedControllers = 'boring-trusted-controllers';
const kBoringTrustedControllersRemove = 'boring-trusted-controllers-remove';

/// Asks the daemon to drop these IDs. It owns the list (the UI's copy can be a second old)
/// and ends their open sessions.
Future<void> removeTrustedControllers(String ids) =>
    bind.mainSetOption(key: kBoringTrustedControllersRemove, value: ids);

Future<void> clearTrustedControllers() =>
    removeTrustedControllers(trustedControllerIds().join(','));

/// The stored list is `id:key` entries (the key the Controller proves on each login). An entry
/// without a key is from before trust binding: not trusted, and the daemon drops it.
final _entry = RegExp(r'^([A-Za-z0-9_-]{1,64}):[0-9a-f]{64}$');

List<String> trustedControllerIds() => bind
    .mainGetOptionSync(key: kBoringTrustedControllers)
    .split(',')
    .map((s) => _entry.firstMatch(s.trim())?.group(1))
    .whereType<String>()
    .toList();

/// The Controllers this computer lets in with the password and no click (each proves its own
/// key). Remove one and its next connection needs a click here again; an open session of it ends.
class TrustedControllers extends StatefulWidget {
  const TrustedControllers({Key? key}) : super(key: key);

  @override
  State<TrustedControllers> createState() => _TrustedControllersState();
}

class _TrustedControllersState extends State<TrustedControllers> {
  Future<void> _remove(String id) async {
    await removeTrustedControllers(id);
    // The UI's option cache refreshes about once a second.
    await Future.delayed(const Duration(milliseconds: 1500));
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final ids = trustedControllerIds();
    if (ids.isEmpty) {
      return Padding(
        padding: const EdgeInsets.all(8),
        child: Text(translate(
            'None yet. A computer connecting for the first time needs a click here.')),
      );
    }
    return Column(
      children: [
        for (final id in ids)
          ListTile(
            dense: true,
            title: Text(id),
            trailing: TextButton(
              onPressed: () => _remove(id),
              child: Text(translate('Remove')),
            ),
          ),
      ],
    );
  }
}
