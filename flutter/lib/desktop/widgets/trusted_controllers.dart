import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/platform_model.dart';

/// Ticket 06: must match `trust_policy::TRUSTED_OPTION` in Rust.
const kBoringTrustedControllers = 'boring-trusted-controllers';

/// Ticket 06: the Controllers this computer lets in with the password alone. Remove one and
/// its next connection needs a click here again. The daemon ignores changes to this list
/// while a remote session is open, so only someone at this computer can edit it.
class TrustedControllers extends StatefulWidget {
  const TrustedControllers({Key? key}) : super(key: key);

  @override
  State<TrustedControllers> createState() => _TrustedControllersState();
}

class _TrustedControllersState extends State<TrustedControllers> {
  List<String> _ids() => bind
      .mainGetOptionSync(key: kBoringTrustedControllers)
      .split(',')
      .map((s) => s.trim())
      .where((s) => s.isNotEmpty)
      .toList();

  Future<void> _remove(String id) async {
    final rest = _ids().where((x) => x != id).join(',');
    await bind.mainSetOption(key: kBoringTrustedControllers, value: rest);
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final ids = _ids();
    if (ids.isEmpty) {
      return const Padding(
        padding: EdgeInsets.all(8),
        child: Text(
            'None yet. A computer connecting for the first time needs a click here.'),
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
