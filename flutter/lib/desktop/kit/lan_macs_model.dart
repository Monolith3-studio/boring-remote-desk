import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/models/platform_model.dart';

import 'lan_macs.dart';

/// Mac Home's "On this network" list, fed by the `load_lan_peers` event src/lan.rs
/// pushes after every LAN Discovery cycle. A Mac that misses a round stays listed for a grace.
class LanMacsModel extends ChangeNotifier {
  List<LanMac> macs = const [];
  final _seen = <String, LanSeen>{};

  LanMacsModel() {
    platformFFI.registerEventHandler('load_lan_peers', 'boring-mac-home', (evt) async {
      macs = keepRecentLanMacs(_seen, lanMacsFromJson((evt['peers'] ?? '').toString()), DateTime.now());
      notifyListeners();
    });
    bind.mainLoadLanPeers();
  }
}

final lanMacs = LanMacsModel();
