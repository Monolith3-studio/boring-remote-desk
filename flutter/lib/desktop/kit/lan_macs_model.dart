import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/models/platform_model.dart';

import 'lan_macs.dart';

/// Mac Home's "On this network" list, fed by the `load_lan_peers` event src/lan.rs
/// pushes after every LAN Discovery cycle. Peers that left are already pruned there.
class LanMacsModel extends ChangeNotifier {
  List<LanMac> macs = const [];

  LanMacsModel() {
    platformFFI.registerEventHandler('load_lan_peers', 'boring-mac-home', (evt) async {
      macs = lanMacsFromJson((evt['peers'] ?? '').toString());
      notifyListeners();
    });
    bind.mainLoadLanPeers();
  }
}

final lanMacs = LanMacsModel();
