import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/kit/lan_macs.dart';

const studio = LanMac(name: 'edit-bay-2', ip: '192.168.1.20');
const stage = LanMac(name: 'stage-left', ip: '10.0.4.7');
const all = [studio, stage];

void main() {
  test('discovered peers arrive with hostname and IP; ones without an IP are skipped', () {
    final macs = lanMacsFromJson('[{"id":"1","hostname":"edit-bay-2","ip":"192.168.1.20"},'
        '{"id":"2","hostname":"","ip":"10.0.4.7"},{"id":"3","hostname":"public","ip":""}]');
    expect(macs.map((m) => '${m.name} ${m.ip}'), ['edit-bay-2 192.168.1.20', 'Unnamed Mac 10.0.4.7']);
    expect(lanMacsFromJson(''), isEmpty);
    expect(lanMacsFromJson('not json'), isEmpty);
  });

  test('filter matches a name substring, any case', () {
    expect(filterLanMacs(all, 'BAY'), [studio]);
    expect(filterLanMacs(all, ''), all);
  });

  test('filter matches an IP prefix, not an IP substring', () {
    expect(filterLanMacs(all, '192.168.'), [studio]);
    expect(filterLanMacs(all, '10.0'), [stage]);
    expect(filterLanMacs(all, '168.1'), isEmpty);
  });

  test('a bare IP is one address, no port, no name', () {
    for (final s in ['192.168.1.40', ' 10.0.0.1 ', 'fe80::1']) {
      expect(isBareIp(s), isTrue, reason: s);
    }
    for (final s in ['192.168.1', '192.168.1.40:21118', 'edit-bay-2', '']) {
      expect(isBareIp(s), isFalse, reason: s);
    }
  });

  test('a Mac that misses one discovery round stays listed, in place, until the grace runs out', () {
    final memory = <String, LanSeen>{};
    final t0 = DateTime(2026, 11, 2, 13, 0, 0);
    expect(keepRecentLanMacs(memory, all, t0), all);
    // One round where stage-left's answer was missed: still listed, same order.
    expect(keepRecentLanMacs(memory, [studio], t0.add(const Duration(seconds: 6))), all);
    // It answers again: back to fresh, nothing doubled.
    expect(keepRecentLanMacs(memory, [stage, studio], t0.add(const Duration(seconds: 12))), all);
    // Gone past the grace: dropped.
    expect(keepRecentLanMacs(memory, [studio], t0.add(const Duration(seconds: 33))), [studio]);
  });
}
