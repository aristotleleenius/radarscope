import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import radarscope


class RadarScopeV3Tests(unittest.TestCase):
    def test_invalid_hostname_tokens_are_not_machine_identity(self) -> None:
        self.assertIsNone(radarscope.clean_hostname("NXDOMAIN", "192.168.1.100"))
        self.assertIsNone(radarscope.clean_hostname("found", "192.168.1.100"))
        self.assertIsNone(radarscope.clean_hostname("not", "192.168.1.100"))

    def test_nmap_nxdomain_without_mac_is_discarded(self) -> None:
        xml = (
            '<nmaprun><host><status state="up"/>'
            '<address addr="192.168.1.100" addrtype="ipv4"/>'
            '<hostnames><hostname name="NXDOMAIN"/></hostnames>'
            '</host></nmaprun>'
        )
        self.assertEqual(radarscope.parse_nmap_discovery_xml(xml), [])

    def test_topology_hides_unidentified_pollution(self) -> None:
        devices = [
            {"ip": "192.168.1.100", "hostname": "NXDOMAIN", "mac": None, "source": ["nmap"]},
            {"ip": "224.0.0.251", "hostname": "mdns.mcast.net", "mac": "01:00:5e:00:00:fb", "source": ["arp"]},
            {"ip": "192.168.1.10", "hostname": "test-device.home", "mac": "aa:bb:cc:dd:ee:ff", "source": ["arp"]},
        ]
        system = {
            "hostname": "mac.home",
            "default_interface": "en0",
            "interfaces": [{"name": "en0", "ipv4": "192.168.1.47", "loopback": False}],
        }
        with patch.object(radarscope, "default_gateway", return_value=None):
            topology = radarscope.build_topology(devices, system)
        self.assertEqual(topology["device_count"], 1)
        self.assertEqual(topology["nodes"][-1]["ip"], "192.168.1.10")

    def test_current_wifi_is_marked_for_ui_filtering(self) -> None:
        networks = [{"ssid": "Maison", "bssid": "aa:bb:cc:dd:ee:ff"}, {"ssid": "Voisin", "bssid": "11:22:33:44:55:66"}]
        marked = radarscope.mark_current_wifi(networks, "Maison")
        self.assertTrue(marked[0]["current"])
        self.assertFalse(marked[1]["current"])

    def test_normalise_mac_pads_single_digit_octets(self) -> None:
        self.assertEqual(radarscope.normalise_mac("aa:bb:cc:dd:e:f"), "aa:bb:cc:dd:0e:0f")

    def test_parse_arp_output_keeps_hostname_when_arp_provides_it(self) -> None:
        output = "test-device.home (192.0.2.47) at 00:11:22:33:44:55 on en0 ifscope [ethernet]"
        with patch.object(radarscope, "command_output", return_value=output):
            entries = radarscope.collect_arp_entries()
        self.assertEqual(entries[0]["hostname"], "test-device.home")
        self.assertEqual(entries[0]["hostname_source"], "arp")

    def test_collect_arp_entries_ignores_unreachable_and_broadcast_rows(self) -> None:
        output = "\n".join(
            [
                "? (192.168.1.0) at ff:ff:ff:ff:ff:ff on en0",
                "? (192.168.1.11) at (incomplete) on en0",
                "camera.home (192.168.1.20) at aa:bb:cc:dd:ee:ff on en0",
            ]
        )
        with patch.object(radarscope, "command_output", return_value=output):
            entries = radarscope.collect_arp_entries()
        self.assertEqual([entry["ip"] for entry in entries], ["192.168.1.20"])

    def test_reverse_dns_parser_prefers_the_actual_pointer(self) -> None:
        output = "192.168.1.1.in-addr.arpa domain name pointer router.home."
        self.assertEqual(
            radarscope._hostname_from_command_output(output, "192.168.1.1"),
            "router.home",
        )

    def test_enrich_device_identities_uses_multi_source_resolver(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_file = str(Path(directory) / "state.json")
            devices = [{"ip": "192.168.1.20", "hostname": None}]
            with patch.object(
                radarscope,
                "reverse_dns_lookup",
                return_value=("laptop.home", "reverse-dns"),
            ):
                enriched = radarscope.enrich_device_identities(devices, state_file, True)
            self.assertEqual(enriched[0]["hostname"], "laptop.home")
            self.assertEqual(enriched[0]["hostname_source"], "reverse-dns")
            saved = json.loads(Path(state_file).read_text(encoding="utf-8"))
            self.assertEqual(saved["hostnames"]["192.168.1.20"], "laptop.home")

    def test_parse_airport_scan_extracts_ssid_signal_channel_and_security(self) -> None:
        output = (
            "SSID                             BSSID             RSSI CHANNEL HT CC SECURITY\n"
            "Cafe Wifi                        aa:bb:cc:dd:ee:ff -52  44      Y  FR WPA(PSK/AES/AES)\n"
        )
        networks = radarscope.parse_airport_scan(output)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["ssid"], "Cafe Wifi")
        self.assertEqual(networks[0]["rssi_dbm"], -52)
        self.assertEqual(networks[0]["band"], "5 GHz")

    def test_parse_profiler_wifi_ignores_interface_rows_and_marks_current(self) -> None:
        data = {
            "spairport_airport_interfaces": [
                {
                    "_name": "en0",
                    "spairport_current_network_information": {
                        "_name": "<redacted>",
                        "spairport_network_channel": "1 (2GHz, 20MHz)",
                        "spairport_security_mode": "WPA2",
                    },
                    "spairport_airport_other_local_wireless_networks": [
                        {
                            "_name": "<redacted>",
                            "spairport_network_channel": "44 (5GHz, 80MHz)",
                            "spairport_security_mode": "WPA2",
                        },
                        {
                            "_name": "<redacted>",
                            "spairport_network_channel": "100 (5GHz, 80MHz)",
                            "spairport_security_mode": "WPA2",
                        }
                    ],
                }
            ]
        }
        networks = radarscope.parse_profiler_wifi(data)
        self.assertEqual(len(networks), 3)
        self.assertTrue(networks[0]["current"])
        self.assertFalse(networks[1]["current"])
        self.assertFalse(networks[2]["current"])

    def test_parse_blueutil_json_extracts_nearby_device(self) -> None:
        output = json.dumps(
            [{"address": "78-2B-64-A0-80-66", "name": "BoseQC45", "rssi": -41, "connected": 1}]
        )
        devices = radarscope.parse_blueutil_inquiry(output)
        self.assertEqual(devices[0]["address"], "78:2b:64:a0:80:66")
        self.assertTrue(devices[0]["connected"])
        self.assertTrue(devices[0]["nearby"])

    def test_parse_nmap_xml_and_merge_with_arp(self) -> None:
        xml = (
            '<nmaprun><host><status state="up"/>'
            '<address addr="192.168.1.10" addrtype="ipv4"/>'
            '<address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="Apple"/>'
            '<hostnames><hostname name="macbook.home"/></hostnames>'
            '<times srtt="12345"/></host></nmaprun>'
        )
        active = radarscope.parse_nmap_discovery_xml(xml)
        merged = radarscope.merge_machine_records(
            [{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "source": ["arp"]}],
            active,
        )
        self.assertEqual(merged[0]["hostname"], "macbook.home")
        self.assertEqual(merged[0]["vendor"], "Apple")
        self.assertEqual(merged[0]["source"], ["arp", "nmap"])
        self.assertEqual(merged[0]["latency_ms"], 12.35)


if __name__ == "__main__":
    unittest.main()
