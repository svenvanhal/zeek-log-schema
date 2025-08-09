from unittest import TestCase

from zeek_log_schema.zkg.packages import parse_zkg_index


class TestZkgPackages(TestCase):
    def test_parse_zkg_index(self):
        test_zkg_index_lines = """https://github.com/zeek/hello-world
https://github.com/zeek/logschema
https://github.com/zeek/osquery-framework
https://github.com/zeek/spicy-analyzers
https://github.com/zeek/spicy-dhcp
https://github.com/zeek/spicy-dns
https://github.com/zeek/spicy-http
https://github.com/zeek/spicy-ldap
https://github.com/zeek/spicy-pe
https://github.com/zeek/spicy-plugin
https://github.com/zeek/spicy-png
https://github.com/zeek/spicy-tftp
https://github.com/zeek/spicy-zip
https://github.com/zeek/zeek-af_packet-plugin
https://github.com/zeek/zeek-cluster-backend-nats
https://github.com/zeek/zeek-more-hashes
https://github.com/zeek/zeek-netmap
https://github.com/zeek/zeek-perf-support""".split()

        expected = {
            "zeek/hello-world": "https://github.com/zeek/hello-world",
            "zeek/logschema": "https://github.com/zeek/logschema",
            "zeek/osquery-framework": "https://github.com/zeek/osquery-framework",
            "zeek/spicy-analyzers": "https://github.com/zeek/spicy-analyzers",
            "zeek/spicy-dhcp": "https://github.com/zeek/spicy-dhcp",
            "zeek/spicy-dns": "https://github.com/zeek/spicy-dns",
            "zeek/spicy-http": "https://github.com/zeek/spicy-http",
            "zeek/spicy-ldap": "https://github.com/zeek/spicy-ldap",
            "zeek/spicy-pe": "https://github.com/zeek/spicy-pe",
            "zeek/spicy-plugin": "https://github.com/zeek/spicy-plugin",
            "zeek/spicy-png": "https://github.com/zeek/spicy-png",
            "zeek/spicy-tftp": "https://github.com/zeek/spicy-tftp",
            "zeek/spicy-zip": "https://github.com/zeek/spicy-zip",
            "zeek/zeek-af_packet-plugin": "https://github.com/zeek/zeek-af_packet-plugin",
            "zeek/zeek-cluster-backend-nats": "https://github.com/zeek/zeek-cluster-backend-nats",
            "zeek/zeek-more-hashes": "https://github.com/zeek/zeek-more-hashes",
            "zeek/zeek-netmap": "https://github.com/zeek/zeek-netmap",
            "zeek/zeek-perf-support": "https://github.com/zeek/zeek-perf-support",
        }

        self.assertDictEqual(expected, parse_zkg_index(test_zkg_index_lines))

    def test_parse_zkg_future_proof(self):
        test_zkg_index_lines = [
            "https://gitlab.com/example/package1\r\n",
            "https://github.com/example/package2?query=test#fragment\n"
        ]

        expected = {
            "example/package1": "https://gitlab.com/example/package1",
            "example/package2": "https://github.com/example/package2?query=test#fragment",
        }

        self.assertDictEqual(expected, parse_zkg_index(test_zkg_index_lines))
