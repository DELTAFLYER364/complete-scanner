"""Tests for scanner.py"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure we can import the scanner from the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import (
    Credential,
    _parse_dns,
    check_credential,
    load_combos,
    parse_combo_line,
    scan,
)


class TestCredential(unittest.TestCase):
    def setUp(self):
        self.cred = Credential(host="example.com", port=8080, username="user1", password="pass1")

    def test_base_url(self):
        self.assertEqual(self.cred.base_url, "http://example.com:8080")

    def test_m3u_url_contains_credentials(self):
        url = self.cred.m3u_url
        self.assertIn("username=user1", url)
        self.assertIn("password=pass1", url)
        self.assertIn("type=m3u_plus", url)
        self.assertIn("/get.php", url)

    def test_api_url_contains_credentials(self):
        url = self.cred.api_url
        self.assertIn("username=user1", url)
        self.assertIn("password=pass1", url)
        self.assertIn("/player_api.php", url)


class TestParseDns(unittest.TestCase):
    def test_plain_host_port(self):
        self.assertEqual(_parse_dns("example.com:8080"), ("example.com", 8080))

    def test_http_scheme(self):
        self.assertEqual(_parse_dns("http://example.com:8080"), ("example.com", 8080))

    def test_https_scheme(self):
        self.assertEqual(_parse_dns("https://example.com:8080"), ("example.com", 8080))

    def test_trailing_slash(self):
        self.assertEqual(_parse_dns("http://example.com:8080/"), ("example.com", 8080))

    def test_invalid_port(self):
        self.assertIsNone(_parse_dns("example.com:notaport"))

    def test_missing_port(self):
        self.assertIsNone(_parse_dns("example.com"))


class TestParseComboLine(unittest.TestCase):
    def test_four_part_combo(self):
        cred = parse_combo_line("myhost.com:8080:admin:secret")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.host, "myhost.com")
        self.assertEqual(cred.port, 8080)
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.password, "secret")

    def test_two_part_combo_with_dns(self):
        cred = parse_combo_line("admin:secret", dns="http://myhost.com:8080")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.host, "myhost.com")
        self.assertEqual(cred.port, 8080)
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.password, "secret")

    def test_two_part_combo_without_dns_returns_none(self):
        cred = parse_combo_line("admin:secret")
        self.assertIsNone(cred)

    def test_http_prefix_stripped(self):
        cred = parse_combo_line("http://myhost.com:8080:admin:secret")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.host, "myhost.com")

    def test_comment_line_returns_none(self):
        self.assertIsNone(parse_combo_line("# this is a comment"))

    def test_empty_line_returns_none(self):
        self.assertIsNone(parse_combo_line(""))
        self.assertIsNone(parse_combo_line("   "))

    def test_invalid_port_returns_none(self):
        self.assertIsNone(parse_combo_line("myhost.com:port:admin:secret"))


class TestLoadCombos(unittest.TestCase):
    def test_loads_four_part_combos(self):
        content = "host1.com:8080:user1:pass1\nhost2.com:9090:user2:pass2\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            creds = load_combos(path)
            self.assertEqual(len(creds), 2)
            self.assertEqual(creds[0].username, "user1")
            self.assertEqual(creds[1].username, "user2")
        finally:
            os.unlink(path)

    def test_loads_two_part_combos_with_dns(self):
        content = "user1:pass1\nuser2:pass2\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            creds = load_combos(path, dns="http://host.com:8080")
            self.assertEqual(len(creds), 2)
        finally:
            os.unlink(path)

    def test_skips_comments_and_blank_lines(self):
        content = "# comment\n\nhost.com:8080:user:pass\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            creds = load_combos(path)
            self.assertEqual(len(creds), 1)
        finally:
            os.unlink(path)

    def test_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            load_combos("/nonexistent/path/combos.txt")


class TestCheckCredential(unittest.TestCase):
    def _make_cred(self):
        return Credential(host="example.com", port=8080, username="user", password="pass")

    def test_returns_m3u_url_on_active_status(self):
        cred = self._make_cred()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"user_info": {"status": "Active"}}
        with patch("scanner.requests.get", return_value=mock_resp):
            result = check_credential(cred)
        self.assertEqual(result, cred.m3u_url)

    def test_returns_m3u_url_when_m3u_content_present(self):
        cred = self._make_cred()
        api_resp = MagicMock()
        api_resp.status_code = 200
        api_resp.json.return_value = {"user_info": {"status": "Disabled"}}

        m3u_resp = MagicMock()
        m3u_resp.status_code = 200
        m3u_resp.text = "#EXTM3U\n#EXTINF:-1,Channel1\nhttp://example.com/stream"

        with patch("scanner.requests.get", side_effect=[api_resp, m3u_resp]):
            result = check_credential(cred)
        self.assertEqual(result, cred.m3u_url)

    def test_returns_none_on_failed_auth(self):
        cred = self._make_cred()
        api_resp = MagicMock()
        api_resp.status_code = 200
        api_resp.json.return_value = {"user_info": {"status": "Disabled"}}

        m3u_resp = MagicMock()
        m3u_resp.status_code = 403
        m3u_resp.text = ""

        with patch("scanner.requests.get", side_effect=[api_resp, m3u_resp]):
            result = check_credential(cred)
        self.assertIsNone(result)

    def test_returns_none_on_connection_error(self):
        from requests.exceptions import ConnectionError as ReqConnErr
        cred = self._make_cred()
        with patch("scanner.requests.get", side_effect=ReqConnErr("refused")):
            result = check_credential(cred)
        self.assertIsNone(result)

    def test_returns_none_on_timeout(self):
        from requests.exceptions import ReadTimeout
        cred = self._make_cred()
        with patch("scanner.requests.get", side_effect=ReadTimeout("timed out")):
            result = check_credential(cred)
        self.assertIsNone(result)


class TestScan(unittest.TestCase):
    def _make_creds(self, n=3):
        return [
            Credential(host="host.com", port=8080, username=f"user{i}", password=f"pass{i}")
            for i in range(n)
        ]

    def test_returns_valid_urls(self):
        creds = self._make_creds(3)
        # First cred is valid, rest are not
        def fake_check(cred, timeout=10):
            if cred.username == "user0":
                return cred.m3u_url
            return None

        with patch("scanner.check_credential", side_effect=fake_check):
            valid = scan(creds, threads=2)

        self.assertEqual(len(valid), 1)
        self.assertIn("user0", valid[0])

    def test_writes_results_to_file(self):
        creds = self._make_creds(2)

        def fake_check(cred, timeout=10):
            return cred.m3u_url  # all valid

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            out_path = f.name

        try:
            with patch("scanner.check_credential", side_effect=fake_check):
                scan(creds, threads=2, output_path=out_path)
            with open(out_path) as fh:
                lines = [l.strip() for l in fh if l.strip()]
            self.assertEqual(len(lines), 2)
        finally:
            os.unlink(out_path)

    def test_empty_credentials_returns_empty(self):
        valid = scan([], threads=2)
        self.assertEqual(valid, [])


if __name__ == "__main__":
    unittest.main()
