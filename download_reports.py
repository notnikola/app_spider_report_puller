#!/usr/bin/env python3
"""
Download completed scan reports from AppSpider Enterprise.

Usage:
    python download_reports.py \
        --url https://appspider.example.com \
        --username admin \
        --password secret \
        --after 2025-01-01 \
        --output ./reports
"""

import argparse
import getpass
import os
import re
import sys
from datetime import datetime, timezone

import requests
import urllib3


BASE_PATH = "/AppSpiderEnterprise/rest/v1"


class AppSpiderClient:
    def __init__(self, base_url, verify_ssl=True):
        self.base_url = base_url.rstrip("/") + BASE_PATH
        self.verify_ssl = verify_ssl
        self.token = None
        self.session = requests.Session()

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _auth_header(self):
        headers = {}
        if self.token:
            headers["Authorization"] = f"Basic {self.token}"
        return headers

    def _get(self, endpoint, params=None, stream=False, timeout=120):
        url = f"{self.base_url}/{endpoint}"
        resp = self.session.get(
            url,
            headers=self._auth_header(),
            params=params,
            verify=self.verify_ssl,
            stream=stream,
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp

    def _post(self, endpoint, json_data=None, timeout=60):
        url = f"{self.base_url}/{endpoint}"
        headers = {**self._auth_header(), "Content-Type": "application/json"}
        resp = self.session.post(
            url,
            headers=headers,
            json=json_data,
            verify=self.verify_ssl,
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp

    def login(self, username, password, client_id=None):
        payload = {"name": username, "password": password}
        if client_id:
            payload["clientId"] = client_id
        resp = self._post("Authentication/Login", payload)
        data = resp.json()
        if not data.get("IsSuccess"):
            raise RuntimeError(
                f"Authentication failed: {data.get('ErrorMessage') or data.get('Reason') or 'unknown error'}"
            )
        self.token = data["Token"]

    def get_clients(self):
        """Fetch the list of clients accessible to the authenticated user."""
        resp = self._get("Client/GetClients")
        data = resp.json()
        if not data.get("IsSuccess"):
            raise RuntimeError(
                f"Failed to get clients: {data.get('ErrorMessage') or 'unknown error'}"
            )
        return data.get("Clients") or data.get("Data") or []

    def get_scans(self):
        """Fetch all scans."""
        resp = self._get("Scan/GetScans")
        data = resp.json()

        if not data.get("IsSuccess"):
            raise RuntimeError(
                f"Failed to get scans: {data.get('ErrorMessage') or 'unknown error'}"
            )

        return data.get("Scans") or data.get("Data") or []

    def get_scan_statuses(self):
        """Fetch the scan status enum mapping. Returns {name: id}."""
        resp = self._get("Scan/GetScanStatuses")
        data = resp.json()

        # Response is directly {name: id} dict, no wrapper
        # e.g. {'Completed': 32, 'Running': 82, ...}
        if "Completed" in data:
            return data

        if not data.get("IsSuccess"):
            raise RuntimeError(
                f"Failed to get scan statuses: {data.get('ErrorMessage') or 'unknown error'} | Raw: {data}"
            )

        # Fallback: try nested structures
        statuses = data.get("Statuses") or data.get("Data") or data.get("Result") or {}
        if isinstance(statuses, dict):
            return statuses

        return {}

    def has_report(self, scan_id):
        resp = self._get("Scan/HasReport", params={"scanId": scan_id})
        data = resp.json()
        return data.get("Result", False)

    def download_report_zip(self, scan_id):
        """Download ReportAllFiles.zip for a scan. Returns bytes."""
        resp = self._get("Report/GetReportZip", params={"scanId": scan_id}, stream=True)
        content = resp.content
        if not content or len(content) == 0:
            raise RuntimeError(f"Empty report returned for scan {scan_id}")
        return content


def parse_date(date_str):
    """Parse a date string from the API into a timezone-aware datetime.

    Handles ISO 8601, .NET JSON dates like /Date(1234567890000)/, and plain dates.
    """
    if not date_str:
        return None

    # Handle .NET JSON date format: /Date(1234567890000)/
    match = re.match(r"/Date\((\d+)([+-]\d{4})?\)/", date_str)
    if match:
        timestamp_ms = int(match.group(1))
        return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)

    # Try ISO 8601 formats
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Fallback: try fromisoformat (Python 3.7+)
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt
    except (ValueError, AttributeError):
        pass

    return None


def sanitize_filename(name):
    """Remove characters that are unsafe for filenames."""
    return re.sub(r'[<>:"/\\|?*]', "_", name).strip()


def main():
    parser = argparse.ArgumentParser(
        description="Download completed AppSpider Enterprise scan reports."
    )
    parser.add_argument("--url", required=True, help="AppSpider Enterprise base URL (e.g. https://appspider.example.com)")
    parser.add_argument("--username", required=True, help="Login username")
    parser.add_argument("--password", default=None, help="Login password (omit to be prompted securely)")
    parser.add_argument("--client", default=None, help="Client name to scope the session to (required for multi-client instances)")
    parser.add_argument("--after", required=True, help="Download reports for scans started after this date (YYYY-MM-DD)")
    parser.add_argument("--output", default="./reports", help="Output directory for downloaded reports (default: ./reports)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--debug", action="store_true", help="Print debug info (sample scan data)")

    args = parser.parse_args()

    # Prompt for password if not provided
    if not args.password:
        args.password = getpass.getpass(prompt="AppSpider password: ")

    # Parse cutoff date
    try:
        cutoff = datetime.strptime(args.after, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        print(f"Error: Invalid date format '{args.after}'. Use YYYY-MM-DD.", file=sys.stderr)
        sys.exit(1)

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Initialize client
    client = AppSpiderClient(args.url, verify_ssl=not args.no_verify_ssl)

    # Authenticate
    try:
        client.login(args.username, args.password)
        print("Authenticated successfully.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # If a client name is specified, look up its ID and re-authenticate scoped to it
    if args.client:
        try:
            clients = client.get_clients()
            match = None
            for c in clients:
                name = c.get("Name") or c.get("ClientName") or ""
                if name.lower() == args.client.lower():
                    match = c
                    break
            if not match:
                available = [c.get("Name") or c.get("ClientName") or "?" for c in clients]
                print(f"Error: Client '{args.client}' not found. Available: {', '.join(available)}", file=sys.stderr)
                sys.exit(1)
            client_id = match.get("Id") or match.get("ClientId")
            print(f"Switching to client '{args.client}' ({client_id})...")
            client.login(args.username, args.password, client_id=client_id)
            print("Re-authenticated with client scope.")
        except RuntimeError as e:
            print(f"Error resolving client: {e}", file=sys.stderr)
            sys.exit(1)

    # Fetch scan status mapping to find the "Completed" status ID
    try:
        status_map = client.get_scan_statuses()
        # status_map is {name: id}, e.g. {'Completed': 32, 'Running': 82}
        completed_status_id = status_map.get("Completed")
        if completed_status_id is None:
            print(f"Warning: Could not find 'Completed' status in: {list(status_map.keys())}", file=sys.stderr)
        else:
            print(f"Completed status ID: {completed_status_id}")
    except Exception as e:
        print(f"Warning: Could not fetch status mapping: {e}", file=sys.stderr)
        completed_status_id = None

    # Fetch scans
    print("Fetching scan list...")
    try:
        scans = client.get_scans()
    except Exception as e:
        print(f"Error fetching scans: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(scans)} total scans.")

    if args.debug and scans:
        import json
        print("\n[DEBUG] Sample scan object:")
        print(json.dumps(scans[0], indent=2, default=str))
        print()

    # Filter for completed scans started after cutoff date
    matching = []
    for scan in scans:
        status = scan.get("Status")
        # Status is an integer enum; compare to completed_status_id
        if completed_status_id is not None:
            if status != completed_status_id:
                continue
        else:
            # Fallback: try string comparison if we couldn't get the mapping
            if str(status).lower() != "completed":
                continue

        start_time_str = scan.get("StartTime")
        start_time = parse_date(start_time_str)

        if start_time and start_time >= cutoff:
            matching.append((scan, start_time))

    print(f"Found {len(matching)} completed scans started after {args.after}.")

    if not matching:
        print("Nothing to download.")
        return

    # Download reports
    downloaded = 0
    skipped = 0

    for scan, start_time in matching:
        scan_id = scan.get("Id") or scan.get("ScanId") or scan.get("id")
        scan_name = scan.get("Name") or scan.get("ScanName") or scan.get("ConfigName") or str(scan_id)

        label = f"{scan_name} ({scan_id})"
        date_tag = start_time.strftime("%Y%m%d")

        # Check if report exists
        try:
            if not client.has_report(scan_id):
                print(f"  SKIP {label} — no report available")
                skipped += 1
                continue
        except Exception as e:
            print(f"  SKIP {label} — error checking report: {e}")
            skipped += 1
            continue

        # Download
        safe_name = sanitize_filename(scan_name)
        filename = f"{safe_name}_{date_tag}_{scan_id}.zip"
        filepath = os.path.join(args.output, filename)

        print(f"  Downloading {label}...")
        try:
            content = client.download_report_zip(scan_id)
            with open(filepath, "wb") as f:
                f.write(content)
            print(f"    Saved: {filepath} ({len(content):,} bytes)")
            downloaded += 1
        except Exception as e:
            print(f"    FAILED: {e}")
            skipped += 1

    print(f"\nDone. Downloaded: {downloaded}, Skipped: {skipped}")


if __name__ == "__main__":
    main()
