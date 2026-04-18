#!/usr/bin/env python3
"""Make an HTTP request and analyze response headers.

Usage examples:
  python3 analyze_headers.py https://example.com
  python3 analyze_headers.py https://example.com --method HEAD --timeout 8
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class AnalysisResult:
    score: int
    positives: List[str]
    warnings: List[str]


WARNING_REMEDIATION = {
    "Add Content-Security-Policy to reduce XSS risk.": (
        "Add header example: Content-Security-Policy: default-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    ),
    "Add X-Content-Type-Options: nosniff.": (
        "Add header example: X-Content-Type-Options: nosniff"
    ),
    "Add X-Frame-Options (DENY or SAMEORIGIN).": (
        "Add header example: X-Frame-Options: SAMEORIGIN"
    ),
    "Add Referrer-Policy to limit referrer leakage.": (
        "Add header example: Referrer-Policy: strict-origin-when-cross-origin"
    ),
    "Add Permissions-Policy to restrict browser features.": (
        "Add header example: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    ),
    "Add Strict-Transport-Security for HTTPS responses.": (
        "Add header example: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ),
    "Server header is exposed; consider minimizing server fingerprinting.": (
        "Server setting: remove or minimize the Server response header where possible"
    ),
    "X-Powered-By header is exposed; consider removing it.": (
        "App/server setting: disable X-Powered-By header"
    ),
    "Review Cache-Control directives for sensitive responses.": (
        "Sensitive-content example: Cache-Control: no-store, max-age=0"
    ),
    "CORS allows all origins (*); verify this is intended.": (
        "CORS setting: replace '*' with trusted origin(s) if credentials or sensitive data are involved"
    ),
}


def remediation_steps(warnings: List[str]) -> List[str]:
    steps: List[str] = []
    for warning in warnings:
        fix = WARNING_REMEDIATION.get(warning)
        if fix:
            steps.append(f"{warning} -> {fix}")
    return steps


def normalize_headers(headers: urllib.request.HTTPMessage) -> Dict[str, str]:
    return {k.lower(): v.strip() for k, v in headers.items()}


def analyze_headers(headers: Dict[str, str], is_https: bool) -> AnalysisResult:
    positives: List[str] = []
    warnings: List[str] = []
    score = 0

    security_headers = {
        "content-security-policy": "Add Content-Security-Policy to reduce XSS risk.",
        "x-content-type-options": "Add X-Content-Type-Options: nosniff.",
        "x-frame-options": "Add X-Frame-Options (DENY or SAMEORIGIN).",
        "referrer-policy": "Add Referrer-Policy to limit referrer leakage.",
        "permissions-policy": "Add Permissions-Policy to restrict browser features.",
    }

    for header_name, missing_msg in security_headers.items():
        if header_name in headers:
            positives.append(f"{header_name} is present.")
            score += 10
        else:
            warnings.append(missing_msg)

    if is_https:
        if "strict-transport-security" in headers:
            positives.append("strict-transport-security is present.")
            score += 15
        else:
            warnings.append("Add Strict-Transport-Security for HTTPS responses.")
    else:
        warnings.append("Target is not HTTPS, so transport is not encrypted in transit.")

    server = headers.get("server")
    if server:
        warnings.append("Server header is exposed; consider minimizing server fingerprinting.")
    else:
        positives.append("Server header is not exposed.")
        score += 5

    powered_by = headers.get("x-powered-by")
    if powered_by:
        warnings.append("X-Powered-By header is exposed; consider removing it.")
    else:
        positives.append("X-Powered-By header is not exposed.")
        score += 5

    cache_control = headers.get("cache-control", "")
    if "no-store" in cache_control.lower() or "private" in cache_control.lower():
        positives.append("Cache-Control includes privacy-aware directives.")
        score += 5
    elif cache_control:
        warnings.append("Review Cache-Control directives for sensitive responses.")

    acao = headers.get("access-control-allow-origin")
    if acao == "*":
        warnings.append("CORS allows all origins (*); verify this is intended.")
    elif acao:
        positives.append("CORS policy is explicitly set.")
        score += 5

    score = max(0, min(score, 100))
    return AnalysisResult(score=score, positives=positives, warnings=warnings)


def build_request(url: str, method: str) -> urllib.request.Request:
    return urllib.request.Request(
        url=url,
        method=method,
        headers={
            "User-Agent": "header-analyzer/1.0",
            "Accept": "*/*",
        },
    )


def fetch(url: str, method: str, timeout: float, insecure: bool) -> tuple[str, int, Dict[str, str]]:
    context = None
    if insecure:
        context = ssl._create_unverified_context()

    request = build_request(url, method)
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        final_url = response.geturl()
        status = response.status
        headers = normalize_headers(response.headers)
        return final_url, status, headers


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send an HTTP request and analyze response headers."
    )
    parser.add_argument("url", help="Target URL (for example: https://example.com)")
    parser.add_argument(
        "--method",
        choices=["GET", "HEAD"],
        default="GET",
        help="HTTP method to use (default: GET)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification (testing only)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print output as JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.timeout <= 0:
        print("Error: --timeout must be greater than 0", file=sys.stderr)
        return 2

    try:
        final_url, status, headers = fetch(args.url, args.method, args.timeout, args.insecure)
    except urllib.error.HTTPError as exc:
        print(f"HTTP error: {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"Request failed: {exc.reason}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Invalid URL: {exc}", file=sys.stderr)
        return 1

    analysis = analyze_headers(headers, is_https=final_url.lower().startswith("https://"))
    remediations = remediation_steps(analysis.warnings)

    if args.json:
        payload = {
            "url": args.url,
            "final_url": final_url,
            "status": status,
            "headers": headers,
            "analysis": {
                "score": analysis.score,
                "positives": analysis.positives,
                "warnings": analysis.warnings,
                "remediations": remediations,
            },
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"URL: {args.url}")
    print(f"Final URL: {final_url}")
    print(f"Status: {status}")
    print("\nHeaders:")
    for key in sorted(headers):
        print(f"  {key}: {headers[key]}")

    print("\nAnalysis:")
    print(f"  Security score: {analysis.score}/100")

    if analysis.positives:
        print("  Positive findings:")
        for item in analysis.positives:
            print(f"    - {item}")

    if analysis.warnings:
        print("  Warnings:")
        for item in analysis.warnings:
            print(f"    - {item}")

        if remediations:
            print("\nFix Suggestions:")
            for item in remediations:
                print(f"  - {item}")
    else:
        print("  Warnings: none")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
