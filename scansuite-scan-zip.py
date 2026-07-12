import argparse
import getpass
import sys
from pathlib import Path

import scansuite_cli


SUPPORTED_LANGUAGES = (
    "multilanguage",
    "python",
    "java",
    "kotlin",
    "javascript",
    "typescript",
    "php",
    "cpp",
    "csharp",
    "ruby",
    "go",
    "swift",
)

SCAN_MODES = {
    "once": "Once",
    "custom-scope": "Custom Scope",
}

CUSTOM_SCOPE_SCANNERS = frozenset(
    {"mlsast", "sast_quick", "sast_full", "sast_custom", "iacs_kics"}
)


def get_password(prompt):
    return getpass.getpass(prompt)


def get_user_input(prompt):
    return input(prompt)


parser = argparse.ArgumentParser(description="Run a static code scan from a ZIP archive.")
parser.add_argument("-s", "--server_url", type=str, help="Target server URL")
parser.add_argument("-u", "--username", type=str, help="ScanSuite user")
parser.add_argument("-p", "--password", type=str, help="ScanSuite password")
parser.add_argument("-l", "--lang", type=str, help="Programming language of the scan")
parser.add_argument(
    "-f",
    "--file-path",
    "--file_path",
    dest="file_path",
    help="Path to the ZIP archive to scan",
)
parser.add_argument(
    "-e",
    "--engagement-id",
    default="",
    help="Existing product engagement ID",
)
parser.add_argument(
    "--product-name",
    default="",
    help="Product name when creating a new product (default: archive filename)",
)
parser.add_argument(
    "-m",
    "--mode",
    choices=tuple(SCAN_MODES),
    default="once",
    help=(
        "Scanning mode. ZIP archives support once and custom-scope; incremental "
        "scanning requires a Git repository."
    ),
)
parser.add_argument(
    "--scope",
    action="append",
    default=[],
    metavar="PATTERN",
    help="Custom Scope archive-relative file, folder, or glob; repeat as needed",
)
parser.add_argument(
    "--scope-file",
    action="append",
    default=[],
    metavar="PATH",
    help="Read Custom Scope patterns from a UTF-8 file, one pattern per line",
)
parser.add_argument(
    "--scanners",
    default=None,
    metavar="ID[,ID...]",
    help=(
        "Comma-separated scanner IDs. Defaults to mlsast,secrets for a full "
        "scan and mlsast for Custom Scope."
    ),
)
parser.add_argument(
    "--mlsast-git-history",
    action="store_true",
    help="Enable MLSAST Git history analysis when the archive contains Git metadata",
)
parser.add_argument(
    "--no-reachability",
    action="store_true",
    help="Disable MLSAST reachability verification",
)
parser.add_argument(
    "--no-security-architecture",
    action="store_true",
    help="Disable MLSAST security architecture analysis",
)
parser.add_argument(
    "--no-secrets-ai",
    action="store_true",
    help="Disable AI processing for the secrets scanner",
)
parser.add_argument(
    "-r",
    "--repository-url",
    default="",
    help="Browsable repository URL used in finding links",
)

args = parser.parse_args()

server_url = (args.server_url or get_user_input("Enter server URL: ")).strip().rstrip("/")
username = (args.username or get_user_input("Enter username: ")).strip()
password = args.password or get_password("Enter password: ")
lang = (args.lang or get_user_input("Enter programming language: ")).strip().lower()
file_path = Path(
    args.file_path or get_user_input("Enter ZIP archive path: ")
).expanduser()
frequency = SCAN_MODES[args.mode]

if not server_url or not username or not password:
    sys.exit("Server URL, username, and password are required.")
if lang not in SUPPORTED_LANGUAGES:
    sys.exit(
        f"Unsupported language '{lang}'. Choose one of: {', '.join(SUPPORTED_LANGUAGES)}"
    )
if not file_path.is_file():
    sys.exit(f"ZIP archive does not exist: {file_path}")
if file_path.suffix.lower() != ".zip":
    sys.exit("Static archive scans require a .zip file.")

scope_patterns = list(args.scope)
for scope_file in args.scope_file:
    try:
        scope_patterns.extend(
            Path(scope_file).expanduser().read_text(encoding="utf-8").splitlines()
        )
    except OSError as exc:
        sys.exit(f"Could not read scope file '{scope_file}': {exc}")
scope_patterns = [pattern.strip() for pattern in scope_patterns if pattern.strip()]

if frequency == "Custom Scope" and not scope_patterns:
    sys.exit("Custom Scope mode requires at least one --scope or --scope-file pattern.")
if frequency != "Custom Scope" and scope_patterns:
    sys.exit("--scope and --scope-file can only be used with --mode custom-scope.")

default_scanners = "mlsast" if frequency == "Custom Scope" else "mlsast,secrets"
scanner_ids = tuple(
    dict.fromkeys(
        scanner_id.strip()
        for scanner_id in (args.scanners or default_scanners).split(",")
        if scanner_id.strip()
    )
)
unknown_scanners = set(scanner_ids) - scansuite_cli.SAST_SCANNER_IDS
if unknown_scanners:
    sys.exit("Unknown scanner ID(s): " + ", ".join(sorted(unknown_scanners)))
if frequency == "Custom Scope":
    unsupported_scanners = set(scanner_ids) - CUSTOM_SCOPE_SCANNERS
    if unsupported_scanners:
        sys.exit(
            "Custom Scope does not support scanner(s): "
            + ", ".join(sorted(unsupported_scanners))
        )

try:
    scanner_fields = {scanner_id: "on" for scanner_id in scanner_ids}
    if "mlsast" in scanner_fields:
        if args.mlsast_git_history:
            scanner_fields["mlsast_git_history"] = "on"
        if not args.no_reachability:
            scanner_fields["mlsast_reachability"] = "on"
        if not args.no_security_architecture:
            scanner_fields["mlsast_security_architecture"] = "on"
    if "secrets" in scanner_fields and not args.no_secrets_ai:
        scanner_fields["secrets_ai"] = "on"
    scanners_list = scansuite_cli.normalize_sast_scanners(scanner_fields)
except ValueError as exc:
    sys.exit(f"Invalid SAST scanner configuration: {exc}")

cookie = scansuite_cli.login(server_url, username, password)
if not cookie:
    sys.exit("Login failed. Exiting.")

engagement_id = args.engagement_id.strip()
if not engagement_id:
    product_name = args.product_name.strip() or file_path.name
    engid = scansuite_cli.create_product(server_url, cookie, product_name)
    if not engid:
        sys.exit(
            "Failed to create product. If it already exists, provide its "
            "engagement ID with --engagement-id."
        )
    engagement_id = scansuite_cli.extract_engagement_id(engid)
    if not engagement_id:
        sys.exit("The server did not return a valid product engagement ID. Exiting.")
print(f"Using product engagement ID: {engagement_id}")

scanid = scansuite_cli.static_scan_file(
    server_url,
    cookie,
    lang,
    engagement_id,
    str(file_path),
    scanners_list,
    frequency=frequency,
    repository_url=args.repository_url.strip(),
    scope_patterns="\n".join(scope_patterns),
)
if not scanid:
    sys.exit("Failed to initiate static scan. Exiting.")

scan_status = scansuite_cli.get_scan_status(server_url, cookie, scanid)
if scan_status:
    print(f"Scan {scanid} is with status {scan_status}")
