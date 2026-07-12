import scansuite_cli
import sys
import argparse
import getpass
from pathlib import Path

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
    "incremental": "Incremental Scan",
    "custom-scope": "Custom Scope",
    "monitor-changes": "Monitor Changes",
    "daily": "Daily",
    "weekly": "Weekly",
    "monthly": "Monthly",
}

CUSTOM_SCOPE_SCANNERS = frozenset(
    {"mlsast", "sast_quick", "sast_full", "sast_custom", "iacs_kics"}
)

def get_password(prompt):
    return getpass.getpass(prompt)

def get_user_input(prompt):
    return input(prompt)

# Set up argument parser
parser = argparse.ArgumentParser(description="Run a static code scan using scansuite_cli.")
parser.add_argument("-s", "--server_url", type=str, help="Target server URL")
parser.add_argument("-u", "--username", type=str, help="ScanSuite user")
parser.add_argument("-p", "--password", type=str, help="ScanSuite password")
parser.add_argument("-l", "--lang", type=str, help="Programming language of the scan")
parser.add_argument("-g", "--giturl", type=str, help="Git repository URL to be scanned")
parser.add_argument(
    "-e",
    "--engagement-id",
    default="",
    help=(
        "Existing product engagement ID. Reuse the same ID for incremental "
        "and monitored scans."
    ),
)
parser.add_argument(
    "--product-name",
    default="",
    help="Product name when creating a new product (default: repository name)",
)
parser.add_argument(
    "-r",
    "--repository-url",
    "--repository_url",
    default="",
    help=(
        "Repository web URL used in secrets finding links "
        "(default: Git repository URL)"
    ),
)
parser.add_argument(
    "-b",
    "--branch-name",
    "--branch_name",
    default="",
    help="Repository branch to scan (default: repository default branch)",
)
parser.add_argument(
    "-m",
    "--mode",
    choices=tuple(SCAN_MODES),
    default="once",
    help="Scanning mode (default: once)",
)
parser.add_argument(
    "--scope",
    action="append",
    default=[],
    metavar="PATTERN",
    help=(
        "Custom Scope repository-relative file, folder, or Git-style glob. "
        "Repeat this option for multiple patterns."
    ),
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
        "Comma-separated scanner IDs. Defaults to mlsast,secrets for normal "
        "modes and mlsast for Custom Scope."
    ),
)
parser.add_argument(
    "--no-mlsast-git-history",
    action="store_true",
    help="Disable MLSAST Git history analysis",
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
    "--scan-name",
    default="New",
    help="Saved definition name for scheduled or Monitor Changes modes",
)

args = parser.parse_args()

# Prompt for missing arguments
server_url = (args.server_url or get_user_input("Enter server URL: ")).strip().rstrip("/")
username = (args.username or get_user_input("Enter username: ")).strip()
password = args.password or get_password("Enter password: ")
lang = (args.lang or get_user_input("Enter programming language: ")).strip().lower()
giturl = (args.giturl or get_user_input("Enter Git repository URL: ")).strip()
repository_url = (args.repository_url or giturl).strip()
branch_name = args.branch_name.strip()
frequency = SCAN_MODES[args.mode]

if not server_url or not username or not password or not giturl:
    sys.exit("Server URL, username, password, and Git repository URL are required.")
if lang not in SUPPORTED_LANGUAGES:
    sys.exit(
        f"Unsupported language '{lang}'. Choose one of: {', '.join(SUPPORTED_LANGUAGES)}"
    )

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

# Build the checkbox fields accepted by the server's SAST configuration.
try:
    scanner_fields = {scanner_id: "on" for scanner_id in scanner_ids}
    if "mlsast" in scanner_fields:
        if not args.no_mlsast_git_history:
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

# Login
cookie = scansuite_cli.login(server_url, username, password)
if not cookie:
    sys.exit("Login failed. Exiting.")

engagement_id = args.engagement_id.strip()
if not engagement_id:
    git_repo_name = scansuite_cli.extract_file_name(giturl)
    product_name = args.product_name.strip() or git_repo_name
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

# Initiate new static scan
scanid = scansuite_cli.static_scan_url(
    server_url,
    cookie,
    giturl,
    lang,
    engagement_id,
    scanners_list,
    branch_name=branch_name,
    repository_url=repository_url,
    frequency=frequency,
    scan_id=args.scan_name,
    scope_patterns="\n".join(scope_patterns),
)
if not scanid:
    sys.exit("Failed to initiate static scan. Exiting.")

# Example of the new scan status check
scan_status = scansuite_cli.get_scan_status(server_url, cookie, scanid)
if scan_status:
    print(f"Scan {scanid} is with status {scan_status}")
