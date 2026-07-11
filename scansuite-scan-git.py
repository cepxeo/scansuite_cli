import scansuite_cli
import sys
import argparse
import getpass

SUPPORTED_LANGUAGES = (
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

args = parser.parse_args()

# Prompt for missing arguments
server_url = (args.server_url or get_user_input("Enter server URL: ")).strip().rstrip("/")
username = (args.username or get_user_input("Enter username: ")).strip()
password = args.password or get_password("Enter password: ")
lang = (args.lang or get_user_input("Enter programming language: ")).strip().lower()
giturl = (args.giturl or get_user_input("Enter Git repository URL: ")).strip()
repository_url = (args.repository_url or giturl).strip()
branch_name = args.branch_name.strip()

if not server_url or not username or not password or not giturl:
    sys.exit("Server URL, username, password, and Git repository URL are required.")
if lang not in SUPPORTED_LANGUAGES:
    sys.exit(
        f"Unsupported language '{lang}'. Choose one of: {', '.join(SUPPORTED_LANGUAGES)}"
    )

# Scanner checkbox fields accepted by the server's SAST configuration.
# Include only desired scanners; static_scan_url normalizes enabled values to "on".
try:
    scanners_list = scansuite_cli.normalize_sast_scanners({
        "mlsast": "on",
        "mlsast_git_history": "on",
        "mlsast_reachability": "on",
        "mlsast_security_architecture": "on",
        "secrets": "on",
        "secrets_ai": "on",

        # Other available SAST scanners. Uncomment the desired entries.
        # "sast_quick": "on",
        # "sast_full": "on",
        # "sast_custom": "on",
        # "snyk": "on",
        # "dep_checks": "on",
        # "dep_checks_ai": "on",  # Requires dep_checks.
        # "iacs_kics": "on",
        # "gen_docs": "on",
        # "code_flow": "on",
    })
except ValueError as exc:
    sys.exit(f"Invalid SAST scanner configuration: {exc}")

# Login
cookie = scansuite_cli.login(server_url, username, password)
if not cookie:
    sys.exit("Login failed. Exiting.")

git_repo_name = scansuite_cli.extract_file_name(giturl)

# Create new product
product_name = git_repo_name
engid = scansuite_cli.create_product(server_url, cookie, product_name)
if not engid:
    sys.exit("Failed to create product. Exiting.")
engagement_id = scansuite_cli.extract_engagement_id(engid)
if not engagement_id:
    sys.exit("The server did not return a valid product engagement ID. Exiting.")

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
    frequency="Once",
    scan_id="New",
)
if not scanid:
    sys.exit("Failed to initiate static scan. Exiting.")

# Example of the new scan status check
scan_status = scansuite_cli.get_scan_status(server_url, cookie, scanid)
if scan_status:
    print(f"Scan {scanid} is with status {scan_status}")
