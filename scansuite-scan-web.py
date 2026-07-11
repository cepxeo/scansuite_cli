import scansuite_cli
import sys
import argparse
from datetime import datetime
import getpass

def get_password(prompt):
    return getpass.getpass(prompt)

def get_user_input(prompt):
    return input(prompt)

# Set up argument parser
parser = argparse.ArgumentParser(description="Run a dynamic web scan using scansuite_cli.")
parser.add_argument("-s", "--server_url", type=str, help="Target server URL")
parser.add_argument("-u", "--username", type=str, help="ScanSuite user")
parser.add_argument("-p", "--password", type=str, help="ScanSuite password")
parser.add_argument("-w", "--websites", type=str, help="Comma separated websites list")
parser.add_argument("-c", "--auth_cookie", type=str, default="", help="Authentication cookie (optional)")
parser.add_argument("-a", "--auth_header", type=str, default="", help="Authentication header (optional)")
parser.add_argument("-n", "--product_name", type=str, help="Product name (optional, defaults to current date and time)")

args = parser.parse_args()

# Prompt for missing arguments
server_url = args.server_url or get_user_input("Enter server URL: ")
username = args.username or get_user_input("Enter username: ")
password = args.password or get_password("Enter password: ")
websites = args.websites or get_user_input("Enter websites to scan: ")
auth_cookie = args.auth_cookie
auth_header = args.auth_header
product_name = args.product_name or datetime.now().strftime("%Y-%m-%d %H-%M-%S")

# Chosen scanners:
# Uncomment more, if required
web_scanners = {
    "dast_quick": "on",
    "dast_balanced": "on",
    "tech_discovery": "on",
    "dirbust": "on",
    # "zap_full": "on",
    # "api_scan": "on",
    # "nessus_web": "on",
    # "acunetix": "on",
    # "wpscan": "on",
    # "nikto": "on",
    # "crawl": "on",
    # "mldast": "on",
    "nuclei_custom": "on"
}

# Login
cookie = scansuite_cli.login(server_url, username, password)
if not cookie:
    sys.exit("Login failed. Exiting.")

# Create new product
# Product name should be unique
engid = scansuite_cli.create_product(server_url, cookie, product_name)
if not engid:
    sys.exit("Failed to create product. Exiting.")

# Start dynamic web scan
scanid = scansuite_cli.dynamic_scan(
    server_url, cookie, websites, engid.split(",")[1], auth_cookie, auth_header, web_scanners
)
if not scanid:
    sys.exit("Failed to initiate dynamic web scan. Exiting.")

# Example of the scan status check every 30 seconds until Finished:

# while True:
#     scan_status = scansuite_cli.get_scan_status(server_url, cookie, scanid)
#     if scan_status:
#         print(f"Scan {scanid} is with status {scan_status}")
#         if scan_status == "Finished":
#             break

#         print("Will check again in 30 seconds")
#         time.sleep(30)
#     else:
#         break
