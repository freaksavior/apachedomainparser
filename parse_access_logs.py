import re
from collections import defaultdict
from datetime import datetime
import os
import argparse

# Function to parse arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Parse Apache access logs to analyze request counts per hour for each domain.')
    parser.add_argument('--verbosedomain', action='store_true', help='Show verbose output for domain checks')
    parser.add_argument('--verboselog', action='store_true', help='Show verbose output for log file checks')
    parser.add_argument('--verboseall', action='store_true', help='Show all verbose outputs')
    return parser.parse_args()

# Parse command-line arguments
args = parse_args()

# Paths to the necessary files
user_domain_file = '/etc/userdatadomains'
log_directory = '/home/{user}/logs/'
# Adjusted regex to match the provided Apache log format
log_format = r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]+)" "(?P<user_agent>[^"]+)"'

# Dictionary to hold domain -> hourly -> IP -> request counts
domain_stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

# Prompt the user for a date range
start_date_str = input("Enter the start date (dd/mm/yyyy): ")
end_date_str = input("Enter the end date (dd/mm/yyyy): ")

# Convert input strings to datetime objects for comparison
try:
    start_date = datetime.strptime(start_date_str, '%d/%m/%Y')
    end_date = datetime.strptime(end_date_str, '%d/%m/%Y')
except ValueError:
    print("Invalid date format. Please use dd/mm/yyyy.")
    exit(1)

# Step 1: Parse the domain list
domains = {}
with open(user_domain_file, 'r') as file:
    for line in file:
        parts = line.strip().split("==")
        if len(parts) >= 2:
            # Get domain and username
            domain_name = parts[0].split(":")[0]  # Extracts domain before ":"
            user = parts[0].split(":")[1].strip()  # Extracts and strips username after ":"
            domains[domain_name] = user
            if args.verbosedomain or args.verboseall:
                print(f"[INFO] Loaded domain '{domain_name}' for user '{user}'.")

# Step 2: Parse logs for each domain/user
for domain, user in domains.items():
    if args.verbosedomain or args.verboseall:
        print(f"\n[INFO] Checking logs for domain '{domain}' (User: '{user}')")

    # Construct possible log file names
    log_path_non_ssl = os.path.join(log_directory.format(user=user), f"{domain}")
    log_path_ssl = os.path.join(log_directory.format(user=user), f"{domain}-ssl-log")

    # Try to open each log file (non-SSL and SSL versions)
    processed_logs = False
    for log_path in [log_path_non_ssl, log_path_ssl]:
        if args.verboselog or args.verboseall:
            print(f"  [INFO] Checking for log file: {log_path}")

        if not os.path.isfile(log_path):
            print(f"    [WARNING] Log file '{log_path}' not found, skipping.")
            continue

        if args.verboselog or args.verboseall:
            print(f"    [INFO] Processing log file '{log_path}'...")
        processed_logs = True

        try:
            with open(log_path, 'r') as log_file:
                for line in log_file:
                    match = re.match(log_format, line)
                    if match:
                        # Parse and filter based on date
                        time_str = match.group('time').split()[0]  # Remove timezone part
                        log_time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S')
                        log_date = log_time.date()

                        if start_date.date() <= log_date <= end_date.date():
                            ip = match.group('ip')
                            hour = log_time.strftime('%Y-%m-%d %H:00')  # Hourly time frame

                            # Step 3: Update the count per hour -> IP for the domain
                            domain_stats[domain][hour][ip] += 1
        except Exception as e:
            print(f"    [ERROR] An error occurred while processing logs for domain '{domain}' in file '{log_path}': {e}")

    if processed_logs and (args.verbosedomain or args.verboseall):
        print(f"  [INFO] Finished processing logs for domain '{domain}'.")

# Step 4: Output the results
print("\n[INFO] Hourly request count per domain within the specified date range:")
for domain, hourly_data in domain_stats.items():
    print(f"\nDomain: {domain}")
    for hour, ip_data in sorted(hourly_data.items()):
        print(f"  Hour: {hour}")
        for ip, count in ip_data.items():
            print(f"    IP: {ip} - {count} requests")
