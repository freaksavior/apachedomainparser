#!/usr/bin/python3
import re
from collections import defaultdict
from datetime import datetime, timedelta
import os
import argparse
import logging
import gzip

# Constants
USER_DOMAIN_FILE = '/etc/userdatadomains'
LOG_DIRECTORY = '/home/{user}/logs/'
LOG_FORMAT = r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]+)" "(?P<user_agent>[^"]+)"'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_args():
    parser = argparse.ArgumentParser(description='Parse Apache access logs to analyze request counts per hour for each domain.')
    parser.add_argument('--verbosedomain', action='store_true', help='Show verbose output for domain checks')
    parser.add_argument('--verboselog', action='store_true', help='Show verbose output for log file checks')
    parser.add_argument('--verboseall', action='store_true', help='Show all verbose outputs')
    parser.add_argument('--domain', type=str, help='Specify a domain to search for, or leave empty to search all domains')
    parser.add_argument('--daterange', type=str, help='Specify a date range in format dd/mm/yyyy-dd/mm/yyyy (default is last 24 hours)')
    return parser.parse_args()

def determine_date_range(daterange):
    if daterange:
        try:
            start_str, end_str = daterange.split('-')
            start_date = datetime.strptime(start_str, '%d/%m/%Y')
            end_date = datetime.strptime(end_str, '%d/%m/%Y')
        except ValueError:
            logging.error("Invalid date range format. Please use dd/mm/yyyy-dd/mm/yyyy.")
            exit(1)
    else:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=1)
    return start_date, end_date

def parse_domain_list(file_path):
    domains = {}
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split("==")
            if len(parts) >= 2:
                domain_name, user = parts[0].split(":")
                domains[domain_name.strip()] = user.strip()
    return domains

def process_log_file(log_path, start_date, end_date, domain_stats, verbose):
    if verbose:
        logging.info(f"Processing log file '{log_path}'...")
    try:
        with open(log_path, 'r') as log_file:
            for line in log_file:
                match = re.match(LOG_FORMAT, line)
                if match:
                    time_str = match.group('time').split()[0]
                    log_time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S')
                    log_date = log_time.date()
                    if start_date.date() <= log_date <= end_date.date():
                        ip = match.group('ip')
                        hour = log_time.strftime('%Y-%m-%d %H:00')
                        domain_stats[hour][ip] += 1
    except Exception as e:
        logging.error(f"An error occurred while processing log file '{log_path}': {e}")

def process_logs(domain, user, start_date, end_date, log_paths, verbose):
    domain_stats = defaultdict(lambda: defaultdict(int))
    for log_path in log_paths:
        if verbose:
            logging.info(f"Checking for log file: {log_path}")
        if not os.path.isfile(log_path):
            logging.warning(f"Log file '{log_path}' not found, skipping.")
            continue
        process_log_file(log_path, start_date, end_date, domain_stats, verbose)
    return domain_stats

def process_archived_logs(domain, user, start_date, end_date, log_directory, verbose):
    domain_stats = defaultdict(lambda: defaultdict(int))
    current_month = datetime.now().strftime('%b-%Y')
    archive_patterns = [
        f"{domain}-ssl_log-{current_month}.gz",
        f"{domain}-{current_month}.gz"
    ]
    for archive_pattern in archive_patterns:
        archive_path = os.path.join(log_directory.format(user=user), archive_pattern)
        if verbose:
            logging.info(f"Checking for archived log file: {archive_path}")
        if not os.path.isfile(archive_path):
            logging.warning(f"Archived log file '{archive_path}' not found, skipping.")
            continue
        if verbose:
            logging.info(f"Processing archived log file '{archive_path}'...")
        try:
            with gzip.open(archive_path, 'rt') as log_file:
                for line in log_file:
                    match = re.match(LOG_FORMAT, line)
                    if match:
                        time_str = match.group('time').split()[0]
                        log_time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S')
                        log_date = log_time.date()
                        if start_date.date() <= log_date <= end_date.date():
                            ip = match.group('ip')
                            hour = log_time.strftime('%Y-%m-%d %H:00')
                            domain_stats[hour][ip] += 1
        except Exception as e:
            logging.error(f"An error occurred while processing archived log file '{archive_path}': {e}")
    return domain_stats

def main():
    args = parse_args()
    start_date, end_date = determine_date_range(args.daterange)
    domains = parse_domain_list(USER_DOMAIN_FILE)
    all_stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    for domain, user in domains.items():
        if args.domain and args.domain != domain:
            continue
        if args.verbosedomain or args.verboseall:
            logging.info(f"Checking logs for domain '{domain}' (User: '{user}')")
        log_paths = [
            os.path.join(LOG_DIRECTORY.format(user=user), f"{domain}"),
            os.path.join(LOG_DIRECTORY.format(user=user), f"{domain}-ssl_log")
        ]
        domain_stats = process_logs(domain, user, start_date, end_date, log_paths, args.verboselog or args.verboseall)
        archived_stats = process_archived_logs(domain, user, start_date, end_date, LOG_DIRECTORY, args.verboselog or args.verboseall)
        for hour, ip_data in archived_stats.items():
            for ip, count in ip_data.items():
                domain_stats[hour][ip] += count
        for hour, ip_data in domain_stats.items():
            for ip, count in ip_data.items():
                all_stats[domain][hour][ip] += count
        if args.verbosedomain or args.verboseall:
            logging.info(f"Finished processing logs for domain '{domain}'.")

    logging.info("\nHourly request count per domain within the specified date range:")
    for domain, hourly_data in all_stats.items():
        print(f"\n\033[1mDomain: {domain}\033[0m")  # Highlight domain
        for hour, ip_data in sorted(hourly_data.items()):
            print(f"  Hour: {hour}")
            for ip, count in ip_data.items():
                print(f"    IP: {ip} - {count} requests")

if __name__ == "__main__":
    main()
