#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use DateTime;
use File::Basename;

# Function to display help message
sub usage {
    print "Usage: parse_access_logs.pl --daterange <dd/mm/yyyy-dd/mm/yyyy> --domain <domain_name> --verbosedomain --verboselog --verboseall\n";
    print "Description: Parses Apache access logs to analyze request counts per hour for each domain.\n";
    exit;
}

# Command line arguments
my $verbose_domain = 0;
my $verbose_log = 0;
my $verbose_all = 0;
my $domain = '';
my $date_range = '';
GetOptions(
    'verbosedomain' => \$verbose_domain,
    'verboselog'    => \$verbose_log,
    'verboseall'    => \$verbose_all,
    'domain=s'      => \$domain,
    'daterange=s'   => \$date_range,
) or usage();

# Paths to the necessary files
my $user_domain_file = '/etc/userdatadomains';
my $log_directory = '/home/%s/logs/';
my $log_format = qr/(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d{3}) (\S+) "(.*?)" "(.*?)"/;

# Hash to hold domain -> hourly -> IP -> request counts
my %domain_stats;

# Determine the date range
my ($start_date, $end_date);
if ($date_range) {
    my ($start_str, $end_str) = split(/-/, $date_range);
    $start_date = DateTime->from_epoch(epoch => DateTime::Format::Strptime->new(pattern => '%d/%m/%Y')->parse_datetime($start_str)->epoch);
    $end_date = DateTime->from_epoch(epoch => DateTime::Format::Strptime->new(pattern => '%d/%m/%Y')->parse_datetime($end_str)->epoch);
} else {
    # Default to the last 24 hours
    $end_date = DateTime->now;
    $start_date = $end_date->clone->subtract(days => 1);
}

# Step 1: Parse the domain list
my %domains;
open my $domain_fh, '<', $user_domain_file or die "Cannot open $user_domain_file: $!";
while (my $line = <$domain_fh>) {
    chomp $line;
    my @parts = split(/==/, $line);
    if (scalar @parts >= 2) {
        my $domain_name = (split(/:/, $parts[0]))[0];  # Extracts domain before ":"
        my $user = (split(/:/, $parts[0]))[1];         # Extracts username after ":"
        $user =~ s/^\s+|\s+$//g;                         # Trim whitespace
        $domains{$domain_name} = $user;
    }
}
close $domain_fh;

# Step 2: Parse logs for each domain/user
foreach my $domain_name (keys %domains) {
    my $user = $domains{$domain_name};
    if ($domain && $domain ne $domain_name) {
        next;  # Skip domains that don't match the specified one
    }

    print "\n[INFO] Checking logs for domain '$domain_name' (User: '$user')\n" if $verbose_domain || $verbose_all;

    # Construct possible log file names
    my $log_path_non_ssl = sprintf($log_directory, $user) . $domain_name;
    my $log_path_ssl = sprintf($log_directory, $user) . "${domain_name}-ssl_log";  # Updated suffix

    # Try to open each log file (non-SSL and SSL versions)
    my $processed_logs = 0;
    foreach my $log_path ($log_path_non_ssl, $log_path_ssl) {
        print "  [INFO] Checking for log file: $log_path\n" if $verbose_log || $verbose_all;

        if (!-e $log_path) {
            print "    [WARNING] Log file '$log_path' not found, skipping.\n";
            next;
        }

        print "    [INFO] Processing log file '$log_path'...\n" if $verbose_log || $verbose_all;
        $processed_logs = 1;

        open my $log_fh, '<', $log_path or die "Cannot open '$log_path': $!";
        while (my $line = <$log_fh>) {
            if ($line =~ $log_format) {
                my $ip = $1;
                my $time_str = $2;
                my $log_time = DateTime::Format::Strptime->new(pattern => '%d/%b/%Y:%H:%M:%S')->parse_datetime($time_str);
                my $log_date = $log_time->to_date;

                if ($log_date >= $start_date->to_date && $log_date <= $end_date->to_date) {
                    my $hour = $log_time->strftime('%Y-%m-%d %H:00');  # Hourly time frame
                    $domain_stats{$domain_name}{$hour}{$ip}++;
                }
            }
        }
        close $log_fh;

        print "  [INFO] Finished processing logs for domain '$domain_name'.\n" if $processed_logs && ($verbose_domain || $verbose_all);
    }
}

# Step 4: Output the results
print "\n[INFO] Hourly request count per domain within the specified date range:\n";
foreach my $domain_name (keys %domain_stats) {
    print "\nDomain: $domain_name\n";
    foreach my $hour (sort keys %{ $domain_stats{$domain_name} }) {
        print "  Hour: $hour\n";
        foreach my $ip (keys %{ $domain_stats{$domain_name}{$hour} }) {
            my $count = $domain_stats{$domain_name}{$hour}{$ip};
            print "    IP: $ip - $count requests\n";
        }
    }
    print "[INFO] Loaded domain '$domain_name' for user '$domains{$domain_name}'.\n" if $verbose_domain || $verbose_all;
}
