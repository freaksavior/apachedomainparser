Parse Apache access logs to analyze request counts per hour for each domain.

Updated the options to parse apache by domain, by all domains, by date range. Added options to increase verbosity of what files were loaded and what users. 

Options now include 
--verbosedomain -  Show verbose output for domain checks

--verboselog - Show verbose output for log file checks')

--verboseall Show all verbose outputs from above

--domain Specify a domain to search for, or leave empty to search all domains

--daterange Specify a date range in format dd/mm/yyyy-dd/mm/yyyy (default is last 24 hours)')
 
