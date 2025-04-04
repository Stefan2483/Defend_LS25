This playbook (sgid_get.yml) will scan your systems for all files with the SGID bit set, which is similar to the SUID bit but grants the group privileges of the file owner rather than the user privileges. Here's what it does:

Runs with elevated privileges on all target hosts
Creates a local output directory for organizing results
Searches for all files with the SGID bit set (-perm -2000), excluding noisy paths like /proc, /sys, etc.
Saves the list of SGID files to a host-specific file with timestamp
Counts and displays the number of SGID files found on each host
Creates a consolidated CSV report with host information and SGID file counts
Collects and saves detailed information about each SGID file (permissions, ownership, etc.)

The playbook improves on a simple command line search by:

Organizing results by host and timestamp
Excluding file systems that would generate noise or errors
Creating both summary and detailed reports
Adding system distribution information for analysis
Collecting detailed file attributes for security assessment

You can run this playbook with:

ansible-playbook sgid_get.yml

All results will be stored in /tmp/security_audit/ by default. You can modify the output_dir variable if you want to store the data elsewhere.
SGID files, like SUID files, can pose security risks if unnecessary privileges are granted, so this information is valuable for security audits.