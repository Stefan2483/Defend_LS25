This Ansible playbook scans all your systems for SUID files (files with the Set-UID bit set, which can be a security concern). Here's what it does:

Runs with elevated privileges on all hosts
Creates a local output directory for storing results
Finds all SUID files using the find command, excluding file systems that would create noise (/proc, /sys, /run, /dev)
Saves the results to a host-specific file with timestamp
Counts the number of SUID files found and displays a summary
Creates a consolidated CSV report with host information and SUID file counts

The playbook improves on a direct command-line search by:

Excluding noisy paths that often cause errors
Organizing results by host
Creating both detailed and summary reports
Adding timestamp information for tracking changes over time
Including OS distribution information for correlation

You can run this playbook with:
ansible-playbook check-suid-files.yml

The results will be stored in /tmp/security_audit/ by default, but you can modify the output_dir variable to change this location.