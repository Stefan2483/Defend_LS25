Here's what the playbook does:

Identifies all files with SUID bits set on your systems
Compares against a whitelist of legitimate SUID binaries
Creates detailed backups of current permissions before making any changes
Removes the SUID bit from any files not in the whitelist
Generates a comprehensive report of all actions taken

Key security features:

Only modifies custom/non-standard SUID files
Maintains a whitelist of legitimate SUID binaries
Creates full backups before any changes
Generates before/after comparisons
Excludes system paths that would cause noise (/proc, /sys, etc.)
Includes detailed reporting for audit purposes

To use this playbook:

Review and customize the suid_whitelist variable to match your environment
Run it with ansible-playbook suid_set.yml
Check the reports in /root/suid_permissions_backup/ on each host

The playbook is designed to be safe, with complete documentation of what was changed and the ability to restore permissions if needed.