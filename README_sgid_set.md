The playbook:

Maintains a whitelist of legitimate SGID binaries that should keep their permissions
Creates backups before making any changes
Only removes the SGID bit from files not in the whitelist
Generates detailed reports of all changes made

Key features:

Safely identifies and modifies only non-standard SGID files
Creates comprehensive backups before any modifications
Skips system paths that would cause noise or errors
Provides detailed before/after comparisons
Generates a summary report with details of all actions taken

To use this playbook:

Review and customize the sgid_whitelist variable for your environment
Run with ansible-playbook sgid_set.yml
Check the reports in /root/sgid_permissions_backup/ on each host