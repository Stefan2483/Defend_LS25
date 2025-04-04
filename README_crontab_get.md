This playbook (crontab_get.yml) performs a comprehensive security audit of all crontab files across your systems, searching for potentially malicious or suspicious commands. Here's what it does:

Scans both user crontabs and system crontab files
Checks for 15+ suspicious patterns commonly associated with malicious activity
Creates detailed reports of all findings
Organizes results by host and user

Key features:

Examines crontabs for all local users on each system
Inspects system crontab locations (/etc/crontab, /etc/cron.d/, etc.)
Detects risky patterns like:

Commands piped directly to bash (curl/wget piping)
Network shells and backdoors
Suspicious permission changes
Base64 encoded commands
Path traversal attempts
Command injection patterns



The playbook creates:

Individual files with each user's crontab content
Copies of all system crontab files
A specific report highlighting suspicious entries
A consolidated summary showing findings across all hosts

To run the playbook:
ansible-playbook crontab_get.yml

Results will be saved to /tmp/security_audit/crontabs/ with separate directories for each host.
You can customize the suspicious_patterns list to add additional patterns relevant to your environment or to adjust the sensitivity of the detection.
This audit can help identify potential security issues like:

Persistence mechanisms installed by attackers
Data exfiltration attempts
Privilege escalation via cron
Unauthorized scheduled tasks