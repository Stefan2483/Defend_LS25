#!/bin/sh

# id: crontab_get
# author: Stefan Olaru
# tags: linux debian-based redhat-based freebsd-based

set -eu

# Create output directory
OUTPUT_DIR="/tmp/crontab_audit"
mkdir -p "$OUTPUT_DIR"
echo "Created output directory: $OUTPUT_DIR"

# Get timestamp
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
echo "Starting crontab security audit at $TIMESTAMP"

# Get list of all users with UID >= 1000 (normal users)
echo "Getting list of users..."
USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
echo "Found $(echo "$USERS" | wc -w) regular users"

# Get user crontabs
echo "Checking user crontabs..."
for user in $USERS; do
    echo "Checking crontab for user: $user"
    echo "=== Crontab for $user ===" > "$OUTPUT_DIR/user_${user}_crontab.txt"
    crontab -l -u $user 2>/dev/null >> "$OUTPUT_DIR/user_${user}_crontab.txt" || 
        echo "No crontab for $user" >> "$OUTPUT_DIR/user_${user}_crontab.txt"
done

# Get system crontab files
echo "Checking system crontab files..."
echo "=== /etc/crontab ===" > "$OUTPUT_DIR/system_crontabs.txt"
cat /etc/crontab 2>/dev/null >> "$OUTPUT_DIR/system_crontabs.txt" || 
    echo "File not found" >> "$OUTPUT_DIR/system_crontabs.txt"

# Check cron directories
for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    echo "Checking $crondir..."
    echo "" >> "$OUTPUT_DIR/system_crontabs.txt"
    echo "=== $crondir ===" >> "$OUTPUT_DIR/system_crontabs.txt"
    
    if [ -d "$crondir" ]; then
        # Only process if files exist in the directory
        if [ "$(ls -A $crondir 2>/dev/null)" ]; then
            for cronfile in $crondir/*; do
                if [ -f "$cronfile" ]; then
                    echo "  Processing $cronfile"
                    echo "" >> "$OUTPUT_DIR/system_crontabs.txt"
                    echo "--- $cronfile ---" >> "$OUTPUT_DIR/system_crontabs.txt"
                    cat "$cronfile" 2>/dev/null >> "$OUTPUT_DIR/system_crontabs.txt" || 
                        echo "Cannot read file" >> "$OUTPUT_DIR/system_crontabs.txt"
                fi
            done
        else
            echo "  No files in directory"
            echo "No files in directory" >> "$OUTPUT_DIR/system_crontabs.txt"
        fi
    else
        echo "  Directory not found"
        echo "Directory not found" >> "$OUTPUT_DIR/system_crontabs.txt"
    fi
done

# Check for suspicious patterns - using POSIX compliant approach without arrays
echo "Scanning for suspicious patterns..."
> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 1: Curl piped to bash
pattern="curl.*\\|.*bash"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 2: Wget piped to bash
pattern="wget.*\\|.*bash"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 3: Netcat with execute flag
pattern="nc -e"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 4: Interactive bash shell
pattern="bash -i"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 5: Insecure permissions
pattern="chmod 777"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 6: Bash network redirection
pattern="/dev/tcp/"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 7: Base64 decoded executions
pattern="base64.*decode"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 8: Inline Python execution
pattern="python -c"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Pattern 9: Inline Perl execution
pattern="perl -e"
echo "Checking for pattern: $pattern"
echo "=== Pattern: $pattern ===" >> "$OUTPUT_DIR/suspicious_entries.txt"
grep -E "$pattern" "$OUTPUT_DIR"/user_*_crontab.txt "$OUTPUT_DIR/system_crontabs.txt" >> "$OUTPUT_DIR/suspicious_entries.txt" 2>/dev/null || 
    echo "No matches found" >> "$OUTPUT_DIR/suspicious_entries.txt"
echo "" >> "$OUTPUT_DIR/suspicious_entries.txt"

# Create summary report
TOTAL_MATCHES=$(grep -v "No matches found\|=== Pattern:" "$OUTPUT_DIR/suspicious_entries.txt" | grep -v "^$" | wc -l)
echo "=== Crontab Security Audit Summary ===" > "$OUTPUT_DIR/summary_report.txt"
echo "Date: $(date)" >> "$OUTPUT_DIR/summary_report.txt"
echo "Host: $(hostname)" >> "$OUTPUT_DIR/summary_report.txt"
echo "Users checked: $(echo "$USERS" | wc -w)" >> "$OUTPUT_DIR/summary_report.txt"
echo "Suspicious entries found: $TOTAL_MATCHES" >> "$OUTPUT_DIR/summary_report.txt"
echo "" >> "$OUTPUT_DIR/summary_report.txt"
echo "Check $OUTPUT_DIR/suspicious_entries.txt for details" >> "$OUTPUT_DIR/summary_report.txt"

# Display summary
echo ""
echo "===== Audit Complete ====="
echo "Users checked: $(echo "$USERS" | wc -w)"
echo "Suspicious entries found: $TOTAL_MATCHES"
echo "Results saved to: $OUTPUT_DIR"
echo "Check $OUTPUT_DIR/suspicious_entries.txt for suspicious entries"
echo "Check $OUTPUT_DIR/summary_report.txt for the summary"

# Exit with status code 1 if suspicious entries are found
if [ "$TOTAL_MATCHES" -gt 0 ]; then
    echo "WARNING: Suspicious crontab entries detected!" >&2
    exit 1
fi

exit 0
