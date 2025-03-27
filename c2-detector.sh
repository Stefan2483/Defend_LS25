#!/bin/bash

# C2 Beacon Detector Script
# This script helps identify potential Command & Control beacons/implants on Linux systems
# It analyzes network connections, processes, and system behavior for suspicious activities
# Run with root privileges for best results

# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored section headers
print_header() {
    echo -e "\n${BLUE}==== $1 ====${NC}"
}

# Function to print potential threats
print_alert() {
    echo -e "${RED}[!] $1${NC}"
}

# Function to print information
print_info() {
    echo -e "${YELLOW}[*] $1${NC}"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script should be run as root for best results${NC}"
   echo -e "${YELLOW}[*] Some checks will be limited without root privileges${NC}"
   read -p "Continue anyway? (y/n) " -n 1 -r
   echo
   if [[ ! $REPLY =~ ^[Yy]$ ]]; then
       exit 1
   fi
fi

# Create a timestamp for the output file
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="./c2_scan_results_$TIMESTAMP"
OUTPUT_FILE="$OUTPUT_DIR/c2_scan_results.txt"

# Create output directory
mkdir -p "$OUTPUT_DIR"
touch "$OUTPUT_FILE"

# Function to log output to file
log() {
    echo "$1" | tee -a "$OUTPUT_FILE"
}

log "C2 Beacon Detector Scan Results - $(date)"
log "============================================="

# Check for common C2 beacon patterns in network connections
print_header "Checking for suspicious network connections"

# Look for beaconing patterns (regular interval connections)
log "$(print_info "Analyzing network connections for beaconing patterns...")"
netstat -ant | grep ESTABLISHED > "$OUTPUT_DIR/established_connections.txt"

# Check for connections to high ports
HIGH_PORT_CONNECTIONS=$(netstat -ant | grep ESTABLISHED | grep -E ':(4[0-9]{4}|5[0-9]{4}|6[0-9]{4})')
if [[ ! -z "$HIGH_PORT_CONNECTIONS" ]]; then
    log "$(print_alert "Found connections to uncommon high ports:")"
    log "$HIGH_PORT_CONNECTIONS"
else
    log "$(print_success "No suspicious high port connections found")"
fi

# Check for connections with low data transfer (potential beaconing)
log "$(print_info "Checking for connections with minimal data transfer (potential beaconing)...")"
ss -tn | grep ESTAB > "$OUTPUT_DIR/ss_connections.txt"

# Check for unusual DNS queries
print_header "Checking for suspicious DNS activity"
if command -v tcpdump &> /dev/null; then
    log "$(print_info "Capturing DNS queries for 10 seconds...")"
    timeout 10 tcpdump -i any -nn -s0 port 53 > "$OUTPUT_DIR/dns_queries.txt" 2>/dev/null
    UNUSUAL_DNS=$(grep -E '(\.top|\.xyz|\.info|\.bit|\.cc|\.ws)' "$OUTPUT_DIR/dns_queries.txt" | sort | uniq)
    if [[ ! -z "$UNUSUAL_DNS" ]]; then
        log "$(print_alert "Found queries to unusual TLDs:")"
        log "$UNUSUAL_DNS"
    else
        log "$(print_success "No suspicious DNS queries detected")"
    fi
else
    log "$(print_info "tcpdump not available, skipping DNS capture")"
fi

# Check for unusual processes
print_header "Checking for suspicious processes"

# Look for processes with no parent or unusual parents
log "$(print_info "Checking for processes with unusual parent relationships...")"
ps -eo pid,ppid,user,cmd --forest > "$OUTPUT_DIR/process_tree.txt"
ORPHAN_PROCESSES=$(ps -eo pid,ppid,user,cmd | awk '$2 == 1 && $3 != "root" {print}')
if [[ ! -z "$ORPHAN_PROCESSES" ]]; then
    log "$(print_alert "Found potential orphaned processes:")"
    log "$ORPHAN_PROCESSES"
else
    log "$(print_success "No unusual orphaned processes found")"
fi

# Check for hidden processes
log "$(print_info "Checking for hidden processes...")"
HIDDEN_PROCS=$(ps aux | grep -v grep | grep ' ?' | grep -v '\[')
if [[ ! -z "$HIDDEN_PROCS" ]]; then
    log "$(print_alert "Potentially hidden processes detected:")"
    log "$HIDDEN_PROCS"
else
    log "$(print_success "No hidden processes detected")"
fi

# Check for processes with high CPU usage despite low activity
log "$(print_info "Checking for processes with unusual resource usage...")"
top -b -n 1 > "$OUTPUT_DIR/top_output.txt"
HIGH_CPU_LOW_MEM=$(top -b -n 1 | grep -E '^[ ]*[0-9]+' | awk '$9 > 10 && $10 < 1 {print}')
if [[ ! -z "$HIGH_CPU_LOW_MEM" ]]; then
    log "$(print_alert "Processes with high CPU but low memory usage (potential cryptominers or encoders):")"
    log "$HIGH_CPU_LOW_MEM"
fi

# Check for suspicious files
print_header "Checking for suspicious files"

# Look for recently modified executables
log "$(print_info "Checking for recently modified executables...")"
RECENT_EXECS=$(find /usr/bin /usr/sbin /bin /sbin -type f -executable -mtime -7 2>/dev/null)
if [[ ! -z "$RECENT_EXECS" ]]; then
    log "$(print_alert "Recently modified system executables (last 7 days):")"
    log "$RECENT_EXECS"
fi

# Look for executables in /tmp, /var/tmp
log "$(print_info "Checking for executables in temporary directories...")"
TMP_EXECS=$(find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null)
if [[ ! -z "$TMP_EXECS" ]]; then
    log "$(print_alert "Executable files found in temporary directories:")"
    log "$TMP_EXECS"
else
    log "$(print_success "No executables found in temporary directories")"
fi

# Check for hidden directories
log "$(print_info "Checking for hidden directories in user homes...")"
HIDDEN_DIRS=$(find /home -type d -name ".*" -not -name ".." -not -name "." -not -name ".config" -not -name ".cache" -not -name ".local" 2>/dev/null)
if [[ ! -z "$HIDDEN_DIRS" ]]; then
    log "$(print_alert "Unusual hidden directories found:")"
    log "$HIDDEN_DIRS"
fi

# Check for persistence mechanisms
print_header "Checking for persistence mechanisms"

# Check cron jobs
log "$(print_info "Checking cron jobs...")"
mkdir -p "$OUTPUT_DIR/cron"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null > "$OUTPUT_DIR/cron/$user.cron"
done
cat /etc/crontab > "$OUTPUT_DIR/cron/system.cron"
find /etc/cron.* -type f -exec cp {} "$OUTPUT_DIR/cron/" \; 2>/dev/null

# Check startup services
log "$(print_info "Checking startup services...")"
systemctl list-unit-files --type=service > "$OUTPUT_DIR/systemd_services.txt"
UNUSUAL_SERVICES=$(systemctl list-unit-files --type=service | grep -i "enabled" | grep -v -E '(ssh|network|system|dbus|user|login)')
if [[ ! -z "$UNUSUAL_SERVICES" ]]; then
    log "$(print_alert "Potentially unusual enabled services:")"
    log "$UNUSUAL_SERVICES"
fi

# Check for unusual SUID/SGID binaries
log "$(print_info "Checking for unusual SUID/SGID binaries...")"
UNUSUAL_SUID=$(find / -type f -perm -4000 -o -perm -2000 2>/dev/null | grep -v -E '(/bin/|/sbin/|/usr/bin/|/usr/sbin/)')
if [[ ! -z "$UNUSUAL_SUID" ]]; then
    log "$(print_alert "Unusual SUID/SGID binaries found outside standard directories:")"
    log "$UNUSUAL_SUID"
fi

# Check for known C2 indicators
print_header "Checking for known C2 indicators"

# Check for known C2 domains/IPs (simplified - in practice you'd use a threat intel feed)
log "$(print_info "Checking connections against known C2 indicators...")"
HOSTS_FILE=$(cat /etc/hosts)
NETSTAT_OUTPUT=$(netstat -ant)

# Define basic indicators (would be expanded with actual threat intel)
C2_INDICATORS=(
    "pastebin.com"
    "github.io"
    "githubusercontent.com"
    "gist.github.com"
    "raw.githubusercontent.com"
    "discord.com/api"
    "dropbox.com/api"
    "tinyurl.com"
    "bit.ly"
)

for indicator in "${C2_INDICATORS[@]}"; do
    if echo "$HOSTS_FILE" | grep -q "$indicator" || echo "$NETSTAT_OUTPUT" | grep -q "$indicator"; then
        log "$(print_alert "Potential C2 indicator found: $indicator")"
    fi
done

# Check for encoded/obfuscated commands
print_header "Checking for encoded commands"

# Look for base64 encoded commands in process list
log "$(print_info "Checking for base64 encoded commands...")"
BASE64_CMDS=$(ps -eo command | grep -E '(base64|b64decode|bash.*echo.*\|)')
if [[ ! -z "$BASE64_CMDS" ]]; then
    log "$(print_alert "Potential encoded commands detected:")"
    log "$BASE64_CMDS"
fi

# Check for common endpoints in web logs
print_header "Checking for suspicious web access patterns"

# Common web logs locations
WEB_LOGS=(
    "/var/log/apache2/access.log"
    "/var/log/nginx/access.log"
    "/var/log/httpd/access_log"
)

for log_file in "${WEB_LOGS[@]}"; do
    if [[ -f "$log_file" ]]; then
        log "$(print_info "Analyzing web log: $log_file")"
        # Look for patterns indicating C2 activity
        SUSPICIOUS_PATTERNS=$(grep -E '(/admin|/shell|/cmd|/c99|/r57|/upload|/backdoor)' "$log_file" 2>/dev/null)
        if [[ ! -z "$SUSPICIOUS_PATTERNS" ]]; then
            log "$(print_alert "Suspicious web access patterns detected:")"
            log "$SUSPICIOUS_PATTERNS"
        else
            log "$(print_success "No suspicious patterns in $log_file")"
        fi
    fi
done

# Check for periodic beaconing using iptables logs if available
print_header "Checking for consistent beaconing patterns"

if [[ -f "/var/log/iptables.log" ]]; then
    log "$(print_info "Analyzing iptables logs for beaconing patterns...")"
    awk '{print $1, $5}' /var/log/iptables.log | sort | uniq -c | sort -nr > "$OUTPUT_DIR/connection_frequency.txt"
    HIGH_FREQUENCY=$(head -20 "$OUTPUT_DIR/connection_frequency.txt")
    log "$(print_info "Top 20 most frequent connections (potential beaconing):")"
    log "$HIGH_FREQUENCY"
fi

# Check for memory only implants
print_header "Checking for memory-only implants"

if command -v volatility &> /dev/null; then
    log "$(print_info "Volatility found, can perform memory analysis (not automated in this script)")"
    log "$(print_info "For memory analysis, capture memory with: 'sudo dd if=/dev/mem of=memory.dump bs=1MB'")"
    log "$(print_info "Then analyze with: 'volatility -f memory.dump --profile=<profile> psscan'")"
else
    log "$(print_info "Volatility not found, skipping memory analysis")"
    log "$(print_info "Consider installing Volatility for deeper memory forensics")"
fi

# Summary of findings
print_header "Scan Summary"
log "Scan completed at $(date)"
log "Results saved to $OUTPUT_FILE"
log "All detailed data saved to $OUTPUT_DIR"

echo -e "\n${GREEN}Scan completed!${NC}"
echo -e "${YELLOW}This is a basic detection script and may generate false positives${NC}"
echo -e "${YELLOW}Manual investigation is recommended for any suspicious findings${NC}"
echo -e "${GREEN}Results saved to: $OUTPUT_FILE${NC}"
