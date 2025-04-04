#!/bin/bash
# FastCredFinder - A high-performance credential hunting script for Linux
# Optimized for speed, showing only actual credential findings in real-time

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${RED}"
    echo "  _____          _  _____              _  _____ _           _           "
    echo " |  ___|        | |/  __ \\            | ||  ___(_)         | |          "
    echo " | |_ __ _ ___  | || /  \\/ ___  _ __  | || |_   _ _ __   __| | ___ _ __ "
    echo " |  _/ _\` / __| | || |    / _ \\| '__| | ||  _| | | '_ \\ / _\` |/ _ \\ '__|"
    echo " | || (_| \\__ \\ | || \\__/\\ (_) | |    | || |   | | | | | (_| |  __/ |   "
    echo " \\_| \\__,_|___/ |_| \\____/\\___/|_|    |_|\\_|   |_|_| |_|\\__,_|\\___|_|   "
    echo -e "${NC}"
    echo -e "${BLUE}[*] Fast Credential Hunting Script for Linux Systems${NC}"
    echo -e "${BLUE}[*] Starting scan at: $(date)${NC}"
    echo ""
}

# Print status message with timestamp
log() {
    echo -e "[$(date +%H:%M:%S)] $1"
}

# Print finding with colored output
print_finding() {
    echo -e "${YELLOW}[FOUND]${NC} $1 ${GREEN}→${NC} $2"
}

# Create temporary directory for parallel processing
setup_temp() {
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    
    if [ "$(id -u)" -eq 0 ]; then
        log "${GREEN}[+] Running as root - Complete system scan${NC}"
    else
        log "${YELLOW}[!] Not running as root - Limited scan scope${NC}"
    fi
}

# Define credential patterns
CREDENTIAL_PATTERNS=(
    "password[[:space:]]*=[[:space:]]*[^[:space:];]+"
    "passwd[[:space:]]*=[[:space:]]*[^[:space:];]+"
    "secret[[:space:]]*=[[:space:]]*[^[:space:];]+"
    "key[[:space:]]*=[[:space:]]*[^[:space:];]+"
    "token[[:space:]]*=[[:space:]]*[^[:space:];]+"
    "api[_-]?key[[:space:]]*=[[:space:]]*[^[:space:];]+"
    "access[_-]?token[[:space:]]*=[[:space:]]*[^[:space:];]+"
    "connection[_-]?string[[:space:]]*="
    "aws[_-]?access[_-]?key[_-]?id"
    "aws[_-]?secret[_-]?access[_-]?key"
    "BEGIN[[:space:]]PRIVATE[[:space:]]KEY"
    "BEGIN[[:space:]]RSA[[:space:]]PRIVATE[[:space:]]KEY"
    "\"password\"[[:space:]]*:[[:space:]]*\"[^\"]+\""
    "\"api_key\"[[:space:]]*:[[:space:]]*\"[^\"]+\""
    "\"token\"[[:space:]]*:[[:space:]]*\"[^\"]+\""
)

# Fast scan directories for config files and check for credentials in real-time
fast_scan_directory() {
    local dir=$1
    
    if [ ! -d "$dir" ]; then
        return
    fi
    
    log "${BLUE}[*] Scanning $dir${NC}"
    
    # Find config files and process them
    find "$dir" -type f \( -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.json" \
        -o -name "*.xml" -o -name "*.yml" -o -name "*.yaml" -o -name "*.properties" -o -name "*.env" \
        -o -name "*.pem" -o -name "*.key" -o -name "*.crt" -o -name "*.p12" -o -name "*.auth" \
        -o -name "*.cfg" -o -name "*.cnf" -o -name "*.credentials" -o -name "*.secret" \) \
        -not -path "*/node_modules/*" -not -path "*/\.*cache/*" -not -path "*/\.git/*" \
        -not -path "*/proc/*" -not -path "*/sys/*" \
        -size -1M 2>/dev/null | \
    while read -r file; do
        for pattern in "${CREDENTIAL_PATTERNS[@]}"; do
            if grep -q -E "$pattern" "$file" 2>/dev/null; then
                echo "$file" >> "$TEMP_DIR/findings.txt"
                break
            fi
        done
    done
}

# Scan shell scripts separately
fast_scan_scripts() {
    log "${BLUE}[*] Scanning for credentials in scripts${NC}"
    
    # Find script files with common extensions
    find / -type f \( -name "*.sh" -o -name "*.py" -o -name "*.rb" -o -name "*.pl" -o -name "*.js" -o -name "*.php" \) \
        -not -path "*/node_modules/*" -not -path "*/\.*cache/*" -not -path "*/\.git/*" \
        -not -path "*/proc/*" -not -path "*/sys/*" \
        -size -1M 2>/dev/null | \
    while read -r file; do
        for pattern in "${CREDENTIAL_PATTERNS[@]}"; do
            if grep -q -E "$pattern" "$file" 2>/dev/null; then
                echo "$file" >> "$TEMP_DIR/script_findings.txt"
                break
            fi
        done
    done
}

# Fast scan for SSH keys and history files
fast_scan_ssh_and_history() {
    log "${BLUE}[*] Scanning for SSH keys and history files${NC}"
    
    # Find SSH keys and history files
    find / -type f \( -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" \
        -o -name ".bash_history" -o -name ".zsh_history" \) \
        -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null >> "$TEMP_DIR/ssh_keys.txt"
        
    # Find all authorized_keys files
    find / -name "authorized_keys" 2>/dev/null >> "$TEMP_DIR/ssh_keys.txt"
    
    # Find potential password stores
    find / -type f -path "*/\.password-store/*" 2>/dev/null >> "$TEMP_DIR/password_stores.txt"
}

# Fast scan AWS, Azure, GCP credential files
fast_scan_cloud_credentials() {
    log "${BLUE}[*] Scanning for cloud credentials${NC}"
    
    # Find AWS, Azure, and GCP credential files
    find / -type f \( -path "*/.aws/credentials" -o -path "*/.azure/credentials" \
        -o -name "credentials.json" -o -name "service-account*.json" \) \
        -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null >> "$TEMP_DIR/cloud_credentials.txt"
}

# Fast scan database configurations
fast_scan_database_configs() {
    log "${BLUE}[*] Scanning for database configurations${NC}"
    
    # Find database config files
    find / -type f \( -name "my.cnf" -o -name ".my.cnf" -o -name "pg_hba.conf" \
        -o -name ".pgpass" -o -name "mongod.conf" \) \
        -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null >> "$TEMP_DIR/db_configs.txt"
}

# Process and display findings in real-time
process_findings() {
    # Process config files findings
    if [ -f "$TEMP_DIR/findings.txt" ]; then
        echo -e "\n${GREEN}=== Configuration Files with Credentials ===${NC}"
        while IFS= read -r file; do
            print_finding "Config" "$file"
        done < "$TEMP_DIR/findings.txt"
    fi
    
    # Process script findings
    if [ -f "$TEMP_DIR/script_findings.txt" ]; then
        echo -e "\n${GREEN}=== Scripts with Credentials ===${NC}"
        while IFS= read -r file; do
            print_finding "Script" "$file"
        done < "$TEMP_DIR/script_findings.txt"
    fi
    
    # Process SSH keys
    if [ -f "$TEMP_DIR/ssh_keys.txt" ]; then
        echo -e "\n${GREEN}=== SSH Keys and History Files ===${NC}"
        while IFS= read -r file; do
            if [[ "$file" == *"history"* ]]; then
                # For history files, check if they contain password-related commands
                if grep -q -E "password|passwd|secret|token|key|curl.*-u" "$file" 2>/dev/null; then
                    print_finding "History" "$file"
                fi
            else
                print_finding "SSH Key" "$file"
            fi
        done < "$TEMP_DIR/ssh_keys.txt"
    fi
    
    # Process cloud credentials
    if [ -f "$TEMP_DIR/cloud_credentials.txt" ]; then
        echo -e "\n${GREEN}=== Cloud Credential Files ===${NC}"
        while IFS= read -r file; do
            print_finding "Cloud" "$file"
        done < "$TEMP_DIR/cloud_credentials.txt"
    fi
    
    # Process database configs
    if [ -f "$TEMP_DIR/db_configs.txt" ]; then
        echo -e "\n${GREEN}=== Database Configuration Files ===${NC}"
        while IFS= read -r file; do
            print_finding "Database" "$file"
        done < "$TEMP_DIR/db_configs.txt"
    fi
    
    # Process password stores
    if [ -f "$TEMP_DIR/password_stores.txt" ]; then
        echo -e "\n${GREEN}=== Password Stores ===${NC}"
        while IFS= read -r file; do
            print_finding "Password Store" "$file"
        done < "$TEMP_DIR/password_stores.txt"
    fi
}

# Check specific high-value locations immediately
check_high_value_locations() {
    log "${BLUE}[*] Checking high-value locations${NC}"
    
    # List of high-value locations to check immediately
    HIGH_VALUE_DIRS=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/ssh"
        "/home/*/.ssh"
        "/root/.ssh"
        "/var/www"
        "/var/backups"
    )
    
    for location in "${HIGH_VALUE_DIRS[@]}"; do
        if [ -e "$location" ]; then
            if [ -d "$location" ]; then
                find "$location" -type f -not -path "*/\.*" 2>/dev/null | while read -r file; do
                    for pattern in "${CREDENTIAL_PATTERNS[@]}"; do
                        if grep -q -E "$pattern" "$file" 2>/dev/null; then
                            echo "$file" >> "$TEMP_DIR/critical_findings.txt"
                            break
                        fi
                    done
                done
            elif [ -f "$location" ]; then
                for pattern in "${CREDENTIAL_PATTERNS[@]}"; do
                    if grep -q -E "$pattern" "$location" 2>/dev/null; then
                        echo "$location" >> "$TEMP_DIR/critical_findings.txt"
                        break
                    fi
                done
            fi
        fi
    done
    
    # Process critical findings immediately
    if [ -f "$TEMP_DIR/critical_findings.txt" ]; then
        echo -e "\n${RED}=== CRITICAL FINDINGS ===${NC}"
        while IFS= read -r file; do
            print_finding "CRITICAL" "$file"
        done < "$TEMP_DIR/critical_findings.txt"
    fi
}

# Run scan for a specific type and print findings immediately
scan_and_show() {
    local type=$1
    local dir=$2
    local output_file="$TEMP_DIR/${type}_findings.txt"
    
    case "$type" in
        "config")
            fast_scan_directory "$dir"
            ;;
        "script")
            fast_scan_scripts
            ;;
        "ssh")
            fast_scan_ssh_and_history
            ;;
        "cloud")
            fast_scan_cloud_credentials
            ;;
        "db")
            fast_scan_database_configs
            ;;
    esac
    
    # Show results immediately if file exists
    if [ -f "$output_file" ]; then
        echo -e "\n${GREEN}=== $type Findings ===${NC}"
        while IFS= read -r file; do
            print_finding "$type" "$file"
        done < "$output_file"
    fi
}

# Main function
main() {
    print_banner
    setup_temp
    
    # Start with high-value locations for immediate results
    check_high_value_locations
    
    # Priority directories to scan first
    log "${BLUE}[*] Scanning priority directories...${NC}"
    for dir in "/etc" "$HOME" "/var/www" "/opt"; do
        if [ -d "$dir" ]; then
            fast_scan_directory "$dir"
        fi
    done
    
    # Process and display initial findings
    process_findings
    
    # Ask if user wants to continue with full system scan
    echo ""
    log "${YELLOW}[?] Continue with full system scan? (y/n)${NC}"
    read -r choice
    
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        # Secondary directories
        for dir in "/usr/local" "/srv" "/var"; do
            if [ -d "$dir" ]; then
                fast_scan_directory "$dir"
                # Show findings after each directory
                process_findings
            fi
        done
        
        # Specialized scans
        scan_and_show "script" "/"
        scan_and_show "ssh" "/"
        scan_and_show "cloud" "/"
        scan_and_show "db" "/"
    fi
    
    # Final summary
    total_findings=$(cat "$TEMP_DIR"/*.txt 2>/dev/null | wc -l)
    log "${GREEN}[+] Scan complete! Found $total_findings potential credential files${NC}"
}

# Run the script
main