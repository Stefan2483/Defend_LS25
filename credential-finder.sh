#!/bin/bash
# CredentialFinder - An advanced credential hunting script for Linux systems
# Inspired by LinPEAS but with extended functionality

# ANSI color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner function
print_banner() {
    echo -e "${RED}"
    echo "  _____              _            _   _       _   _____ _           _           "
    echo " / ____|            | |          | | (_)     | | |  ___(_)         | |          "
    echo "| |     _ __ ___  __| | ___ _ __ | |_ _  __ _| | | |_   _ _ __   __| | ___ _ __ "
    echo "| |    | '__/ _ \/ _\` |/ _ \ '_ \| __| |/ _\` | | |  _| | | '_ \ / _\` |/ _ \ '__|"
    echo "| |____| | |  __/ (_| |  __/ | | | |_| | (_| | | | |   | | | | | (_| |  __/ |   "
    echo " \_____|_|  \___|\__,_|\___|_| |_|\__|_|\__,_|_| \_|   |_|_| |_|\__,_|\___|_|   "
    echo -e "${NC}"
    echo -e "${BLUE}[*] Advanced Credential Hunting Script for Linux Systems${NC}"
    echo -e "${BLUE}[*] Starting scan at: $(date)${NC}"
    echo ""
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        echo -e "${GREEN}[+] Running as root - All checks will be performed${NC}"
    else
        echo -e "${YELLOW}[!] Not running as root - Some checks may be limited${NC}"
        echo -e "${YELLOW}[!] Run with sudo for complete results${NC}"
    fi
    echo ""
}

# Create output directory
setup_output() {
    OUTPUT_DIR="credential_finder_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="$OUTPUT_DIR/credential_finder.log"
    touch "$LOG_FILE"
    echo -e "${BLUE}[*] Results will be saved to $OUTPUT_DIR${NC}"
    echo ""
}

# Log function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Section divider
section() {
    log "\n${PURPLE}[+] $1 ${NC}\n"
}

# Find files with specific extensions
find_config_files() {
    section "Searching for configuration files"
    
    # Define common configuration file extensions
    CONFIG_EXTENSIONS=(".conf" ".config" ".ini" ".json" ".xml" ".yml" ".yaml" ".properties" ".prop" ".cfg" ".cnf" ".env" ".credentials" ".secret" ".key" ".pem" ".crt" ".cer" ".p12" ".pfx" ".jks" ".keystore" ".csr" ".priv" ".pub")
    
    # Convert array to find pattern
    FIND_PATTERN=$(printf " -o -name \"*%s\"" "${CONFIG_EXTENSIONS[@]}")
    FIND_PATTERN=${FIND_PATTERN:4} # Remove the leading " -o "
    
    # List of directories to search
    SEARCH_DIRS=("/etc" "/opt" "/home" "/var" "/usr/local/etc" "/usr/share" "/srv" "/app" "$HOME")
    
    for dir in "${SEARCH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            log "${CYAN}[*] Searching in $dir${NC}"
            # Find configuration files, excluding certain directories
            find "$dir" -type f \( $FIND_PATTERN \) -not -path "*/node_modules/*" -not -path "*/\.*cache*/*" -not -path "*/\.git/*" 2>/dev/null | tee -a "$OUTPUT_DIR/config_files.txt"
        fi
    done
    
    log "${GREEN}[+] Found $(wc -l < "$OUTPUT_DIR/config_files.txt") configuration files${NC}"
}

# Analyze files for credentials
analyze_files() {
    section "Analyzing files for credentials"
    
    # Create result files
    CREDS_FILE="$OUTPUT_DIR/found_credentials.txt"
    SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
    
    # Credential patterns to search for
    PATTERNS=(
        # General password patterns
        "password[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "pass[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "pwd[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "passwd[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # API keys and tokens
        "api[_-]?key[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "api[_-]?secret[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "api[_-]?token[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "access[_-]?key[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "access[_-]?token[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "auth[_-]?token[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # Database credentials
        "db[_-]?password[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "database[_-]?password[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "db[_-]?user[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "database[_-]?user[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "jdbc[[:space:]]*=[[:space:]]*['\"]jdbc:[^'\"]+['\"]"
        "connection[_-]?string[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # AWS specific
        "aws[_-]?access[_-]?key[_-]?id[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "aws[_-]?secret[_-]?access[_-]?key[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # Azure specific
        "azure[_-]?storage[_-]?account[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "azure[_-]?storage[_-]?key[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # Google Cloud specific
        "google[_-]?api[_-]?key[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "google[_-]?cloud[_-]?key[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # Private keys and certificates
        "BEGIN[[:space:]]PRIVATE[[:space:]]KEY"
        "BEGIN[[:space:]]RSA[[:space:]]PRIVATE[[:space:]]KEY"
        "BEGIN[[:space:]]DSA[[:space:]]PRIVATE[[:space:]]KEY"
        "BEGIN[[:space:]]EC[[:space:]]PRIVATE[[:space:]]KEY"
        "BEGIN[[:space:]]CERTIFICATE"
        
        # OAuth
        "oauth[_-]?token[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "oauth[_-]?secret[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "client[_-]?secret[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # SSH Keys
        "ssh-rsa[[:space:]]"
        "ssh-dss[[:space:]]"
        "ssh-ed25519[[:space:]]"
        
        # JSON patterns
        "\"password\"[[:space:]]*:[[:space:]]*\"[^\"]+\""
        "\"passwd\"[[:space:]]*:[[:space:]]*\"[^\"]+\""
        "\"secret\"[[:space:]]*:[[:space:]]*\"[^\"]+\""
        "\"token\"[[:space:]]*:[[:space:]]*\"[^\"]+\""
        "\"api_key\"[[:space:]]*:[[:space:]]*\"[^\"]+\""
        
        # XML patterns
        "<password>[^<]+</password>"
        "<secret>[^<]+</secret>"
        "<token>[^<]+</token>"
        
        # YAML patterns
        "password:[[:space:]]+['\"]?[^'\"\n]+['\"]?"
        "secret:[[:space:]]+['\"]?[^'\"\n]+['\"]?"
        "token:[[:space:]]+['\"]?[^'\"\n]+['\"]?"
    )
    
    # Process each config file
    total_files=$(wc -l < "$OUTPUT_DIR/config_files.txt")
    current=0
    
    while IFS= read -r file; do
        current=$((current + 1))
        percentage=$((current * 100 / total_files))
        
        # Show progress
        printf "\r${BLUE}[*] Analyzing files: %d%% (%d/%d)${NC}" "$percentage" "$current" "$total_files"
        
        # Skip if file is not readable
        if [ ! -r "$file" ]; then
            continue
        fi
        
        # Skip binary files
        if file "$file" | grep -q "binary"; then
            continue
        fi
        
        # Check each pattern
        for pattern in "${PATTERNS[@]}"; do
            matches=$(grep -E "$pattern" "$file" 2>/dev/null)
            if [ -n "$matches" ]; then
                echo -e "${YELLOW}[!] Found potential credentials in: $file${NC}" >> "$CREDS_FILE"
                echo -e "Pattern: $pattern" >> "$CREDS_FILE"
                echo -e "$matches" >> "$CREDS_FILE"
                echo -e "------------------------------" >> "$CREDS_FILE"
            fi
        done
    done < "$OUTPUT_DIR/config_files.txt"
    
    echo ""
    if [ -f "$CREDS_FILE" ]; then
        creds_count=$(grep -c "Found potential credentials" "$CREDS_FILE")
        log "${GREEN}[+] Found potential credentials in $creds_count files${NC}"
    else
        log "${YELLOW}[!] No credentials found${NC}"
    fi
}

# Check for hardcoded credentials in scripts
check_scripts() {
    section "Checking for credentials in scripts"
    
    SCRIPTS_FILE="$OUTPUT_DIR/script_credentials.txt"
    
    # Find script files
    SCRIPT_EXTENSIONS=(".sh" ".py" ".pl" ".rb" ".js" ".php" ".bash" ".ksh" ".zsh" ".ps1")
    SCRIPT_PATTERN=$(printf " -o -name \"*%s\"" "${SCRIPT_EXTENSIONS[@]}")
    SCRIPT_PATTERN=${SCRIPT_PATTERN:4}
    
    # Search directories
    SEARCH_DIRS=("/etc" "/opt" "/home" "/var" "/usr/local/bin" "/usr/local/sbin" "/usr/bin" "/usr/sbin" "/bin" "/sbin" "/srv" "/app" "$HOME")
    
    for dir in "${SEARCH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            log "${CYAN}[*] Searching for scripts in $dir${NC}"
            find "$dir" -type f \( $SCRIPT_PATTERN \) -not -path "*/node_modules/*" -not -path "*/\.*cache*/*" -not -path "*/\.git/*" 2>/dev/null | tee -a "$OUTPUT_DIR/script_files.txt"
        fi
    done
    
    script_count=$(wc -l < "$OUTPUT_DIR/script_files.txt")
    log "${GREEN}[+] Found $script_count script files${NC}"
    
    # Patterns specific to scripts
    SCRIPT_PATTERNS=(
        # Password variables
        "password[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "passwd[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "pass[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # API keys in scripts
        "api[_-]?key[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "apikey[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # Tokens
        "token[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        "secret[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # Connection strings
        "connection[_-]?string[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
        
        # Hardcoded credentials in curl commands
        "curl[[:space:]]+.*(-u|--user)[[:space:]]+['\"]?[^[:space:]]+:[^[:space:]]+['\"]?"
        
        # Wget with passwords
        "wget[[:space:]]+.*--password=[^[:space:]]+"
        
        # SSH commands with passwords
        "sshpass[[:space:]]+-p[[:space:]]+['\"][^'\"]+['\"]"
    )
    
    # Process each script file
    total_scripts=$script_count
    current=0
    
    while IFS= read -r script; do
        current=$((current + 1))
        percentage=$((current * 100 / total_scripts))
        
        # Show progress
        printf "\r${BLUE}[*] Analyzing scripts: %d%% (%d/%d)${NC}" "$percentage" "$current" "$total_scripts"
        
        # Skip if file is not readable
        if [ ! -r "$script" ]; then
            continue
        fi
        
        # Skip binary files
        if file "$script" | grep -q "binary"; then
            continue
        fi
        
        # Check each pattern
        for pattern in "${SCRIPT_PATTERNS[@]}"; do
            matches=$(grep -E "$pattern" "$script" 2>/dev/null)
            if [ -n "$matches" ]; then
                echo -e "${YELLOW}[!] Found potential credentials in script: $script${NC}" >> "$SCRIPTS_FILE"
                echo -e "Pattern: $pattern" >> "$SCRIPTS_FILE"
                echo -e "$matches" >> "$SCRIPTS_FILE"
                echo -e "------------------------------" >> "$SCRIPTS_FILE"
            fi
        done
    done < "$OUTPUT_DIR/script_files.txt"
    
    echo ""
    if [ -f "$SCRIPTS_FILE" ]; then
        script_creds_count=$(grep -c "Found potential credentials" "$SCRIPTS_FILE")
        log "${GREEN}[+] Found potential credentials in $script_creds_count script files${NC}"
    else
        log "${YELLOW}[!] No credentials found in scripts${NC}"
    fi
}

# Check for interesting files
check_interesting_files() {
    section "Checking for interesting files"
    
    INTERESTING_FILE="$OUTPUT_DIR/interesting_files.txt"
    
    # Define interesting filenames
    INTERESTING_NAMES=(
        # SSH keys
        "id_rsa" "id_dsa" "id_ecdsa" "id_ed25519" "authorized_keys" "known_hosts"
        
        # Web server configs
        "httpd.conf" "apache2.conf" "nginx.conf" "lighttpd.conf"
        
        # App configs
        "wp-config.php" "config.php" "settings.php" "db.php" "database.php"
        "application.properties" "application.yml" "application.yaml"
        "settings.json" "config.json" "appsettings.json"
        
        # DB configs
        "my.cnf" "mysqld.cnf" "postgresql.conf" "pg_hba.conf" "mongod.conf"
        
        # Docker and container
        "docker-compose.yml" "docker-compose.yaml" "Dockerfile" ".dockerignore"
        "kubernetes.yaml" "kubernetes.yml" "k8s.yaml" "k8s.yml"
        
        # Version control
        ".gitignore" ".git-credentials" ".gitconfig"
        ".svn" ".hg"
        
        # Environment files
        ".env" ".env.local" ".env.development" ".env.production" ".env.backup"
        
        # History files
        ".bash_history" ".zsh_history" ".mysql_history" ".psql_history"
        
        # Backup files
        "*.bak" "*.backup" "*.old" "*.orig" "*.save" "*.swp" "*.swo"
        
        # Certificate files
        "*.pem" "*.crt" "*.cer" "*.p12" "*.pfx" "*.key"
        
        # Password files
        "passwd" "shadow" "credentials.xml" "credentials.json" "passwords.txt"
    )
    
    # Convert array to find pattern for names
    NAMES_PATTERN=$(printf " -o -name \"%s\"" "${INTERESTING_NAMES[@]}")
    NAMES_PATTERN=${NAMES_PATTERN:4}
    
    # Search directories
    SEARCH_DIRS=("/etc" "/opt" "/home" "/var" "/usr/local/etc" "/root" "/srv" "/app" "$HOME")
    
    for dir in "${SEARCH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            log "${CYAN}[*] Searching for interesting files in $dir${NC}"
            find "$dir" -type f \( $NAMES_PATTERN \) -not -path "*/node_modules/*" -not -path "*/\.*cache*/*" 2>/dev/null | tee -a "$INTERESTING_FILE"
        fi
    done
    
    # Count results
    if [ -f "$INTERESTING_FILE" ]; then
        interesting_count=$(wc -l < "$INTERESTING_FILE")
        log "${GREEN}[+] Found $interesting_count interesting files${NC}"
    else
        log "${YELLOW}[!] No interesting files found${NC}"
    fi
}

# Check for .NET Web.config files
check_dotnet_configs() {
    section "Checking for .NET configuration files"
    
    DOTNET_FILE="$OUTPUT_DIR/dotnet_configs.txt"
    
    # Find Web.config files
    find / -name "Web.config" -o -name "App.config" -o -name "appsettings.json" 2>/dev/null | tee -a "$DOTNET_FILE"
    
    # Count results
    if [ -f "$DOTNET_FILE" ]; then
        dotnet_count=$(wc -l < "$DOTNET_FILE")
        log "${GREEN}[+] Found $dotnet_count .NET configuration files${NC}"
        
        # Analyze each file
        while IFS= read -r config; do
            if [ -r "$config" ]; then
                log "${CYAN}[*] Analyzing $config${NC}"
                
                # Check for connection strings
                if grep -q "connectionString" "$config" 2>/dev/null; then
                    log "${YELLOW}[!] Found connection strings in $config${NC}"
                    grep -A 2 "connectionString" "$config" 2>/dev/null >> "$OUTPUT_DIR/dotnet_credentials.txt"
                fi
                
                # Check for encrypted sections
                if grep -q "protectedData" "$config" 2>/dev/null; then
                    log "${YELLOW}[!] Found encrypted sections in $config${NC}"
                    grep -A 5 "protectedData" "$config" 2>/dev/null >> "$OUTPUT_DIR/dotnet_credentials.txt"
                fi
                
                # Check for authentication settings
                if grep -q "authentication" "$config" 2>/dev/null; then
                    log "${YELLOW}[!] Found authentication settings in $config${NC}"
                    grep -A 5 "authentication" "$config" 2>/dev/null >> "$OUTPUT_DIR/dotnet_credentials.txt"
                fi
            fi
        done < "$DOTNET_FILE"
    else
        log "${YELLOW}[!] No .NET configuration files found${NC}"
    fi
}

# Check for Java keystores and property files
check_java_files() {
    section "Checking for Java configuration files"
    
    JAVA_FILE="$OUTPUT_DIR/java_configs.txt"
    
    # Find Java property files and keystores
    find / -name "*.properties" -o -name "*.jks" -o -name "*.keystore" -o -name "*.truststore" 2>/dev/null | tee -a "$JAVA_FILE"
    
    # Count results
    if [ -f "$JAVA_FILE" ]; then
        java_count=$(wc -l < "$JAVA_FILE")
        log "${GREEN}[+] Found $java_count Java configuration files${NC}"
        
        # Analyze each file
        while IFS= read -r config; do
            if [ -r "$config" ]; then
                # Check if it's a keystore or properties file
                if [[ "$config" == *.properties ]]; then
                    log "${CYAN}[*] Analyzing Java properties file: $config${NC}"
                    grep -E "password|passwd|secret|key|token" "$config" 2>/dev/null >> "$OUTPUT_DIR/java_credentials.txt"
                else
                    log "${CYAN}[*] Found Java keystore: $config${NC}"
                    echo "$config" >> "$OUTPUT_DIR/java_keystores.txt"
                    
                    # Try to list certificates if keytool is available
                    if command -v keytool &> /dev/null; then
                        log "${CYAN}[*] Listing certificates in keystore (will fail without password)${NC}"
                        keytool -list -v -keystore "$config" -storepass "changeit" 2>/dev/null >> "$OUTPUT_DIR/keystore_contents.txt" || true
                    fi
                fi
            fi
        done < "$JAVA_FILE"
    else
        log "${YELLOW}[!] No Java configuration files found${NC}"
    fi
}

# Check for cloud provider credentials
check_cloud_credentials() {
    section "Checking for cloud provider credentials"
    
    CLOUD_FILE="$OUTPUT_DIR/cloud_credentials.txt"
    
    # AWS credentials
    log "${CYAN}[*] Checking for AWS credentials${NC}"
    find / -name "credentials" -path "*/.aws/*" -o -name "config" -path "*/.aws/*" 2>/dev/null | tee -a "$CLOUD_FILE"
    find / -name "*.pem" -o -name "*.cer" 2>/dev/null | grep -i "aws" | tee -a "$CLOUD_FILE"
    
    # Azure credentials
    log "${CYAN}[*] Checking for Azure credentials${NC}"
    find / -name "azureProfile.json" -o -name "accessTokens.json" 2>/dev/null | tee -a "$CLOUD_FILE"
    
    # Google Cloud credentials
    log "${CYAN}[*] Checking for Google Cloud credentials${NC}"
    find / -name "application_default_credentials.json" -o -name "service-account*.json" -o -name "legacy_credentials" -path "*/.config/gcloud/*" 2>/dev/null | tee -a "$CLOUD_FILE"
    
    # Count results
    if [ -f "$CLOUD_FILE" ]; then
        cloud_count=$(wc -l < "$CLOUD_FILE")
        log "${GREEN}[+] Found $cloud_count cloud credential files${NC}"
        
        # Analyze each file
        while IFS= read -r config; do
            if [ -r "$config" ]; then
                log "${CYAN}[*] Found cloud credential file: $config${NC}"
                echo "Cloud credential file: $config" >> "$OUTPUT_DIR/cloud_creds_details.txt"
                # Don't dump the content as it may contain sensitive information
                file "$config" >> "$OUTPUT_DIR/cloud_creds_details.txt"
                echo "------------------------------" >> "$OUTPUT_DIR/cloud_creds_details.txt"
            fi
        done < "$CLOUD_FILE"
    else
        log "${YELLOW}[!] No cloud credential files found${NC}"
    fi
}

# Check for database configuration files
check_database_configs() {
    section "Checking for database configuration files"
    
    DB_FILE="$OUTPUT_DIR/database_configs.txt"
    
    # MySQL
    log "${CYAN}[*] Checking for MySQL configuration files${NC}"
    find / -name "my.cnf" -o -name "my.ini" -o -name ".my.cnf" 2>/dev/null | tee -a "$DB_FILE"
    
    # PostgreSQL
    log "${CYAN}[*] Checking for PostgreSQL configuration files${NC}"
    find / -name "pg_hba.conf" -o -name "postgresql.conf" -o -name ".pgpass" 2>/dev/null | tee -a "$DB_FILE"
    
    # MongoDB
    log "${CYAN}[*] Checking for MongoDB configuration files${NC}"
    find / -name "mongod.conf" -o -name "mongodb.conf" 2>/dev/null | tee -a "$DB_FILE"
    
    # SQLite
    log "${CYAN}[*] Checking for SQLite databases${NC}"
    find / -name "*.sqlite" -o -name "*.db" -o -name "*.sqlite3" 2>/dev/null | grep -v "^/proc" | head -n 100 | tee -a "$DB_FILE"
    
    # Count results
    if [ -f "$DB_FILE" ]; then
        db_count=$(wc -l < "$DB_FILE")
        log "${GREEN}[+] Found $db_count database configuration files${NC}"
        
        # Analyze each file
        while IFS= read -r config; do
            if [ -r "$config" ]; then
                case "$config" in
                    *my.cnf|*my.ini|*.my.cnf)
                        log "${CYAN}[*] Analyzing MySQL config: $config${NC}"
                        grep -E "user|password|host|socket" "$config" 2>/dev/null >> "$OUTPUT_DIR/db_credentials.txt"
                        ;;
                    *pg_hba.conf)
                        log "${CYAN}[*] Found PostgreSQL host-based authentication file: $config${NC}"
                        grep -v "^#" "$config" | grep -E "md5|password|trust|reject" 2>/dev/null >> "$OUTPUT_DIR/db_credentials.txt"
                        ;;
                    *.pgpass)
                        log "${CYAN}[*] Found PostgreSQL password file: $config${NC}"
                        echo "PostgreSQL password file: $config" >> "$OUTPUT_DIR/db_credentials.txt"
                        cat "$config" 2>/dev/null >> "$OUTPUT_DIR/db_credentials.txt"
                        ;;
                    *mongodb.conf|*mongod.conf)
                        log "${CYAN}[*] Analyzing MongoDB config: $config${NC}"
                        grep -E "auth|keyFile|password|user" "$config" 2>/dev/null >> "$OUTPUT_DIR/db_credentials.txt"
                        ;;
                    *.sqlite|*.db|*.sqlite3)
                        log "${CYAN}[*] Found SQLite database: $config${NC}"
                        echo "SQLite database: $config" >> "$OUTPUT_DIR/db_credentials.txt"
                        ;;
                esac
                echo "------------------------------" >> "$OUTPUT_DIR/db_credentials.txt"
            fi
        done < "$DB_FILE"
    else
        log "${YELLOW}[!] No database configuration files found${NC}"
    fi
}

# Check for container secrets
check_container_secrets() {
    section "Checking for container secrets"
    
    CONTAINER_FILE="$OUTPUT_DIR/container_secrets.txt"
    
    # Docker configuration
    log "${CYAN}[*] Checking for Docker configuration${NC}"
    find / -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "Dockerfile" 2>/dev/null | tee -a "$CONTAINER_FILE"
    
    # Kubernetes secrets
    log "${CYAN}[*] Checking for Kubernetes configuration${NC}"
    find / -name "*.yaml" -o -name "*.yml" 2>/dev/null | xargs grep -l "kind: Secret" 2>/dev/null | tee -a "$CONTAINER_FILE"
    
    # Check Docker environment variables
    if command -v docker &> /dev/null; then
        log "${CYAN}[*] Checking Docker containers for environment variables${NC}"
        docker ps -q 2>/dev/null | xargs -I {} docker inspect {} 2>/dev/null | grep -E "ENV|PASS|SECRET|KEY|TOKEN" >> "$OUTPUT_DIR/docker_envs.txt" || true
    fi
    
    # Count results
    if [ -f "$CONTAINER_FILE" ]; then
        container_count=$(wc -l < "$CONTAINER_FILE")
        log "${GREEN}[+] Found $container_count container configuration files${NC}"
        
        # Analyze each file
        while IFS= read -r config; do
            if [ -r "$config" ]; then
                log "${CYAN}[*] Analyzing container config: $config${NC}"
                echo "Container config file: $config" >> "$OUTPUT_DIR/container_secrets_details.txt"
                
                # Check for environment variables and secrets
                grep -E "ENV|environment:|PASS|pass|SECRET|secret|KEY|key|TOKEN|token" "$config" 2>/dev/null >> "$OUTPUT_DIR/container_secrets_details.txt"
                echo "------------------------------" >> "$OUTPUT_DIR/container_secrets_details.txt"
            fi
        done < "$CONTAINER_FILE"
    else
        log "${YELLOW}[!] No container configuration files found${NC}"
    fi
}

# Generate summary
# Check for history files that might contain credentials
check_history_files() {
    section "Checking for shell history files"
    
    HISTORY_FILE="$OUTPUT_DIR/history_files.txt"
    
    # Shell history files
    log "${CYAN}[*] Checking for shell history files${NC}"
    find / -name ".bash_history" -o -name ".zsh_history" -o -name ".history" -o -name "*_history" 2>/dev/null | tee -a "$HISTORY_FILE"
    
    # Count results
    if [ -f "$HISTORY_FILE" ]; then
        history_count=$(wc -l < "$HISTORY_FILE")
        log "${GREEN}[+] Found $history_count history files${NC}"
        
        # Keywords to look for in history files
        HISTORY_KEYWORDS=("password" "passwd" "pass" "pwd" "secret" "key" "token" "cred" "ssh" "sudo" "su " "mysql -u" "psql -U" "scp" "rsync")
        
        # Create patterns for grep
        HISTORY_PATTERN=$(printf "|%s" "${HISTORY_KEYWORDS[@]}")
        HISTORY_PATTERN=${HISTORY_PATTERN:1}
        
        # Analyze each history file
        while IFS= read -r history; do
            if [ -r "$history" ]; then
                log "${CYAN}[*] Analyzing history file: $history${NC}"
                echo "History file: $history" >> "$OUTPUT_DIR/history_credentials.txt"
                grep -E "$HISTORY_PATTERN" "$history" 2>/dev/null >> "$OUTPUT_DIR/history_credentials.txt"
                echo "------------------------------" >> "$OUTPUT_DIR/history_credentials.txt"
            fi
        done < "$HISTORY_FILE"
    else
        log "${YELLOW}[!] No history files found${NC}"
    fi
}

# Check for temporary files that might contain credentials
check_temp_files() {
    section "Checking for temporary files"
    
    TEMP_FILE="$OUTPUT_DIR/temp_files.txt"
    
    # Temporary directories
    TEMP_DIRS=("/tmp" "/var/tmp" "/dev/shm" "/var/spool/cron" "/var/spool/at")
    
    for dir in "${TEMP_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            log "${CYAN}[*] Checking temporary directory: $dir${NC}"
            find "$dir" -type f -mtime -7 2>/dev/null | tee -a "$TEMP_FILE"
        fi
    done
    
    # Count results
    if [ -f "$TEMP_FILE" ]; then
        temp_count=$(wc -l < "$TEMP_FILE")
        log "${GREEN}[+] Found $temp_count recent temporary files${NC}"
        
        # Sample 50 recent files to check for credentials
        log "${CYAN}[*] Analyzing a sample of temporary files${NC}"
        head -n 50 "$TEMP_FILE" | while read -r temp; do
            if [ -r "$temp" ] && [ -f "$temp" ]; then
                # Check if it's a text file
                if file "$temp" | grep -q "text"; then
                    grep -E "password|passwd|pass|pwd|secret|key|token|cred" "$temp" 2>/dev/null >> "$OUTPUT_DIR/temp_credentials.txt"
                fi
            fi
        done
    else
        log "${YELLOW}[!] No temporary files found${NC}"
    fi
}

generate_summary() {
    section "Generating summary"
    
    SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
    
    echo "CredentialFinder Scan Summary" > "$SUMMARY_FILE"
    echo "=========================" >> "$SUMMARY_FILE"
    echo "Scan completed at: $(date)" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    
    # Add configuration files stats
    if [ -f "$OUTPUT_DIR/config_files.txt" ]; then
        config_count=$(wc -l < "$OUTPUT_DIR/config_files.txt")
        echo "Configuration files found: $config_count" >> "$SUMMARY_FILE"
    else
        echo "Configuration files found: 0" >> "$SUMMARY_FILE"
    fi
    
    # Add credential stats
    if [ -f "$OUTPUT_DIR/found_credentials.txt" ]; then
        cred_count=$(grep -c "Found potential credentials" "$OUTPUT_DIR/found_credentials.txt")
        echo "Files with potential credentials: $cred_count" >> "$SUMMARY_FILE"
    else
        echo "Files with potential credentials: 0" >> "$SUMMARY_FILE"
    fi
    
    # Add script stats
    if [ -f "$OUTPUT_DIR/script_credentials.txt" ]; then
        script_cred_count=$(grep -c "Found potential credentials" "$OUTPUT_DIR/script_credentials.txt")
        echo "Scripts with potential credentials: $script_cred_count" >> "$SUMMARY_FILE"
    else
        echo "Scripts with potential credentials: 0" >> "$SUMMARY_FILE"
    fi
    
    # Add interesting files stats
    if [ -f "$OUTPUT_DIR/interesting_files.txt" ]; then
        interesting_count=$(wc -l < "$OUTPUT_DIR/interesting_files.txt")
        echo "Interesting files found: $interesting_count" >> "$SUMMARY_FILE"
    else
        echo "Interesting files found: 0" >> "$SUMMARY_FILE"
    fi
    
    # Add database stats
    if [ -f "$OUTPUT_DIR/database_configs.txt" ]; then
        db_count=$(wc -l < "$OUTPUT_DIR/database_configs.txt")
        echo "Database configuration files found: $db_count" >> "$SUMMARY_FILE"
    else
        echo "Database configuration files found: 0" >> "$SUMMARY_FILE"
    fi
    
    # Add cloud credentials stats
    if [ -f "$OUTPUT_DIR/cloud_credentials.txt" ]; then
        cloud_count=$(wc -l < "$OUTPUT_DIR/cloud_credentials.txt")
        echo "Cloud credential files found: $cloud_count" >> "$SUMMARY_FILE"
    else
        echo "Cloud credential files found: 0" >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "Most critical findings:" >> "$SUMMARY_FILE"
    
    # List top findings - SSH keys
    find "$OUTPUT_DIR" -type f -exec grep -l "BEGIN.*PRIVATE KEY" {} \; 2>/dev/null | sort | uniq | head -n 5 >> "$SUMMARY_FILE"
    
    # List files with most credential patterns
    if [ -f "$OUTPUT_DIR/found_credentials.txt" ]; then
        echo "" >> "$SUMMARY_FILE"
        echo "Files with most credential patterns:" >> "$SUMMARY_FILE"
        grep "Found potential credentials" "$OUTPUT_DIR/found_credentials.txt" | sort | uniq -c | sort -nr | head -n 5 >> "$SUMMARY_FILE"
    fi
    
    log "${GREEN}[+] Summary generated in $SUMMARY_FILE${NC}"
}

# Main function
main() {
    print_banner
    check_root
    setup_output
    
    # Core checks
    find_config_files
    analyze_files
    check_scripts
    check_interesting_files
    
    # Extended checks
    check_dotnet_configs
    check_java_files
    check_cloud_credentials
    check_database_configs
    check_container_secrets
    check_history_files
    check_temp_files
    
    # Generate report
    generate_summary
    
    # Final output
    section "Scan completed"
    log "${GREEN}[+] CredentialFinder scan completed${NC}"
    log "${GREEN}[+] Results saved to $OUTPUT_DIR${NC}"
    log "${GREEN}[+] Summary: $SUMMARY_FILE${NC}"
    log "${YELLOW}[!] Remember to secure any sensitive information found${NC}"
}

# Run the script
main
