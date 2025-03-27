#!/bin/bash

# Network C2 Beacon Detector
# Advanced tool for detecting Command & Control beacons across multiple protocols
# Version 1.0.0
# Run with root privileges

# Display help/usage if requested
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    cat << EOF
Network C2 Beacon Detector
--------------------------

DESCRIPTION:
  This script captures network traffic and analyzes it for signs of C2 (Command & Control)
  beaconing activities. It can detect regular communication patterns across multiple
  protocols that might indicate the presence of implants or backdoors.

USAGE:
  sudo ./network_beacon_detector.sh [CAPTURE_TIME] [INTERFACES]
    
  CAPTURE_TIME  : Duration in seconds to capture (default: 60)
  INTERFACES    : Specific interfaces to monitor (default: all)

EXAMPLES:
  sudo ./network_beacon_detector.sh               # 60 second capture on all interfaces
  sudo ./network_beacon_detector.sh 300           # 5 minute capture on all interfaces
  sudo ./network_beacon_detector.sh 120 eth0      # 2 minute capture on eth0 only
  sudo ./network_beacon_detector.sh 60 "eth0 wlan0" # 1 minute capture on eth0 and wlan0

FEATURES:
  - Detects HTTP, HTTPS, DNS, ICMP, TCP, UDP, and SMB beaconing
  - Identifies processes responsible for suspicious network connections
  - Checks for memory-resident implants and unusual memory permissions
  - Analyzes for data tunneling over various protocols
  - Predicts beacon intervals and next beacon times
  - Generates comprehensive HTML report with visualizations

REQUIREMENTS:
  - Required: tcpdump, lsof, tshark, netstat, grep, awk
  - Optional: gnuplot, graphviz, volatility, strace, yara

NOTES:
  - Must be run as root to capture network traffic
  - False positives are possible with legitimate software
  - Consider longer capture times for more accurate detection
  - Results are saved in timestamped output directory
EOF
    exit 0
fi

# Version information
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="network_beacon_detector.sh"

# Trap for cleanup on Ctrl+C or script exit
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    # Kill traffic generator if running
    if [ ! -z "$traffic_pid" ] && ps -p $traffic_pid > /dev/null 2>&1; then
        kill $traffic_pid 2>/dev/null
    fi
    
    # Kill all tcpdump processes
    for pid in $tcpdump_pid $http_pid $dns_pid $icmp_pid $smb_pid $uncommon_pid; do
        if [ ! -z "$pid" ] && ps -p $pid > /dev/null 2>&1; then
            kill -9 $pid 2>/dev/null
        fi
    done
    
    echo -e "${YELLOW}Capture terminated. Results saved to $OUTPUT_DIR${NC}"
    exit 1
}

# Set up trap for SIGINT (Ctrl+C) and EXIT
trap cleanup SIGINT
trap cleanup EXIT

# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

# Show script header
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}                   NETWORK BEACON DETECTOR                   ${NC}"
echo -e "${BLUE}              C2 BEACON & COVERT CHANNEL ANALYZER           ${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "${YELLOW}This script captures and analyzes network traffic for potential C2${NC}"
echo -e "${YELLOW}beacons across multiple protocols and techniques including:${NC}"
echo -e "${YELLOW} - HTTP/HTTPS beacons and suspicious patterns${NC}"
echo -e "${YELLOW} - DNS tunneling, long queries and suspicious responses${NC}"
echo -e "${YELLOW} - ICMP covert channels and persistent tunnels${NC}"
echo -e "${YELLOW} - TCP/UDP on common C2 ports (Cobalt Strike, Metasploit, etc.)${NC}"
echo -e "${YELLOW} - SMB command abuse and lateral movement${NC}"
echo -e "${YELLOW} - Process identification and memory analysis${NC}"
echo -e "${BLUE}============================================================${NC}"
echo

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script requires root privileges to capture network traffic${NC}"
   exit 1
fi

# Check for required tools
for tool in tcpdump lsof tshark netstat grep awk; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}[!] Required tool not found: $tool${NC}"
        case $tool in
            tcpdump)
                echo -e "${YELLOW}[*] Install with: apt-get install tcpdump${NC}"
                ;;
            lsof)
                echo -e "${YELLOW}[*] Install with: apt-get install lsof${NC}"
                ;;
            tshark)
                echo -e "${YELLOW}[*] Install with: apt-get install wireshark-common tshark${NC}"
                ;;
            netstat)
                echo -e "${YELLOW}[*] Install with: apt-get install net-tools${NC}"
                ;;
        esac
        exit 1
    fi
done

# Check for optional tools
for tool in strace volatility yara; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${YELLOW}[*] Optional tool not found: $tool${NC}"
        case $tool in
            strace)
                echo -e "${YELLOW}[*] Install with: apt-get install strace${NC}"
                ;;
            volatility)
                echo -e "${YELLOW}[*] Install with: pip install volatility${NC}"
                ;;
            yara)
                echo -e "${YELLOW}[*] Install with: apt-get install yara${NC}"
                ;;
        esac
    else
        echo -e "${GREEN}[+] Optional tool available: $tool${NC}"
    fi
done

# Create a timestamp for the output directory
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="./network_beacon_scan_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/pcaps"
mkdir -p "$OUTPUT_DIR/logs"
mkdir -p "$OUTPUT_DIR/analysis"

CAPTURE_FILE="$OUTPUT_DIR/pcaps/capture.pcap"
RESULTS_FILE="$OUTPUT_DIR/beacon_results.txt"
touch "$RESULTS_FILE"

# Function to log output to file and screen
log() {
    echo -e "$1" | tee -a "$RESULTS_FILE"
}

# Optional parameters
CAPTURE_TIME=${1:-60}  # Default 60 seconds, can be overridden from command line
EXTRA_INTERFACES=${2:-""}  # Additional interfaces to monitor

log "Network C2 Beacon Detection - $(date)"
log "=========================================="
log "Capture time: $CAPTURE_TIME seconds"
log "Output directory: $OUTPUT_DIR"

# Set the CAPTURE_TIME variable explicitly to an integer
# This should fix any issues with variable interpretation
CAPTURE_TIME=$(($CAPTURE_TIME + 0))

# Get system information
HOSTNAME=$(hostname)
IP_ADDRS=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | tr '\n' ' ')
KERNEL=$(uname -r)

log "Host: $HOSTNAME"
log "IP Addresses: $IP_ADDRS"
log "Kernel: $KERNEL"
log "=========================================="

# Function to detect beaconing patterns
detect_beacons() {
    local proto=$1
    local file=$2
    local interval_threshold=5  # Consider connections with regular intervals of 5 seconds or less as suspicious

    print_header "Analyzing $proto beaconing patterns"
    log "$(print_info "Processing $proto connections for beaconing patterns...")"
    
    # Extract timestamps, source IPs, destination IPs/domains
    if [ "$proto" == "DNS" ]; then
        tshark -r "$file" -Y "dns" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name 2>/dev/null > "$OUTPUT_DIR/${proto}_queries.txt"
        
        # Additional check for DNS TXT records (often used for data exfiltration)
        tshark -r "$file" -Y "dns.txt" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.txt 2>/dev/null > "$OUTPUT_DIR/${proto}_txt_queries.txt"
        
        # Check for unusually long DNS queries (potential DNS tunneling)
        tshark -r "$file" -Y "dns.qry.name.len > 50" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name 2>/dev/null > "$OUTPUT_DIR/${proto}_long_queries.txt"
        
        if [ -s "$OUTPUT_DIR/${proto}_txt_queries.txt" ]; then
            log "$(print_alert "Potential DNS TXT record abuse detected:")"
            head -n 10 "$OUTPUT_DIR/${proto}_txt_queries.txt" | while read -r line; do
                log "  $line"
            done
        fi
        
        if [ -s "$OUTPUT_DIR/${proto}_long_queries.txt" ]; then
            log "$(print_alert "Potential DNS tunneling detected (long queries):")"
            head -n 10 "$OUTPUT_DIR/${proto}_long_queries.txt" | while read -r line; do
                log "  $line"
            done
        fi
    elif [ "$proto" == "HTTP" ]; then
        tshark -r "$file" -Y "http" -T fields -e frame.time_epoch -e ip.src -e http.host -e http.request.uri 2>/dev/null > "$OUTPUT_DIR/${proto}_requests.txt"
        
        # Look for suspicious HTTP headers, paths, and beacons
        tshark -r "$file" -Y "http.request.method == \"GET\" or http.request.method == \"POST\"" -T fields -e frame.time_epoch -e ip.src -e http.host -e http.request.method -e http.request.uri -e http.user_agent 2>/dev/null > "$OUTPUT_DIR/${proto}_detailed.txt"
        
        # Check for suspicious user agents
        grep -i -E "(python|curl|wget|powershell|winhttp|perl|ruby|go-http|shellshock)" "$OUTPUT_DIR/${proto}_detailed.txt" > "$OUTPUT_DIR/${proto}_suspicious_agents.txt"
        
        if [ -s "$OUTPUT_DIR/${proto}_suspicious_agents.txt" ]; then
            log "$(print_alert "Suspicious HTTP user agents detected:")"
            head -n 10 "$OUTPUT_DIR/${proto}_suspicious_agents.txt" | while read -r line; do
                log "  $line"
            done
        fi
    elif [ "$proto" == "HTTPS" ]; then
        tshark -r "$file" -Y "tcp.port==443" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null > "$OUTPUT_DIR/${proto}_requests.txt"
        
        # Look for self-signed certificates or unusual TLS patterns
        tshark -r "$file" -Y "tls.handshake.certificate" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e x509sat.uTF8String 2>/dev/null > "$OUTPUT_DIR/${proto}_certificates.txt"
    elif [ "$proto" == "ICMP" ]; then
        tshark -r "$file" -Y "icmp" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e icmp.type -e icmp.code -e data.len 2>/dev/null > "$OUTPUT_DIR/${proto}_packets.txt"
        
        # Look for ICMP packets with unusual data sizes (potential ICMP tunneling)
        grep -v " 0 " "$OUTPUT_DIR/${proto}_packets.txt" | grep -v " 56 " | grep -v " 64 " > "$OUTPUT_DIR/${proto}_unusual.txt"
        
        if [ -s "$OUTPUT_DIR/${proto}_unusual.txt" ]; then
            log "$(print_alert "Potential ICMP tunneling detected (unusual data sizes):")"
            head -n 10 "$OUTPUT_DIR/${proto}_unusual.txt" | while read -r line; do
                log "  $line"
            done
        fi
    elif [ "$proto" == "TCP_UNCOMMON" ]; then
        # Check for unusual TCP ports often used in C2 communication
        tshark -r "$file" -Y "tcp.port in {4444 8080 8443 1080 1443 9001 9002 2222 6666 31337}" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport 2>/dev/null > "$OUTPUT_DIR/${proto}_connections.txt"
        
        # Look for persistent TCP connections (potential reverse shells)
        tshark -r "$file" -Y "tcp.flags.syn==1 and tcp.port in {4444 8080 8443 1080 1443 9001 9002 2222 6666 31337}" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport 2>/dev/null > "$OUTPUT_DIR/${proto}_shells.txt"
    elif [ "$proto" == "UDP_UNCOMMON" ]; then
        # Check for unusual UDP ports often used in C2 communication
        tshark -r "$file" -Y "udp.port in {53 137 138 5353 5355 6667}" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e data.len 2>/dev/null > "$OUTPUT_DIR/${proto}_connections.txt"
        
        # Look for UDP packets with unusual data sizes
        grep -v " 0$" "$OUTPUT_DIR/${proto}_connections.txt" | awk '$6 > 100' > "$OUTPUT_DIR/${proto}_large_packets.txt"
        
        if [ -s "$OUTPUT_DIR/${proto}_large_packets.txt" ]; then
            log "$(print_alert "Potential UDP tunneling detected (large packet sizes):")"
            head -n 10 "$OUTPUT_DIR/${proto}_large_packets.txt" | while read -r line; do
                log "  $line"
            done
        fi
    elif [ "$proto" == "SMB" ]; then
        # Check for SMB traffic (increasingly used for C2)
        tshark -r "$file" -Y "smb or smb2" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e smb.cmd -e smb2.cmd 2>/dev/null > "$OUTPUT_DIR/${proto}_commands.txt"
    fi

    # Analyze for regular intervals
    if [ -f "$OUTPUT_DIR/${proto}_queries.txt" ] || [ -f "$OUTPUT_DIR/${proto}_requests.txt" ]; then
        local file_to_analyze="$OUTPUT_DIR/${proto}_requests.txt"
        [ "$proto" == "DNS" ] && file_to_analyze="$OUTPUT_DIR/${proto}_queries.txt"
        
        # Sort by source IP and destination
        sort -k2,3 "$file_to_analyze" > "$OUTPUT_DIR/${proto}_sorted.txt"
        
        # Process each unique source-destination pair to find regular intervals
        awk '{
            key = $2 " " $3;
            if (key in timestamps) {
                timestamps[key] = timestamps[key] " " $1;
                count[key]++;
            } else {
                timestamps[key] = $1;
                count[key] = 1;
            }
        } END {
            for (key in timestamps) {
                if (count[key] >= 3) {  # Need at least 3 points to detect a pattern
                    print key " " timestamps[key];
                }
            }
        }' "$OUTPUT_DIR/${proto}_sorted.txt" > "$OUTPUT_DIR/${proto}_potential_beacons.txt"
        
        # Calculate intervals and detect regular patterns
        while read -r line; do
            src_dst=$(echo "$line" | cut -d' ' -f1-2)
            times_str=$(echo "$line" | cut -d' ' -f3-)
            
            # Convert space-separated string to array
            times=()
            for t in $times_str; do
                times+=($t)
            done
            
            # Calculate intervals
            intervals=()
            for ((i=1; i<${#times[@]}; i++)); do
                interval=$(echo "${times[$i]} - ${times[$i-1]}" | bc)
                intervals+=($interval)
            done
            
            # Check if intervals are regular (similar to each other)
            if [ ${#intervals[@]} -ge 2 ]; then
                # Calculate mean and standard deviation
                sum=0
                for interval in "${intervals[@]}"; do
                    sum=$(echo "$sum + $interval" | bc)
                done
                mean=$(echo "scale=2; $sum / ${#intervals[@]}" | bc)
                
                # Calculate variance
                sum_squared_diff=0
                for interval in "${intervals[@]}"; do
                    diff=$(echo "$interval - $mean" | bc)
                    squared_diff=$(echo "$diff * $diff" | bc)
                    sum_squared_diff=$(echo "$sum_squared_diff + $squared_diff" | bc)
                done
                variance=$(echo "scale=2; $sum_squared_diff / ${#intervals[@]}" | bc)
                std_dev=$(echo "scale=2; sqrt($variance)" | bc)
                
                # Calculate coefficient of variation (CV)
                cv=$(echo "scale=2; $std_dev / $mean" | bc)
                
                # If CV is small (intervals are regular) and mean is reasonable for beaconing
                if (( $(echo "$cv < 0.25" | bc -l) )) && (( $(echo "$mean < 60" | bc -l) )); then
                    destination=$(echo "$src_dst" | cut -d' ' -f2)
                    source=$(echo "$src_dst" | cut -d' ' -f1)
                    
                    log "$(print_alert "Potential $proto beacon detected:")"
                    log "  Source IP: $source"
                    log "  Destination: $destination"
                    log "  Average interval: $mean seconds"
                    log "  Regularity (lower is more regular): $cv"
                    log "  Number of observed connections: ${#times[@]}"
                    
                    # Find the process responsible
                    if [ "$proto" == "DNS" ]; then
                        port_filter="port 53"
                    elif [ "$proto" == "HTTP" ]; then
                        port_filter="port 80"
                    elif [ "$proto" == "HTTPS" ]; then
                        port_filter="port 443"
                    fi
                    
                    # Save for process identification
                    echo "$source|$destination|$port_filter" >> "$OUTPUT_DIR/beacon_candidates.txt"
                fi
            fi
        done < "$OUTPUT_DIR/${proto}_potential_beacons.txt"
    else
        log "$(print_info "No $proto traffic detected during capture period")"
    fi
}

# Function to identify processes responsible for beaconing
identify_beacon_processes() {
    print_header "Identifying processes responsible for beaconing"
    
    if [ ! -f "$OUTPUT_DIR/beacon_candidates.txt" ]; then
        log "$(print_info "No beaconing candidates to investigate")"
        return
    fi
    
    log "$(print_info "Identifying processes associated with detected beacons...")"
    
    # Get current network connections with process information for all protocols
    netstat -tnp > "$OUTPUT_DIR/netstat_tcp_output.txt"
    netstat -unp > "$OUTPUT_DIR/netstat_udp_output.txt"
    lsof -i > "$OUTPUT_DIR/lsof_output.txt"
    
    # For ICMP, check processes with raw socket access
    lsof -i icmp > "$OUTPUT_DIR/lsof_icmp_output.txt" 2>/dev/null
    
    # Identify potential memory-resident implants
    print_header "Checking for memory-resident implants"
    log "$(print_info "Analyzing running processes for suspicious memory characteristics...")"
    
    # Find processes with executable memory mappings outside normal regions
    for pid in $(ps -e -o pid=); do
        if [ -d "/proc/$pid" ]; then
            # Look for writable+executable memory regions
            grep -E "rwx|w-x" /proc/$pid/maps 2>/dev/null | grep -v -E '(/usr/lib|/lib|/bin|\.so|vdso|vsyscall)' > "$OUTPUT_DIR/analysis/pid_${pid}_suspicious_maps.txt"
            
            if [ -s "$OUTPUT_DIR/analysis/pid_${pid}_suspicious_maps.txt" ]; then
                process_name=$(ps -p "$pid" -o comm=)
                user=$(ps -p "$pid" -o user=)
                log "$(print_alert "Process $pid ($process_name) owned by $user has suspicious memory permissions:")"
                head -3 "$OUTPUT_DIR/analysis/pid_${pid}_suspicious_maps.txt" | while read -r line; do
                    log "  $line"
                done
                
                # Check if this process has network connections
                if grep -q "$pid/" "$OUTPUT_DIR/lsof_output.txt"; then
                    log "$(print_alert "This process also has active network connections!")"
                    grep "$pid/" "$OUTPUT_DIR/lsof_output.txt" | head -3 | while read -r line; do
                        log "  $line"
                    done
                    
                    # Add to beacon candidates for deeper investigation
                    ip_addr=$(grep "$pid/" "$OUTPUT_DIR/lsof_output.txt" | grep -E 'TCP|UDP' | awk '{print $9}' | cut -d':' -f1 | head -1)
                    echo "memory|$ip_addr|$pid" >> "$OUTPUT_DIR/beacon_candidates.txt"
                fi
            fi
        fi
    done
    
    # Look for hidden network services (listening on unusual ports but not showing in netstat)
    log "$(print_info "Checking for hidden network services...")"
    
    # Get all processes with open network sockets
    lsof -i -n -P | grep -E 'LISTEN|UDP' > "$OUTPUT_DIR/analysis/all_listening_sockets.txt"
    
    # Compare with netstat output
    for line in $(cat "$OUTPUT_DIR/analysis/all_listening_sockets.txt"); do
        proc_pid=$(echo "$line" | awk '{print $2}')
        proc_port=$(echo "$line" | awk '{print $9}' | cut -d':' -f2)
        
        # Check if this port appears in netstat
        if ! grep -q ":$proc_port " "$OUTPUT_DIR/listening_tcp_ports.txt" && ! grep -q ":$proc_port " "$OUTPUT_DIR/listening_udp_ports.txt"; then
            proc_name=$(ps -p "$proc_pid" -o comm=)
            log "$(print_alert "Hidden network service detected! Process $proc_pid ($proc_name) listening on port $proc_port")"
            log "  $(ps -p "$proc_pid" -o pid,ppid,user,cmd --no-headers)"
            
            # Add to beacon candidates
            echo "hidden|localhost:$proc_port|$proc_pid" >> "$OUTPUT_DIR/beacon_candidates.txt"
        fi
    done
    
    # Look for processes communicating with unusual destinations or ports
    log "$(print_info "Checking for unusual network destinations...")"
    
    # Get established connections
    netstat -tunapc > "$OUTPUT_DIR/analysis/all_connections.txt"
    
    # Define suspicious destinations/ports
    suspicious_ports=(4444 8080 8443 1080 1443 9001 9002 2222 6666 31337 1337 1234 12345 54321)
    
    # Check for connections to suspicious ports
    for port in "${suspicious_ports[@]}"; do
        connections=$(grep -E ":$port\s" "$OUTPUT_DIR/analysis/all_connections.txt" | grep ESTABLISHED)
        if [ ! -z "$connections" ]; then
            log "$(print_alert "Connection to suspicious port $port detected:")"
            echo "$connections" | while read -r conn; do
                log "  $conn"
                conn_pid=$(echo "$conn" | awk '{print $7}' | cut -d'/' -f1)
                if [ ! -z "$conn_pid" ] && [ "$conn_pid" != "-" ]; then
                    log "  Process info: $(ps -p "$conn_pid" -o pid,ppid,user,cmd --no-headers)"
                    # Add to beacon candidates
                    remote_ip=$(echo "$conn" | awk '{print $5}' | cut -d':' -f1)
                    echo "suspicious|$remote_ip:$port|$conn_pid" >> "$OUTPUT_DIR/beacon_candidates.txt"
                fi
            done
        fi
    done
    
    # Get a list of all listening ports
    netstat -tlnp > "$OUTPUT_DIR/listening_tcp_ports.txt"
    netstat -ulnp > "$OUTPUT_DIR/listening_udp_ports.txt"
    
    # Look for suspicious processes with network access
    log "$(print_info "Checking for suspicious process attributes...")"
    
    # Processes running from temp locations
    suspicious_locations=$(lsof -i | grep -E '(/tmp/|/dev/shm/|/var/tmp/)' | awk '{print $2}' | sort | uniq)
    if [ ! -z "$suspicious_locations" ]; then
        log "$(print_alert "Processes with network access running from suspicious locations:")"
        for pid in $suspicious_locations; do
            cmd=$(ps -p "$pid" -o cmd=)
            user=$(ps -p "$pid" -o user=)
            log "  PID: $pid, User: $user, CMD: $cmd"
        done
    fi
    
    # Processes with high port counts
    high_connection_procs=$(netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -5)
    if [ ! -z "$high_connection_procs" ]; then
        log "$(print_info "Top 5 IPs with highest connection counts:")"
        echo "$high_connection_procs" | while read -r line; do
            log "  $line"
        done
    fi
    
    while IFS="|" read -r src_ip dst target port_filter; do
        log "$(print_info "Looking for processes connecting to $dst...")"
        
        # Try to find with netstat based on protocol
        if [ "$port_filter" == "port 53" ]; then
            process_info=$(grep -E "$src_ip.*$dst|$dst.*$src_ip" "$OUTPUT_DIR/netstat_udp_output.txt" | grep -oE '[0-9]+/[^ ]+')
        elif [ "$port_filter" == "port 80" ] || [ "$port_filter" == "port 443" ] || [ "$port_filter" == "any" ]; then
            process_info=$(grep -E "$src_ip.*$dst|$dst.*$src_ip" "$OUTPUT_DIR/netstat_tcp_output.txt" | grep -oE '[0-9]+/[^ ]+')
            
            # Also check UDP for "any" protocol
            if [ "$port_filter" == "any" ] && [ -z "$process_info" ]; then
                process_info=$(grep -E "$src_ip.*$dst|$dst.*$src_ip" "$OUTPUT_DIR/netstat_udp_output.txt" | grep -oE '[0-9]+/[^ ]+')
            fi
        fi
        
        if [ -z "$process_info" ]; then
            # Try with lsof
            process_info=$(grep -E "$src_ip.*$dst|$dst.*$src_ip" "$OUTPUT_DIR/lsof_output.txt" | awk '{print $2 " " $1}' | sort | uniq)
        fi
        
        if [ -n "$process_info" ]; then
            log "$(print_alert "Process responsible for beacon to $dst:")"
            log "  $process_info"
            
            # Get more process details
            for pid in $(echo "$process_info" | grep -oE '[0-9]+' | sort | uniq); do
                if [ -d "/proc/$pid" ]; then
                    cmd=$(cat "/proc/$pid/cmdline" | tr '\0' ' ')
                    user=$(stat -c '%U' "/proc/$pid")
                    start_time=$(ps -o lstart= -p "$pid")
                    
                    log "  PID: $pid"
                    log "  User: $user"
                    log "  Started: $start_time"
                    log "  Command: $cmd"
                    
                    # Check if process is hiding or has suspicious traits
                    exe_path=$(readlink "/proc/$pid/exe")
                    if [ -z "$exe_path" ] || [ "$exe_path" == "(deleted)" ]; then
                        log "  $(print_alert "WARNING: Process executable is deleted or hidden!")"
                    elif [[ "$exe_path" == */tmp/* || "$exe_path" == */dev/shm/* || "$exe_path" == */var/tmp/* ]]; then
                        log "  $(print_alert "WARNING: Process running from suspicious location: $exe_path")"
                    fi
                    
                    # Check open files
                    open_files=$(lsof -p "$pid" | wc -l)
                    log "  Open files/sockets: $open_files"
                    
                    # Check process creation time
                    start_time=$(ps -o lstart= -p "$pid")
                    log "  Started: $start_time"
                    
                    # Check process memory maps for suspicious entries
                    grep -E "rwx|w-x" /proc/$pid/maps > "$OUTPUT_DIR/pid_${pid}_suspicious_maps.txt" 2>/dev/null
                    if [ -s "$OUTPUT_DIR/pid_${pid}_suspicious_maps.txt" ]; then
                        log "  $(print_alert "WARNING: Process has memory regions with both write and execute permissions!")"
                        head -n 3 "$OUTPUT_DIR/pid_${pid}_suspicious_maps.txt" | while read -r map_line; do
                            log "    $map_line"
                        done
                    fi
                    
                    # Check for hidden libraries
                    ldd_output=$(ldd "/proc/$pid/exe" 2>/dev/null | grep -E '(/tmp/|/dev/shm/|/var/tmp/)')
                    if [ ! -z "$ldd_output" ]; then
                        log "  $(print_alert "WARNING: Process is using libraries from suspicious locations!")"
                        echo "$ldd_output" | while read -r lib_line; do
                            log "    $lib_line"
                        done
                    fi
                    
                    # Check for network capabilities
                    has_raw_sockets=$(grep -E "cap_(net_raw|net_admin)" "/proc/$pid/status" 2>/dev/null)
                    if [ ! -z "$has_raw_sockets" ]; then
                        log "  $(print_alert "WARNING: Process has raw socket capabilities (could create custom packets)!")"
                    fi
                    
                    # Provide additional context
                    log "  Process tree:"
                    ps -o pid,ppid,user,cmd --forest -p "$pid" -p $(pgrep -P "$pid")
                else
                    log "  Process $pid no longer exists"
                fi
            done
        else
            log "$(print_info "Could not identify process for connection to $dst")"
            log "$(print_info "This could be due to a short-lived process or kernel-level activity")"
        fi
    done < "$OUTPUT_DIR/beacon_candidates.txt"
}

# Define function to perform additional memory analysis if tools are available
perform_memory_analysis() {
    if command -v volatility &> /dev/null && [ -x "/usr/bin/dd" ]; then
        print_header "Memory Analysis (Optional)"
        log "$(print_info "Would you like to perform memory analysis to detect implants? (y/n)")"
        read -p "Perform memory analysis? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "$(print_info "Capturing a memory sample (this may take a while)...")"
            dd if=/dev/mem of="$OUTPUT_DIR/memory.dump" bs=1MB count=1024 2>/dev/null
            if [ -f "$OUTPUT_DIR/memory.dump" ]; then
                log "$(print_success "Memory sample captured, size: $(du -h "$OUTPUT_DIR/memory.dump" | cut -f1)")"
                log "$(print_info "Running basic Volatility analysis...")"
                volatility -f "$OUTPUT_DIR/memory.dump" imageinfo 2>&1 | tee "$OUTPUT_DIR/logs/volatility_imageinfo.txt"
                # Additional Volatility commands could be added here
            else
                log "$(print_alert "Failed to capture memory sample")"
            fi
        else
            log "$(print_info "Memory analysis skipped")"
        fi
    fi
}

# Parse network interfaces
all_interfaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v "lo" || ifconfig -a 2>/dev/null | grep -v "lo" | grep -E "^[a-z]" | awk '{print $1}')

print_header "Available Network Interfaces"
echo "$all_interfaces" | while read -r interface; do
    echo "- $interface"
done

# Ask user if they want to capture on all interfaces or specific ones
if [ -z "$EXTRA_INTERFACES" ]; then
    read -p "Capture on all interfaces? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        capture_interface="any"
    else
        echo "Enter interface(s) to capture on (space-separated):"
        read -r selected_interfaces
        capture_interface="$selected_interfaces"
    fi
else
    capture_interface="$EXTRA_INTERFACES"
fi

# Generate some test traffic if requested
echo -e "${YELLOW}Would you like to generate some test traffic during capture? (y/n)${NC}"
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Will generate test traffic during capture.${NC}"
    # Start background process for test traffic
    {
        # Wait a few seconds for capture to start
        sleep 2
        
        # Generate DNS traffic
        for domain in google.com facebook.com microsoft.com example.com test-beacon.local; do
            nslookup $domain &>/dev/null
            sleep 3
        done
        
        # Generate HTTP traffic
        for site in google.com example.com github.com; do
            curl -s -o /dev/null http://$site &>/dev/null
            sleep 2
        done
        
        # Generate HTTPS traffic
        for site in google.com github.com microsoft.com; do
            curl -s -o /dev/null https://$site &>/dev/null
            sleep 2
        done
        
        # ICMP traffic
        ping -c 3 8.8.8.8 &>/dev/null
        sleep 1
        ping -c 3 1.1.1.1 &>/dev/null
        
    } &
    traffic_pid=$!
    
    # Make sure to kill this process when script exits
    trap "kill $traffic_pid 2>/dev/null" EXIT
fi

# Start capture
print_header "Starting Network Capture"
log "$(print_info "Capturing traffic on interface(s): $capture_interface for $CAPTURE_TIME seconds...")"
log "$(print_info "Press Ctrl+C to stop capture early")"

# Force flush the log file to ensure log messages appear correctly
sync

# BPF filter for C2 traffic
C2_FILTER='(port 80 or port 443 or port 53 or port 22 or port 23 or port 21 or port 3389 or port 4444 or port 8080 or port 8443 or port 1080 or port 1443 or port 9001 or port 9002 or icmp or udp port 53 or port 137 or port 138 or port 445 or port 5353 or port 5355 or port 6667 or proto 47 or port 2222 or port 6666 or port 31337)'

# Create separate captures for different protocol groups for easier analysis
log "$(print_info "Creating separate captures for protocol analysis...")"
sync

# Make sure the command doesn't run too long by using timeout, and run the process in the background
timeout $CAPTURE_TIME tcpdump -i $capture_interface -s0 -w "$OUTPUT_DIR/pcaps/http_https.pcap" '(port 80 or port 443)' 2>/dev/null &
http_pid=$!

timeout $CAPTURE_TIME tcpdump -i $capture_interface -s0 -w "$OUTPUT_DIR/pcaps/dns.pcap" '(port 53)' 2>/dev/null &
dns_pid=$!

timeout $CAPTURE_TIME tcpdump -i $capture_interface -s0 -w "$OUTPUT_DIR/pcaps/icmp.pcap" 'icmp' 2>/dev/null &
icmp_pid=$!

timeout $CAPTURE_TIME tcpdump -i $capture_interface -s0 -w "$OUTPUT_DIR/pcaps/smb.pcap" '(port 137 or port 138 or port 445)' 2>/dev/null &
smb_pid=$!

timeout $CAPTURE_TIME tcpdump -i $capture_interface -s0 -w "$OUTPUT_DIR/pcaps/uncommon.pcap" '(port 4444 or port 8080 or port 8443 or port 1080 or port 1443 or port 9001 or port 9002 or port 2222 or port 6666 or port 31337)' 2>/dev/null &
uncommon_pid=$!

timeout $CAPTURE_TIME tcpdump -i $capture_interface -s0 -w "$CAPTURE_FILE" "$C2_FILTER" 2>/dev/null &
tcpdump_pid=$!

# Show progress
for i in {1..60}; do
    if ! kill -0 $tcpdump_pid 2>/dev/null; then
        break
    fi
    echo -ne "${CYAN}Capturing: $i/60 seconds${NC}\r"
    sleep 1
done

# Ensure all tcpdump processes are stopped after the capture period
echo -e "\n\n${GREEN}Capture phase completed after $CAPTURE_TIME seconds. Processing results...${NC}\n"
log "$(print_success "Capture completed after $CAPTURE_TIME seconds")"

for pid in $tcpdump_pid $http_pid $dns_pid $icmp_pid $smb_pid $uncommon_pid; do
    if ps -p $pid > /dev/null 2>&1; then
        kill -TERM $pid 2>/dev/null
        # Give it a second to clean up
        sleep 1
        # Force kill if still running
        if ps -p $pid > /dev/null 2>&1; then
            kill -9 $pid 2>/dev/null
        fi
    fi
done

# Check if any capture files were created and have content
capture_files_exist=false
for capfile in "$CAPTURE_FILE" "$OUTPUT_DIR/pcaps/http_https.pcap" "$OUTPUT_DIR/pcaps/dns.pcap" "$OUTPUT_DIR/pcaps/icmp.pcap" "$OUTPUT_DIR/pcaps/smb.pcap" "$OUTPUT_DIR/pcaps/uncommon.pcap"; do
    if [ -f "$capfile" ]; then
        filesize=$(stat -c%s "$capfile" 2>/dev/null || echo 0)
        if [ "$filesize" -gt 100 ]; then  # Consider files larger than 100 bytes to have useful content
            capture_files_exist=true
            log "$(print_info "Captured $(du -h "$capfile" | cut -f1) of traffic in $(basename "$capfile")")"
        else
            log "$(print_info "File $(basename "$capfile") exists but contains minimal data ($(stat -c%s "$capfile" 2>/dev/null || echo 0) bytes)")"
        fi
    else
        log "$(print_info "No data captured in $(basename "$capfile")")"
    fi
done

if [ "$capture_files_exist" = false ]; then
    log "$(print_alert "WARNING: No substantial traffic was captured! This could be due to:")"
    log "$(print_info "  - No matching network activity during capture period")"
    log "$(print_info "  - Issues with capture permissions or interfaces")"
    log "$(print_info "  - BPF filter too restrictive")"
    
    # Create an empty file to ensure subsequent commands don't fail
    for capfile in "$CAPTURE_FILE" "$OUTPUT_DIR/pcaps/http_https.pcap" "$OUTPUT_DIR/pcaps/dns.pcap" "$OUTPUT_DIR/pcaps/icmp.pcap" "$OUTPUT_DIR/pcaps/smb.pcap" "$OUTPUT_DIR/pcaps/uncommon.pcap"; do
        if [ ! -f "$capfile" ]; then
            touch "$capfile"
        fi
    done
    
    # Ask if user wants to continue with analysis even though capture was empty
    echo -e "${YELLOW}No substantial traffic was captured. Continue with analysis anyway? (y/n)${NC}"
    read -p "" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Analysis cancelled. Please check your network configuration and try again.${NC}"
        exit 1
    fi
fi

# Analyze for beaconing patterns in each protocol
detect_beacons "HTTP" "$CAPTURE_FILE"
detect_beacons "HTTPS" "$CAPTURE_FILE"
detect_beacons "DNS" "$CAPTURE_FILE"
detect_beacons "ICMP" "$CAPTURE_FILE"
detect_beacons "TCP_UNCOMMON" "$CAPTURE_FILE"
detect_beacons "UDP_UNCOMMON" "$CAPTURE_FILE"
detect_beacons "SMB" "$CAPTURE_FILE"

# Identify processes responsible for beaconing
identify_beacon_processes

# Generate summary statistics
print_header "Beacon Detection Summary"

# Count detected beacons - using safer syntax that handles the case when grep doesn't find anything
http_beacons=$(grep -c "Potential HTTP beacon detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
https_beacons=$(grep -c "Potential HTTPS beacon detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
dns_beacons=$(grep -c "Potential DNS beacon detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
icmp_beacons=$(grep -c "Potential ICMP beacon detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
tcp_uncommon_beacons=$(grep -c "Potential TCP_UNCOMMON beacon detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
udp_uncommon_beacons=$(grep -c "Potential UDP_UNCOMMON beacon detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
smb_beacons=$(grep -c "Potential SMB beacon detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
dns_tunneling=$(grep -c "Potential DNS tunneling detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
icmp_tunneling=$(grep -c "Potential ICMP tunneling detected" "$RESULTS_FILE" 2>/dev/null || echo 0)
udp_tunneling=$(grep -c "Potential UDP tunneling detected" "$RESULTS_FILE" 2>/dev/null || echo 0)

# Make sure variables are integers
http_beacons=$(echo $http_beacons | grep -o '[0-9]*')
[ -z "$http_beacons" ] && http_beacons=0
https_beacons=$(echo $https_beacons | grep -o '[0-9]*') 
[ -z "$https_beacons" ] && https_beacons=0
dns_beacons=$(echo $dns_beacons | grep -o '[0-9]*')
[ -z "$dns_beacons" ] && dns_beacons=0
icmp_beacons=$(echo $icmp_beacons | grep -o '[0-9]*')
[ -z "$icmp_beacons" ] && icmp_beacons=0
tcp_uncommon_beacons=$(echo $tcp_uncommon_beacons | grep -o '[0-9]*')
[ -z "$tcp_uncommon_beacons" ] && tcp_uncommon_beacons=0
udp_uncommon_beacons=$(echo $udp_uncommon_beacons | grep -o '[0-9]*')
[ -z "$udp_uncommon_beacons" ] && udp_uncommon_beacons=0
smb_beacons=$(echo $smb_beacons | grep -o '[0-9]*')
[ -z "$smb_beacons" ] && smb_beacons=0
dns_tunneling=$(echo $dns_tunneling | grep -o '[0-9]*')
[ -z "$dns_tunneling" ] && dns_tunneling=0
icmp_tunneling=$(echo $icmp_tunneling | grep -o '[0-9]*')
[ -z "$icmp_tunneling" ] && icmp_tunneling=0
udp_tunneling=$(echo $udp_tunneling | grep -o '[0-9]*')
[ -z "$udp_tunneling" ] && udp_tunneling=0

# Calculate totals using integer arithmetic
total_beacons=$(( http_beacons + https_beacons + dns_beacons + icmp_beacons + tcp_uncommon_beacons + udp_uncommon_beacons + smb_beacons ))
total_tunneling=$(( dns_tunneling + icmp_tunneling + udp_tunneling ))

log "Detection completed at $(date)"
log "-------------------- BEACON DETECTION SUMMARY --------------------"
log "HTTP beacons detected: $http_beacons"
log "HTTPS beacons detected: $https_beacons"
log "DNS beacons detected: $dns_beacons"
log "ICMP beacons detected: $icmp_beacons"
log "Uncommon TCP port beacons: $tcp_uncommon_beacons"
log "Uncommon UDP port beacons: $udp_uncommon_beacons"
log "SMB beacons detected: $smb_beacons"
log "-------------------- TUNNELING DETECTION SUMMARY ----------------"
log "DNS tunneling/exfiltration: $dns_tunneling"
log "ICMP tunneling: $icmp_tunneling"
log "UDP tunneling: $udp_tunneling"
log "-------------------- TOTALS --------------------"
log "Total potential beacons: $total_beacons"
log "Total tunneling techniques: $total_tunneling"
log "All data saved to: $OUTPUT_DIR"

# Check for domains/IPs commonly associated with C2 servers
if [ -f "$OUTPUT_DIR/DNS_queries.txt" ] || [ -f "$OUTPUT_DIR/HTTP_requests.txt" ] || [ -f "$OUTPUT_DIR/HTTPS_requests.txt" ]; then
    print_header "Checking for known C2 infrastructure"
    log "$(print_info "Analyzing connections for known C2 domains and patterns...")"
    
    # Create a combined list of all domains/IPs
    cat "$OUTPUT_DIR/DNS_queries.txt" 2>/dev/null | awk '{print $3}' > "$OUTPUT_DIR/all_domains.txt"
    cat "$OUTPUT_DIR/HTTP_requests.txt" 2>/dev/null | awk '{print $3}' >> "$OUTPUT_DIR/all_domains.txt"
    cat "$OUTPUT_DIR/HTTPS_requests.txt" 2>/dev/null | awk '{print $4}' >> "$OUTPUT_DIR/all_domains.txt"
    
    # Define patterns commonly used by malware
    patterns=(
        # Dynamic DNS providers
        "\.no-ip\.org$"
        "\.dyndns\.org$"
        "\.hopto\.org$"
        "\.serveo\.net$"
        "\.ngrok\.io$"
        # Payload hosting sites
        "pastebin\.com"
        "github\.io"
        "githubusercontent\.com"
        "gist\.github\.com"
        "raw\.githubusercontent\.com"
        "paste\.ee"
        # TLDs often used by malware
        "\.top$"
        "\.xyz$"
        "\.cc$"
        "\.tk$"
        "\.pw$"
        "\.buzz$"
        # File storage sites
        "dropbox\.com/s/"
        "drive\.google\.com/uc"
        "1drv\.ms"
        # Common C2 patterns
        "/wp-content/uploads/[0-9]{4}/[0-9]{2}/[a-zA-Z0-9]{32,}"
        "/admin/[a-zA-Z0-9]{32,}\.php"
        "/includes/[a-zA-Z0-9]{10,}\.php"
        "/gate\.php"
        "/panel\.php"
    )
    
    # Check for matches
    for pattern in "${patterns[@]}"; do
        matches=$(grep -E "$pattern" "$OUTPUT_DIR/all_domains.txt" | sort | uniq)
        if [ ! -z "$matches" ]; then
            log "$(print_alert "Potential C2 infrastructure detected - pattern: $pattern")"
            echo "$matches" | while read -r match; do
                log "  $match"
                # Add to beacon candidates for process identification
                echo "any|$match|any" >> "$OUTPUT_DIR/beacon_candidates.txt"
            done
        fi
    done
fi

# Create a summary visualization of beacon timings if beacons were found
if [ $total_beacons -gt 0 ] && command -v gnuplot &> /dev/null; then
    log "$(print_info "Generating beacon interval visualization...")"
    
    # Create a data file for gnuplot
    echo "# Source Destination Protocol Interval Regularity" > "$OUTPUT_DIR/analysis/beacon_plot.dat"
    grep -A 5 "Potential .* beacon detected" "$RESULTS_FILE" | grep -E "Source IP:|Destination:|Protocol:|Average interval:|Coefficient of variation:" | awk '{
        if($1 == "Source") { source=$3 }
        if($1 == "Destination:") { dest=$2 }
        if($1 == "Protocol:") { proto=$2 }
        if($1 == "Average") { interval=$3 }
        if($1 == "Coefficient") { print source, dest, proto, interval, $3 }
    }' >> "$OUTPUT_DIR/analysis/beacon_plot.dat"
    
    # Create gnuplot script
    cat > "$OUTPUT_DIR/analysis/beacon_plot.gnuplot" << EOF
set terminal png size 1000,600
set output "$OUTPUT_DIR/analysis/beacon_intervals.png"
set title "Detected Beacon Intervals"
set xlabel "Connection ID"
set ylabel "Interval (seconds)"
set y2label "Regularity (lower is more regular)"
set ytics nomirror
set y2tics
set grid
set key outside right top
set style fill solid 0.5
set boxwidth 0.8
plot "$OUTPUT_DIR/analysis/beacon_plot.dat" using 0:4:xtic(3) with boxes title "Beacon Interval (seconds)", \
     "$OUTPUT_DIR/analysis/beacon_plot.dat" using 0:5 with points pt 7 ps 1.5 axes x1y2 title "Regularity Coefficient"
EOF
    
    # Run gnuplot
    gnuplot "$OUTPUT_DIR/analysis/beacon_plot.gnuplot" 2>/dev/null
    
    if [ -f "$OUTPUT_DIR/analysis/beacon_intervals.png" ]; then
        log "$(print_success "Beacon visualization created: $OUTPUT_DIR/analysis/beacon_intervals.png")"
    else
        log "$(print_info "Error generating visualization")"
    fi
else
    log "$(print_info "Install gnuplot for beacon interval visualization")"
fi

# Create a suspicious connections network map
if [ $total_beacons -gt 0 ] && command -v dot &> /dev/null; then
    log "$(print_info "Generating suspicious connections network map...")"
    
    # Create a DOT file for GraphViz
    cat > "$OUTPUT_DIR/analysis/network_map.dot" << EOF
digraph "Suspicious Connections" {
  graph [fontname = "Arial", fontsize=16, label="Suspicious Network Connections Map", labelloc=t];
  node [fontname = "Arial", fontsize=11, shape=box, style=filled, fillcolor=lightblue];
  edge [fontname = "Arial", fontsize=9];
EOF
    
    # Add nodes and edges from beacon results
    grep -A 5 "Potential .* beacon detected" "$RESULTS_FILE" | grep -E "Source IP:|Destination:|Protocol:|Process:" | awk '{
        if($1 == "Source") { source=$3 }
        if($1 == "Destination:") { dest=$2 }
        if($1 == "Protocol:") { proto=$2 }
        if($1 == "Process:") { 
            split($2, a, "/");
            process=a[2];
            print "  \"" source "\" [fillcolor=lightgreen];"
            print "  \"" dest "\" [fillcolor=salmon];"
            print "  \"" source "\" -> \"" dest "\" [label=\"" proto "\\nProcess: " process "\"];"
        }
    }' >> "$OUTPUT_DIR/analysis/network_map.dot"
    
    # Close the DOT file
    echo "}" >> "$OUTPUT_DIR/analysis/network_map.dot"
    
    # Generate the network map
    dot -Tpng "$OUTPUT_DIR/analysis/network_map.dot" -o "$OUTPUT_DIR/analysis/network_map.png"
    
    if [ -f "$OUTPUT_DIR/analysis/network_map.png" ]; then
        log "$(print_success "Network connection map created: $OUTPUT_DIR/analysis/network_map.png")"
    else
        log "$(print_info "Error generating network map")"
    fi
fi

# Create an HTML report if possible
if command -v base64 &> /dev/null; then
    log "$(print_info "Generating HTML report...")"
    
    # Create HTML report
    cat > "$OUTPUT_DIR/beacon_report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Network Beacon Detection Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #2c3e50; }
        .container { max-width: 1200px; margin: 0 auto; }
        .alert { color: #721c24; background-color: #f8d7da; padding: 10px; border-radius: 5px; }
        .info { color: #0c5460; background-color: #d1ecf1; padding: 10px; border-radius: 5px; }
        .success { color: #155724; background-color: #d4edda; padding: 10px; border-radius: 5px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .section { margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px; }
        pre { background-color: #f8f8f8; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Beacon Detection Report</h1>
        <p>Generated on $(date)</p>
        
        <div class="section">
            <h2>Summary</h2>
            <table>
                <tr><th>Type</th><th>Count</th></tr>
                <tr><td>HTTP Beacons</td><td>$http_beacons</td></tr>
                <tr><td>HTTPS Beacons</td><td>$https_beacons</td></tr>
                <tr><td>DNS Beacons</td><td>$dns_beacons</td></tr>
                <tr><td>ICMP Beacons</td><td>$icmp_beacons</td></tr>
                <tr><td>Uncommon TCP Port Beacons</td><td>$tcp_uncommon_beacons</td></tr>
                <tr><td>Uncommon UDP Port Beacons</td><td>$udp_uncommon_beacons</td></tr>
                <tr><td>SMB Beacons</td><td>$smb_beacons</td></tr>
                <tr><td>DNS Tunneling</td><td>$dns_tunneling</td></tr>
                <tr><td>ICMP Tunneling</td><td>$icmp_tunneling</td></tr>
                <tr><td>UDP Tunneling</td><td>$udp_tunneling</td></tr>
                <tr><th>Total Potential Beacons</th><th>$total_beacons</th></tr>
                <tr><th>Total Tunneling Techniques</th><th>$total_tunneling</th></tr>
            </table>
        </div>
EOF
    
    # Add the network map if available
    if [ -f "$OUTPUT_DIR/analysis/network_map.png" ]; then
        network_map_base64=$(base64 -w 0 "$OUTPUT_DIR/analysis/network_map.png")
        cat >> "$OUTPUT_DIR/beacon_report.html" << EOF
        <div class="section">
            <h2>Network Connection Map</h2>
            <img src="data:image/png;base64,$network_map_base64" alt="Network Map" style="max-width: 100%;">
        </div>
EOF
    fi
    
    # Add the interval visualization if available
    if [ -f "$OUTPUT_DIR/analysis/beacon_intervals.png" ]; then
        intervals_base64=$(base64 -w 0 "$OUTPUT_DIR/analysis/beacon_intervals.png")
        cat >> "$OUTPUT_DIR/beacon_report.html" << EOF
        <div class="section">
            <h2>Beacon Interval Analysis</h2>
            <img src="data:image/png;base64,$intervals_base64" alt="Beacon Intervals" style="max-width: 100%;">
        </div>
EOF
    fi
    
    # Add detailed findings
    cat >> "$OUTPUT_DIR/beacon_report.html" << EOF
        <div class="section">
            <h2>Detailed Findings</h2>
            <pre>$(cat "$RESULTS_FILE" | sed 's/\x1b\[[0-9;]*m//g')</pre>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                <li>Investigate any processes with suspicious memory permissions and network connections</li>
                <li>Monitor connections to external IPs with regular beaconing patterns</li>
                <li>Check any DNS queries with unusually long names or high entropy</li>
                <li>Investigate processes running from temporary directories</li>
                <li>Review any connections to uncommon ports, especially those using scripting languages</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF
    
    log "$(print_success "HTML report created: $OUTPUT_DIR/beacon_report.html")"
fi

# Final summary
echo -e "\n${GREEN}===== Beacon Detection Completed! =====${NC}"
echo -e "${YELLOW}Results saved to: $OUTPUT_DIR${NC}"

# Make sure total_beacons is an integer
[ -z "$total_beacons" ] && total_beacons=0
[ "$total_beacons" = "" ] && total_beacons=0

if [ "$total_beacons" -gt 0 ]; then
    echo -e "${RED}WARNING: $total_beacons potential C2 beacons detected!${NC}"
    
    # Make sure total_tunneling is an integer
    [ -z "$total_tunneling" ] && total_tunneling=0
    [ "$total_tunneling" = "" ] && total_tunneling=0
    
    if [ "$total_tunneling" -gt 0 ]; then
        echo -e "${RED}ADDITIONAL WARNING: $total_tunneling potential data tunneling techniques detected!${NC}"
    fi
    
    echo -e "\n${YELLOW}Details:${NC}"
    echo -e " - HTTP beacons: ${RED}$http_beacons${NC}"
    echo -e " - HTTPS beacons: ${RED}$https_beacons${NC}"
    echo -e " - DNS beacons/tunneling: ${RED}$dns_beacons${NC}"
    echo -e " - ICMP beacons/tunneling: ${RED}$icmp_beacons${NC}"
    echo -e " - Other protocols: ${RED}$((tcp_uncommon_beacons + udp_uncommon_beacons + smb_beacons))${NC}"
    
    # Show processes to investigate
    if [ -f "$OUTPUT_DIR/beacon_candidates.txt" ]; then
        echo -e "\n${YELLOW}Processes to investigate:${NC}"
        processes=$(grep -oE '\|[^|]+\|([0-9]+)' "$OUTPUT_DIR/beacon_candidates.txt" 2>/dev/null | grep -oE '[0-9]+' | sort -u)
        if [ ! -z "$processes" ]; then
            for pid in $processes; do
                if kill -0 $pid 2>/dev/null; then
                    cmd=$(ps -p $pid -o cmd= 2>/dev/null || echo "Unknown")
                    user=$(ps -p $pid -o user= 2>/dev/null || echo "Unknown")
                    echo -e " - ${RED}PID $pid${NC} ($user): $cmd"
                fi
            done
        else
            echo -e " ${YELLOW}No active suspicious processes found${NC}"
        fi
    fi
    
    # Open HTML report if available
    if [ -f "$OUTPUT_DIR/beacon_report.html" ] && command -v xdg-open &> /dev/null; then
        echo -e "\n${YELLOW}HTML report created. Would you like to view it now? (y/n)${NC}"
        read -p "" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            xdg-open "$OUTPUT_DIR/beacon_report.html" 2>/dev/null
        fi
    fi
else
    echo -e "${GREEN}No C2 beacons detected in the capture period${NC}"
    echo -e "${YELLOW}Note: This does not guarantee the absence of beacons. Consider:${NC}"
    echo -e " - Running the script for a longer period (beacons can have intervals of hours)"
    echo -e " - Monitoring additional interfaces"
    echo -e " - Using a different capture time of day (some beacons only activate during certain hours)"
fi

# Ensure we always return to the script directory
cd "$(dirname "$0")"

