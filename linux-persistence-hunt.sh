#!/bin/bash

# Linux Persistence Hunting Script
# Based on: https://matheuzsecurity.github.io/hacking/linux-threat-hunting-persistence/
# This script searches for common Linux persistence mechanisms

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print header with timestamp
echo -e "${BLUE}===== Linux Persistence Hunting Script =====${NC}"
echo -e "${BLUE}Date: $(date)${NC}"
echo -e "${BLUE}Hostname: $(hostname)${NC}"
echo -e "${BLUE}===========================================${NC}\n"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[WARNING] This script should be run as root for complete results${NC}"
  echo -e "${YELLOW}          Some checks may fail or return incomplete results${NC}\n"
fi

# Function to print section headers
section() {
  echo -e "\n${GREEN}[+] $1${NC}"
  echo -e "${GREEN}-------------------------------------------${NC}"
}

# Function to print findings
find_print() {
  if [ -n "$2" ]; then
    echo -e "${RED}[!] Found: $1${NC}"
    echo -e "$2"
    echo -e "${YELLOW}-------------------------------------------${NC}"
  fi
}

# Function to check files for suspicious content
check_file_content() {
  file="$1"
  if [ -f "$file" ]; then
    content=$(cat "$file" 2>/dev/null)
    suspicious=$(echo "$content" | grep -E '(wget|curl|nc|bash|sh|python|perl|ruby|php|base64|eval|exec|nohup|&$|\.sh|\.py|</dev/tcp/|</dev/udp/)' 2>/dev/null)
    if [ -n "$suspicious" ]; then
      find_print "$file contains suspicious commands" "$suspicious"
    fi
  fi
}

# 1. Cron Jobs
section "Checking Cron Jobs"

# System crontabs
system_cron=$(find /etc/cron* /var/spool/cron/crontabs -type f 2>/dev/null)
if [ -n "$system_cron" ]; then
  echo "Analyzing system crontabs..."
  for cron_file in $system_cron; do
    check_file_content "$cron_file"
  done
fi

# User crontabs
for user_home in $(cut -d: -f6 /etc/passwd); do
  if [ -f "$user_home/.crontab" ]; then
    check_file_content "$user_home/.crontab"
  fi
done

# Check for unusual cron directories
unusual_cron=$(find /etc -name "*cron*" | grep -v "^/etc/cron\|^/etc/anacrontab\|^/etc/crontab" 2>/dev/null)
find_print "Unusual cron directories" "$unusual_cron"

# 2. Systemd Services
section "Checking Systemd Services"

# Check for recently created systemd services
recent_services=$(find /etc/systemd/system /usr/lib/systemd/system -type f -name "*.service" -mtime -30 2>/dev/null)
find_print "Recently created systemd services (last 30 days)" "$recent_services"

# Check for suspicious service content
for service in $(find /etc/systemd/system /usr/lib/systemd/system -type f -name "*.service" 2>/dev/null); do
  check_file_content "$service"
done

# Check for suspicious timer units
timer_units=$(find /etc/systemd/system /usr/lib/systemd/system -type f -name "*.timer" 2>/dev/null)
for timer in $timer_units; do
  check_file_content "$timer"
done

# Check for enabled services with unusual names
unusual_services=$(systemctl list-unit-files --type=service | grep enabled | grep -v "^systemd-\|^dbus-\|^network\|^ssh\|^cron\|^rsyslog\|^sudo\|^user\|^getty\|^snapd\|^apt\|^ufw" 2>/dev/null)
find_print "Enabled services with unusual names" "$unusual_services"

# 3. Startup Scripts
section "Checking Startup Scripts"

# Init.d scripts
init_scripts=$(find /etc/init.d -type f ! -name "README" 2>/dev/null)
for script in $init_scripts; do
  check_file_content "$script"
done

# RC scripts
rc_scripts=$(find /etc/rc*.d -type l 2>/dev/null)
find_print "RC scripts" "$rc_scripts"

# 4. Profile and Bashrc Files
section "Checking Profile and Bashrc Files"

# System-wide profile files
profile_files="/etc/profile /etc/bash.bashrc /etc/profile.d/*.sh /etc/environment"
for file in $profile_files; do
  check_file_content "$file"
done

# User profile files
for user_home in $(cut -d: -f6 /etc/passwd); do
  for user_file in "$user_home/.bashrc" "$user_home/.bash_profile" "$user_home/.profile" "$user_home/.zshrc"; do
    check_file_content "$user_file"
  done
done

# 5. SSH Keys and Configurations
section "Checking SSH Files"

# Global SSH configuration
check_file_content "/etc/ssh/sshd_config"

# Authorized keys
for user_home in $(cut -d: -f6 /etc/passwd); do
  if [ -d "$user_home/.ssh" ]; then
    auth_keys="$user_home/.ssh/authorized_keys"
    if [ -f "$auth_keys" ]; then
      keys=$(cat "$auth_keys" 2>/dev/null | wc -l)
      if [ "$keys" -gt 0 ]; then
        find_print "SSH keys found for $(basename "$user_home")" "$(cat "$auth_keys" 2>/dev/null)"
      fi
    fi
  fi
done

# Check for unusual permissions on .ssh directories
unusual_ssh_perms=$(find /home -name .ssh -type d -perm /o+rwx 2>/dev/null)
find_print "SSH directories with unusual permissions" "$unusual_ssh_perms"

# 6. Kernel Modules
section "Checking Kernel Modules"

# List loaded modules
loaded_modules=$(lsmod | tail -n +2 | awk '{print $1}')
echo "Analyzing loaded kernel modules..."

# Check recently added modules
for module in $loaded_modules; do
  module_info=$(modinfo "$module" 2>/dev/null | grep -E 'filename|description|author')
  is_suspicious=$(echo "$module_info" | grep -iv "linux\|kernel\|intel\|amd\|nvidia\|realtek\|broadcom\|qlogic\|emulex" 2>/dev/null)
  if [ -n "$is_suspicious" ]; then
    find_print "Potentially suspicious kernel module: $module" "$is_suspicious"
  fi
done

# 7. PAM (Pluggable Authentication Modules)
section "Checking PAM Configurations"

# Check for suspicious PAM configuration
pam_files=$(find /etc/pam.d -type f 2>/dev/null)
for pam_file in $pam_files; do
  check_file_content "$pam_file"
done

# Custom PAM modules
custom_pam_modules=$(find /lib/security -type f -name "*.so" 2>/dev/null | grep -v -e pam_unix.so -e pam_deny.so -e pam_permit.so -e pam_env.so -e pam_time.so)
find_print "Custom PAM modules" "$custom_pam_modules"

# 8. Sudo Configuration
section "Checking Sudo Configuration"

# Check sudo configuration
check_file_content "/etc/sudoers"
sudoers_d=$(find /etc/sudoers.d -type f 2>/dev/null)
for sudo_file in $sudoers_d; do
  check_file_content "$sudo_file"
done

# 9. Web Shells
section "Checking for Web Shells"

# Common web directories
web_dirs="/var/www /srv/www /usr/share/nginx /var/www/html /usr/local/www /opt/lampp/htdocs"
for dir in $web_dirs; do
  if [ -d "$dir" ]; then
    echo "Scanning $dir for potential web shells..."
    webshells=$(find "$dir" -type f -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.cgi" 2>/dev/null | xargs grep -l -E "eval\(|shell_exec\(|system\(|passthru\(|exec\(|base64_decode\(|assert\(" 2>/dev/null)
    find_print "Potential web shells found" "$webshells"
  fi
done

# 10. Hidden Files and Directories
section "Checking for Hidden Files and Directories"

# Find hidden files in /tmp, /var/tmp, and /dev/shm
hidden_dirs=$(find /tmp /var/tmp /dev/shm -name ".*" -type d 2>/dev/null)
find_print "Hidden directories in temp locations" "$hidden_dirs"

hidden_execs=$(find /tmp /var/tmp /dev/shm -name ".*" -type f -executable 2>/dev/null)
find_print "Hidden executable files in temp locations" "$hidden_execs"

# 11. Scheduled Tasks
section "Checking for Additional Scheduled Tasks"

# Check for at jobs
at_jobs=$(atq 2>/dev/null)
find_print "Scheduled at jobs" "$at_jobs"

# Check for systemd timers
systemd_timers=$(systemctl list-timers --all 2>/dev/null | grep -v "^NEXT\|^●")
echo "Systemd timers:"
echo "$systemd_timers"

# 12. Configuration in /etc/ld.so.preload
section "Checking for LD_PRELOAD persistence"

if [ -f "/etc/ld.so.preload" ]; then
  preload_content=$(cat /etc/ld.so.preload 2>/dev/null)
  find_print "Content in /etc/ld.so.preload (potential for LD_PRELOAD attacks)" "$preload_content"
else
  echo "No /etc/ld.so.preload file found (good)"
fi

# 13. Checking for backdoored binaries
section "Checking for Modified System Binaries"

# List of critical binaries to check
critical_bins="/bin/bash /bin/sh /bin/login /bin/su /usr/bin/sudo /usr/bin/passwd"
for bin in $critical_bins; do
  if [ -f "$bin" ]; then
    file_info=$(stat "$bin")
    modified_time=$(echo "$file_info" | grep "Modify:")
    echo "$bin last $modified_time"
  fi
done

# 14. Check for SUID/SGID binaries
section "Checking for Unusual SUID/SGID Binaries"

# Find SUID and SGID binaries
unusual_suid=$(find / -type f -perm -4000 -o -perm -2000 2>/dev/null | grep -v -E '^/bin/|^/sbin/|^/usr/bin/|^/usr/sbin/')
find_print "Unusual SUID/SGID binaries outside standard directories" "$unusual_suid"

# 15. Check for suspicious D-Bus services
section "Checking for D-Bus Services"

dbus_services=$(find /usr/share/dbus-1 /etc/dbus-1 -type f -name "*.service" 2>/dev/null)
for service in $dbus_services; do
  check_file_content "$service"
done

# 16. Check for XDG autostart entries
section "Checking for XDG Autostart Entries"

xdg_autostart=$(find /etc/xdg/autostart /home/*/.config/autostart -type f -name "*.desktop" 2>/dev/null)
for entry in $xdg_autostart; do
  check_file_content "$entry"
done

# 17. Check for Docker persistence
section "Checking for Docker Persistence"

if command -v docker &> /dev/null; then
  docker_images=$(docker images 2>/dev/null)
  echo "Docker images:"
  echo "$docker_images"
  
  docker_containers=$(docker ps -a 2>/dev/null)
  echo -e "\nDocker containers:"
  echo "$docker_containers"
fi

# 18. Summary
section "Hunting Summary"

echo "Persistence hunting scan completed. Review any findings marked in red above."
echo "Remember to manually verify any suspicious findings as they may be legitimate configurations."
echo -e "${BLUE}===========================================${NC}"
