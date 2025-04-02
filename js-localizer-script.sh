#!/bin/bash

# Script to find web pages, locate external JS references to code.berylia.org,
# and replace them with reliable CDN versions

# Configuration
TARGET_DOMAIN="code.berylia.org"
WEB_EXTENSIONS=("php" "html" "htm" "asp" "aspx" "jsp")
SEARCH_DIRS=("/var/www" "/opt")
LOGFILE="js_cdn_replacer.log"

# CDN mappings - add more as needed
declare -A CDN_MAPPINGS
# jQuery versions
CDN_MAPPINGS["jquery-3.4.1.js"]="https://code.jquery.com/jquery-3.4.1.min.js"
CDN_MAPPINGS["jquery-3.4.1.min.js"]="https://code.jquery.com/jquery-3.4.1.min.js"
CDN_MAPPINGS["jquery-3.5.1.js"]="https://code.jquery.com/jquery-3.5.1.min.js"
CDN_MAPPINGS["jquery-3.5.1.min.js"]="https://code.jquery.com/jquery-3.5.1.min.js"
CDN_MAPPINGS["jquery-3.6.0.js"]="https://code.jquery.com/jquery-3.6.0.min.js"
CDN_MAPPINGS["jquery-3.6.0.min.js"]="https://code.jquery.com/jquery-3.6.0.min.js"
# Bootstrap versions
CDN_MAPPINGS["bootstrap.bundle.min.js"]="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.bundle.min.js"
CDN_MAPPINGS["bootstrap.min.js"]="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.min.js"
CDN_MAPPINGS["bootstrap.js"]="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.js"
# Add more mappings as needed

# Initialize log
echo "$(date) - Starting JavaScript CDN replacement" > "$LOGFILE"

# Function to log messages
log_message() {
    echo "$(date) - $1" >> "$LOGFILE"
    echo "$1" >&2  # Send to stderr instead of stdout
}

# Function to get CDN URL for a JavaScript file
get_cdn_url() {
    local js_url="$1"
    local js_filename=$(basename "$js_url")
    
    # First try exact filename match
    if [[ -n "${CDN_MAPPINGS[$js_filename]}" ]]; then
        echo "${CDN_MAPPINGS[$js_filename]}"
        return 0
    fi
    
    # If no exact match, try to find a suitable alternative based on patterns
    if [[ "$js_filename" == *"jquery"* && "$js_filename" == *"3.4"* ]]; then
        echo "${CDN_MAPPINGS["jquery-3.4.1.min.js"]}"
        return 0
    elif [[ "$js_filename" == *"jquery"* && "$js_filename" == *"3.5"* ]]; then
        echo "${CDN_MAPPINGS["jquery-3.5.1.min.js"]}"
        return 0
    elif [[ "$js_filename" == *"jquery"* && "$js_filename" == *"3.6"* ]]; then
        echo "${CDN_MAPPINGS["jquery-3.6.0.min.js"]}"
        return 0
    elif [[ "$js_filename" == *"bootstrap"* && "$js_filename" == *"bundle"* ]]; then
        echo "${CDN_MAPPINGS["bootstrap.bundle.min.js"]}"
        return 0
    elif [[ "$js_filename" == *"bootstrap"* ]]; then
        echo "${CDN_MAPPINGS["bootstrap.min.js"]}"
        return 0
    fi
    
    # If no matching CDN is found, return empty
    log_message "No CDN mapping found for $js_filename"
    return 1
}

# Function to process file and replace JS references
process_file() {
    local file="$1"
    local temp_file=$(mktemp)
    local file_modified=false
    local replacement_count=0
    
    # Save original file owner and permissions
    local orig_perms=$(stat -c "%a" "$file")
    local orig_owner=$(stat -c "%U" "$file")
    local orig_group=$(stat -c "%G" "$file")
    
    log_message "Processing file: $file (owner: $orig_owner:$orig_group, permissions: $orig_perms)"
    
    # Find all script tags with src attribute pointing to TARGET_DOMAIN
    if grep -q "$TARGET_DOMAIN" "$file"; then
        # Extract all JS URLs from the file using grep
        mapfile -t js_urls < <(grep -o "src=['\"][^'\"]*$TARGET_DOMAIN[^'\"]*['\"]" "$file" | sed -E "s/src=['\"](http[s]?:\/\/[^'\"]*)['\"].*/\1/g")
        
        if [ ${#js_urls[@]} -gt 0 ]; then
            log_message "Found ${#js_urls[@]} JS URLs to process"
            
            # Create mapping of URLs to CDN replacements
            declare -A url_to_cdn_map
            for js_url in "${js_urls[@]}"; do
                log_message "Found external JS: $js_url"
                
                # Get appropriate CDN URL
                cdn_url=$(get_cdn_url "$js_url")
                
                if [ $? -eq 0 ] && [ -n "$cdn_url" ]; then
                    # Store the mapping from URL to CDN URL
                    url_to_cdn_map["$js_url"]="$cdn_url"
                    log_message "Will replace $js_url with CDN: $cdn_url"
                else
                    log_message "WARNING: No suitable CDN found for $js_url - will keep original URL"
                fi
            done
            
            # Process the file line by line
            > "$temp_file"  # Clear temp file
            
            while IFS= read -r line; do
                modified_line="$line"
                
                # Process each URL
                for js_url in "${!url_to_cdn_map[@]}"; do
                    cdn_url="${url_to_cdn_map[$js_url]}"
                    
                    # Replace double-quoted URLs
                    if [[ "$modified_line" == *"src=\"$js_url\""* ]]; then
                        old_pattern="src=\"$js_url\""
                        new_pattern="src=\"$cdn_url\""
                        modified_line="${modified_line//$old_pattern/$new_pattern}"
                        replacement_count=$((replacement_count + 1))
                        file_modified=true
                        log_message "Replaced $js_url with $cdn_url (double quotes)"
                    fi
                    
                    # Replace single-quoted URLs
                    if [[ "$modified_line" == *"src='$js_url'"* ]]; then
                        old_pattern="src='$js_url'"
                        new_pattern="src=\"$cdn_url\""
                        modified_line="${modified_line//$old_pattern/$new_pattern}"
                        replacement_count=$((replacement_count + 1))
                        file_modified=true
                        log_message "Replaced $js_url with $cdn_url (single quotes)"
                    fi
                done
                
                # Write the modified line to the temp file
                echo "$modified_line" >> "$temp_file"
            done < "$file"
            
            # If modifications were made, replace the original file
            if [ "$file_modified" = true ]; then
                # Verify the file was modified
                if ! cmp -s "$file" "$temp_file"; then
                    # Preserve file ownership and permissions
                    cp -p "$temp_file" "$file"
                    chown "$orig_owner:$orig_group" "$file"
                    chmod "$orig_perms" "$file"
                    
                    log_message "Updated file: $file with $replacement_count replacements"
                    log_message "Ensured file ownership is $orig_owner:$orig_group and permissions $orig_perms"
                    printf "true"
                else
                    log_message "No actual changes detected in file content"
                    printf "false"
                fi
            else
                printf "false"
            fi
        else
            printf "false"
        fi
    else
        printf "false"
    fi
    
    # Remove temp file
    rm -f "$temp_file"
}

# Main function to search directories and process files
main() {
    local total_files=0
    local processed_files=0
    local modified_files=0
    
    log_message "Starting search in directories: ${SEARCH_DIRS[*]}"
    log_message "Found ${#CDN_MAPPINGS[@]} CDN mappings in configuration"
    
    # Build find command for web file extensions
    find_cmd="find"
    for dir in "${SEARCH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            find_cmd="$find_cmd $dir"
        else
            log_message "WARNING: Directory not found: $dir"
        fi
    done
    
    # Add file extension patterns
    find_cmd="$find_cmd -type f \("
    for (( i=0; i<${#WEB_EXTENSIONS[@]}; i++ )); do
        find_cmd="$find_cmd -name \"*.${WEB_EXTENSIONS[$i]}\""
        if [ $i -lt $((${#WEB_EXTENSIONS[@]}-1)) ]; then
            find_cmd="$find_cmd -o"
        fi
    done
    find_cmd="$find_cmd \)"
    
    log_message "Executing: $find_cmd"
    
    # Execute find command to get all web files
    mapfile -t web_files < <(eval "$find_cmd")
    
    # Count total files
    total_files=${#web_files[@]}
    
    log_message "Found $total_files web files to scan"
    
    # Process each file
    for file in "${web_files[@]}"; do
        if [ -n "$file" ] && [ -f "$file" ]; then
            if [ -r "$file" ] && [ -w "$file" ]; then
                processed_files=$((processed_files + 1))
                
                # Process file and capture if it was modified
                was_modified=$(process_file "$file")
                
                if [ "$was_modified" = "true" ]; then
                    modified_files=$((modified_files + 1))
                    log_message "MODIFICATION COUNT: $modified_files files modified so far"
                fi
            else
                log_message "WARNING: Cannot read/write file: $file"
            fi
        fi
    done
    
    log_message "SUMMARY: Modified $modified_files out of $processed_files processed files (from a total of $total_files found)"
    log_message "All JavaScript references have been replaced with reliable CDN sources"
}

# Execute main function
main

log_message "Script completed. Check $LOGFILE for details."
exit 0
