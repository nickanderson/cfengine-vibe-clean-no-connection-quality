#!/bin/bash

# Script to clean CFEngine host entries from cf_lastseen.lmdb
# based on log warnings and PostgreSQL deletion status.

# Function to display usage information
usage() {
    echo "Usage: $0 [OPTIONS] [LOG_FILE]"
    echo "  LOG_FILE: Path to the log file. If not provided, reads from stdin."
    echo ""
    echo "Options:"
    echo "  -h, --help                Display this help message."
    echo "  --limit N                 Process at most N hostkeys. Default is no limit."
    echo "  --dry-run                 Simulate the removal process without actually running cf-key --remove-keys."
    echo "  --cfe-module-protocol F   Write CFEngine module protocol output to file F for affected hostkeys."
    echo ""
    echo "Example:"
    echo "  $0 /var/log/cfengine/hub.log"
    echo "  journalctl -u cf-hub | $0 --limit 10 --dry-run --cfe-module-protocol /tmp/cf_module_output.txt"
    exit 1
}

# Initialize limit, dry_run, and cfe_module_protocol_file variables
LIMIT=""
DRY_RUN=false
CFE_MODULE_PROTOCOL_FILE=""
TEMP_CFE_PROTOCOL_FILE="" # New variable for temporary file

# Function to clean up temporary file on exit
cleanup_temp_file() {
    if [[ -n "$TEMP_CFE_PROTOCOL_FILE" && -f "$TEMP_CFE_PROTOCOL_FILE" ]]; then
        rm -f "$TEMP_CFE_PROTOCOL_FILE"
        echo "Cleaned up temporary file: $TEMP_CFE_PROTOCOL_FILE" >&2
    fi
}

# Trap signals to ensure cleanup
trap cleanup_temp_file EXIT HUP INT QUIT TERM

# Parse command-line options
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        --limit)
            if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
                LIMIT="$2"
                shift # Consume the argument value
            else
                echo "Error: --limit requires a positive integer argument." >&2
                usage
            fi
            ;;
        --dry-run)
            DRY_RUN=true
            ;;
        --cfe-module-protocol)
            if [[ -n "$2" ]]; then
                CFE_MODULE_PROTOCOL_FILE="$2"
                shift # Consume the argument value
            else
                echo "Error: --cfe-module-protocol requires a file path argument." >&2
                usage
            fi
            ;;
        *)
            # Assume it's the log file path if not an option
            if [[ -z "$INPUT_SOURCE" ]]; then
                INPUT_SOURCE="$1"
            else
                echo "Error: Too many arguments. Unexpected: $1" >&2
                usage
            fi
            ;;
    esac
    shift # Consume the option or argument
done

# Determine input source if not already set by positional argument
if [[ -z "$INPUT_SOURCE" ]]; then
    INPUT_SOURCE="/dev/stdin"
fi

# Validate input source
if [[ "$INPUT_SOURCE" != "/dev/stdin" && ! -f "$INPUT_SOURCE" ]]; then
    echo "Error: Log file '$INPUT_SOURCE' not found." >&2
    usage
fi

# If CFE module protocol file is specified, create a temporary file
if [[ -n "$CFE_MODULE_PROTOCOL_FILE" ]]; then
    # Create a temporary file in the same directory as the target, if possible,
    # or in /tmp if the target directory is not writable or doesn't exist.
    TARGET_DIR=$(dirname "$CFE_MODULE_PROTOCOL_FILE")
    if [[ -w "$TARGET_DIR" ]]; then
        TEMP_CFE_PROTOCOL_FILE=$(mktemp "$TARGET_DIR/$(basename "$CFE_MODULE_PROTOCOL_FILE").XXXXXX")
    else
        TEMP_CFE_PROTOCOL_FILE=$(mktemp "/tmp/$(basename "$CFE_MODULE_PROTOCOL_FILE").XXXXXX")
    fi

    if [[ -z "$TEMP_CFE_PROTOCOL_FILE" ]]; then
        echo "Error: Failed to create temporary file for --cfe-module-protocol." >&2
        exit 1
    fi
    echo "CFEngine module protocol output will be staged in temporary file: $TEMP_CFE_PROTOCOL_FILE"
fi

# Declare a regular array to store unique hostkeys
# This array will be populated in the current shell context.
declare -a unique_hostkeys

echo "--- Reading log entries and extracting hostkeys ---"

# Extract all hostkeys from the input, refine them to just the SHA,
# make them unique, and store them in the 'unique_hostkeys' array.
# The '< <(...)' syntax uses process substitution to feed the pipeline's output
# to 'readarray', ensuring the array is populated in the current shell.
readarray -t unique_hostkeys < <(grep -Eo "No connection quality information for host '(SHA=[a-f0-9]{64})'" "$INPUT_SOURCE" | \
                                  sed -n "s/.*'\(SHA=[a-f0-9]\{64\}\)'.*/\1/p" | \
                                  sort -u)

# Print extracted hostkeys for user feedback
for hostkey in "${unique_hostkeys[@]}"; do
    echo "Extracted hostkey: $hostkey"
done

# Check if any hostkeys were found
if [[ ${#unique_hostkeys[@]} -eq 0 ]]; then
    echo "No hostkeys found in the provided input. Exiting."
    exit 0
fi

echo -e "\n--- Checking ${#unique_hostkeys[@]} unique hostkeys against PostgreSQL ---"

# Counter for processed hostkeys
processed_count=0

# Iterate over unique hostkeys collected in the array
for hostkey in "${unique_hostkeys[@]}"; do
    # Apply limit if set
    if [[ -n "$LIMIT" && "$processed_count" -ge "$LIMIT" ]]; then
        echo "Limit of $LIMIT hostkeys reached. Stopping processing."
        break
    fi

    echo "Processing hostkey: $hostkey"

    # Construct the PostgreSQL query command
    # We're checking if the hostkey exists and was deleted more than 30 days ago.
    # The 'deleted' column is a timestamp, so we compare it with NOW() - INTERVAL '30 days'.
    # -t (or --tuples-only) is added to suppress headers and footers from psql output,
    # making it easier to parse programmatically.
    PG_QUERY="select hostkey from __hosts where hostkey = '$hostkey' AND deleted < NOW() - INTERVAL '30 days'"
    SQL_COMMAND=("psql" "-d" "cfdb" "-t" "-c" "$PG_QUERY")

    # Execute the PostgreSQL query
    # We redirect stderr to /dev/null to suppress potential psql warnings/errors if hostkey is not found.
    # We check the exit code and the output.
    if PG_RESULT=$("${SQL_COMMAND[@]}" 2>/dev/null); then
        # Check if the hostkey was returned by the SQL query (i.e., it's in the output)
        # Using grep -q is more robust than string comparison for psql output.
        if echo "$PG_RESULT" | grep -q "$hostkey"; then
            echo "  Hostkey $hostkey found in PostgreSQL and deleted more than 30 days ago."
            CF_KEY_COMMAND=("cf-key" "--remove-keys" "$hostkey" "--force")
            echo "  Attempting to remove from cf_lastseen.lmdb: ${CF_KEY_COMMAND[*]}"

            # Write to CFE module protocol temporary file if specified
            if [[ -n "$TEMP_CFE_PROTOCOL_FILE" ]]; then
                # Strip "SHA=" from the hostkey for the variable name
                hostkey_no_sha="${hostkey#SHA=}"
                echo "^meta=inventory,attribute_name=Missing connection quality info" >> "$TEMP_CFE_PROTOCOL_FILE"
                echo "=no_quality_info_in_db_deleted[$hostkey_no_sha]= $hostkey" >> "$TEMP_CFE_PROTOCOL_FILE"
                echo "  Added CFEngine module protocol entry to temporary file."
            fi

            if $DRY_RUN; then
                echo "  (DRY RUN) Would execute: ${CF_KEY_COMMAND[*]}"
            else
                # Execute the cf-key removal command
                if CF_KEY_OUTPUT=$("${CF_KEY_COMMAND[@]}" 2>&1); then
                    echo "  Successfully purged $hostkey from cf_lastseen.lmdb."
                    if [[ -n "$CF_KEY_OUTPUT" ]]; then
                        echo "    cf-key output: $CF_KEY_OUTPUT"
                    fi
                else
                    echo "  Error purging $hostkey with cf-key. Output:" >&2
                    echo "$CF_KEY_OUTPUT" >&2
                fi
            fi
        else
            echo "  Hostkey $hostkey not found in PostgreSQL with deletion older than 30 days, or not deleted."
        fi
    else
        echo "  Error querying PostgreSQL for $hostkey. Check 'psql -d cfdb' command and permissions." >&2
    fi
    processed_count=$((processed_count + 1))
done

# Move the temporary file to the final destination if CFE_MODULE_PROTOCOL_FILE was specified
if [[ -n "$CFE_MODULE_PROTOCOL_FILE" && -f "$TEMP_CFE_PROTOCOL_FILE" ]]; then
    echo -e "\n--- Finalizing CFEngine module protocol output ---"
    if mv "$TEMP_CFE_PROTOCOL_FILE" "$CFE_MODULE_PROTOCOL_FILE"; then
        echo "Successfully moved temporary protocol file to: $CFE_MODULE_PROTOCOL_FILE"
    else
        echo "Error: Failed to move temporary protocol file '$TEMP_CFE_PROTOCOL_FILE' to '$CFE_MODULE_PROTOCOL_FILE'." >&2
        echo "The temporary file might still exist at '$TEMP_CFE_PROTOCOL_FILE'." >&2
        exit 1 # Exit with an error code if the move fails
    fi
fi

echo -e "\n--- Script execution finished ---"
