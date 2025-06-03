#!/bin/bash

# Script to clean CFEngine host entries from cf_lastseen.lmdb
# based on log warnings and PostgreSQL deletion status.

# Function to display usage information
usage() {
    echo "Usage: $0 [OPTIONS] [LOG_FILE]"
    echo "  LOG_FILE: Path to the log file. If not provided, reads from stdin."
    echo ""
    echo "Options:"
    echo "  -h, --help    Display this help message."
    echo "  --limit N     Process at most N hostkeys. Default is no limit."
    echo "  --dry-run     Simulate the removal process without actually running cf-key --remove-keys."
    echo ""
    echo "Example:"
    echo "  $0 /var/log/cfengine/hub.log"
    echo "  journalctl -u cf-hub | $0 --limit 10 --dry-run"
    exit 1
}

# Initialize limit and dry_run variables
LIMIT=""
DRY_RUN=false

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
    # Changed 'sql cfdb -c' to 'psql -d cfdb -t -c'
    # -t (or --tuples-only) is added to suppress headers and footers from psql output,
    # making it easier to parse programmatically.
    PG_QUERY="select hostkey from __hosts where hostkey = '$hostkey' AND deleted < NOW() - INTERVAL '30 days'"
    SQL_COMMAND=("psql" "-d" "cfdb" "-t" "-c" "$PG_QUERY")

    # Execute the PostgreSQL query
    # We redirect stderr to /dev/null to suppress potential psql warnings/errors if hostkey is not found.
    # We check the exit code and the output.
    if PG_RESULT=$("${SQL_COMMAND[@]}" 2>/dev/null); then
        # Check if the hostkey was returned by the SQL query (i.e., it's in the output)
        # We trim whitespace from PG_RESULT before checking.
        if [[ "$(echo "$PG_RESULT" | tr -d '[:space:]')" == "$(echo "$hostkey" | tr -d '[:space:]')" ]]; then
            echo "  Hostkey $hostkey found in PostgreSQL and deleted more than 30 days ago."
            CF_KEY_COMMAND=("cf-key" "--remove-keys" "$hostkey" "--force")
            echo "  Attempting to remove from cf_lastseen.lmdb: ${CF_KEY_COMMAND[*]}"

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

echo -e "\n--- Script execution finished ---"

