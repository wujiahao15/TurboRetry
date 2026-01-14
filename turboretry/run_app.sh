#!/bin/bash

# default logging level
DEFAULT_LEVEL="warn"

# logging level map
declare -A LEVEL_MAP=(
    ["trace"]=70
    ["debug"]=60
    ["info"]=50
    ["warn"]=40
    ["error"]=30
)

# help message
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --app_level trace|debug|info|warn|error   Set application log level (default: warn)"
    echo "  --sdk_level trace|debug|info|warn|error   Set SDK log level (default: warn)"
    echo "  --help                                    Show this help message"
    exit 0
}

# validate log level
validate_log_level() {
    local level=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    if [[ ! ${LEVEL_MAP[$level]+_} ]]; then
        echo "Error: Invalid log level '$1'. Valid options: debug, info, warn, error"
        exit 1
    fi
    echo ${LEVEL_MAP[$level]}
}

# set default logging level
app_level=$DEFAULT_LEVEL
sdk_level=$DEFAULT_LEVEL

# parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            show_help
            ;;
        --app_level)
            validate_log_level "$2" >/dev/null
            app_level="$2"
            shift 2
            ;;
        --sdk_level)
            validate_log_level "$2" >/dev/null
            sdk_level="$2"
            shift 2
            ;;
        *)
            echo "Error: Unknown option $1"
            exit 1
            ;;
    esac
done

# logging level string to number
app_level_num=$(validate_log_level "$app_level")
sdk_level_num=$(validate_log_level "$sdk_level")

# run the application
./build/doca_retry_baseline --lcores 0@0,1@1,2@2,3@3,4@4,5@5,6@6,7@7,8@8,9@9,10@10,11@11,12@12,13@13,14@14,15@15    -- -p 03:00.0 -r vf4294967295 \
    --log-level $app_level_num \
    --sdk-log-level $sdk_level_num
