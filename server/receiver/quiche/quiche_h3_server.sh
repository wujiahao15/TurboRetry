#!/usr/bin/env bash

enable_retry=false

script_name=$(basename "$0")

print_usage() {
    echo -e "Usage: $script_name [OPTIONS]"
    echo -e "Options:"
    echo -e "  -r, --retry    Enable retry mode"
    echo -e "  -h, --help     Show this help message"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--retry)
                enable_retry=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo -e "\033[31mError: Unknown option: $1\033[0m"
                print_usage
                exit 1
                ;;
        esac
    done
}

parse_args "$@"

if [[ $enable_retry == true ]]; then
    echo -e "\033[32mGoing to run quiche http3 server with retry enabled\033[0m"
    retry_flag=""
else
    echo -e "\033[32mGoing to run quiche http3 server without retry\033[0m"
    retry_flag="--no-retry"
fi

listen_url="0.0.0.0:4433"
your_domain=""
cert_path="$HOME/.cert/${your_domain}.pem"
key_path="$HOME/.cert/${your_domain}.key"

if [[ ! -f $cert_path ]]; then
    echo -e "\033[31mError: Certificate file not found: $cert_path\033[0m"
    exit 1
fi

if [[ ! -f $key_path ]]; then
    echo -e "\033[31mError: Key file not found: $key_path\033[0m"
    exit 1
fi

echo -e "\033[32mStarting quiche http3 server, listening on ${listen_url}.\033[0m"
./target/debug/quiche-server \
  --cert "$cert_path" \
  --key "$key_path" \
  --listen "$listen_url" \
  $retry_flag
