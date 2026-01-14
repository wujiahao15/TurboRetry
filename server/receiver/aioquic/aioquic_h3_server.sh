#!/usr/bin/env bash

retry_flag=""

script_name=$(basename "$0")

print_usage() {
    echo -e "Usage: $script_name [OPTIONS]"
    echo -e "Options:"
    echo -e "  --retry    Enable retry mode"
    echo -e "  --help     Show this help message"
}

parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --retry)
                retry_flag="--retry"
                ;;
            --help)
                print_usage
                exit 0
                ;;
            *)
                echo -e "\033[31mError: Unknown option: $arg\033[0m"
                print_usage
                exit 1
                ;;
        esac
    done
}

parse_args "$@"

your_ip=""
domain_name=""
certificate_path="$HOME/.cert/$domain_name.pem"
private_key_path="$HOME/.cert/$domain_name.key"

if [ ! -f "$certificate_path" ]; then
    echo -e "\033[31mError: Certificate file not found: $certificate_path\033[0m"
    exit 1
else
    echo -e "\033[32mCertificate file set to: $certificate_path\033[0m"
fi

if [ ! -f "$private_key_path" ]; then
    echo -e "\033[31mError: Private key file not found: $private_key_path\033[0m"
    exit 1
else
    echo -e "\033[32mPrivate key file set to: $private_key_path\033[0m"
fi

if [ -n "$retry_flag" ]; then
    echo -e "\033[32mStarting aioquic http3 server with retry enabled...\033[0m"
else
    echo -e "\033[32mStarting aioquic http3 server without retry...\033[0m"
fi
python examples/http3_server.py \
    --certificate "$certificate_path" \
    --private-key "$private_key_path" \
    --host $your_ip \
    --port "4433" \
    $retry_flag
