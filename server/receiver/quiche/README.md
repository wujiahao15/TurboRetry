# Quiche Baseline Implementation

## Prerequisite

- [Rust](https://www.rust-lang.org/tools/install) environment installed.

## Usage

1. Run the setup script by `bash setup.sh`. The script will do the following steps:
  1. git clone the [quiche (Cloudflare)](https://github.com/cloudflare/quiche?tab=readme-ov-file#building) repository and modify the retry token related code.
  2. compile and build quiche-server.

2. run the quiche based http3 server by `bash quiche_h3_server.sh`.
