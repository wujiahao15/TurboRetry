#!/usr/bin/env bash

# 1. clone quiche
git clone --recursive https://github.com/cloudflare/quiche

# 2. modify token generation
mv quiche/apps/src/bin/quiche-server.rs quiche/apps/src/bin/quiche-server.rs.bak
cp quiche-server.rs quiche/apps/src/bin/quiche-server.rs
mv quiche/apps/Cargo.toml quiche/apps/Cargo.toml.bak
cp Cargo.toml quiche/apps/Cargo.toml

# 3. build the project
cd quiche/apps
cargo build
