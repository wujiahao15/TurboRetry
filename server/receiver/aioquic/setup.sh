#!/usr/bin/env bash

# 1. clone the repository
git clone -b 1.2.0 https://github.com/aiortc/aioquic.git
# 2. modify retry related codes
mv aioquic/src/aioquic/quic/retry.py aioquic/src/aioquic/quic/retry.py.bak
cp retry.py aioquic/src/aioquic/quic/retry.py
cp server.py aioquic/src/aioquic/asyncio/server.py
# 3. change logging level from info to warning
#    This tends to decrease messages print to stdout when running the server,
#    and improves the performance.
sed -i 's/logging\.INFO/logging.WARNING/g' aioquic/examples/http3_server.py
