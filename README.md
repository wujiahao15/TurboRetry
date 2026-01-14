# TurboRetry: Mitigating large-scale QUIC Handshake Floods with Off-the-shelf DPU Offloading

We adhere to the open science policy and make `TurboRetry` public.

## Source Code Overview

The folder structure is as follows:

```csv
artifact
    |-- turboretry  --- contains the source code of our proposed `TurboRetry`
    └-- README.md
```

## Hardware and software information

### Hardware

- Server machine (HTTP/3 Service) 
  - BlueField-3
    - ATF: v2.2(release):4.7.0-25-g5569834 
    - UEFI: 4.7.0-42-g13081ae
    - FW: 32.41.1000
- Benign client machine
  - Intel X710 2×10Gbps NIC
- Adversary machine
  - Mellanox ConnectX-6 2×100Gbps

### Software

- DOCA: 2.7.0
- DPDK: 23.03
- Ubuntu 22.04 with kernel version 5.15.0
