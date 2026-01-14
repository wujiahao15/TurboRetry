# Attacker code

Traffic generator built on top of DPDK.

## Requirements

- DPDK: 23.03

## Usage

- Compile
  - `make release`
- Run
  - `sudo ./build/dpdk_qia 1000 10`
    - Generate attack traffic with 1000 pps rate with 10s duration.
