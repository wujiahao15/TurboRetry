# Aioquic Baseline Implementation

## Prerequisite

- Python environment installed.
  - [Pyenv](https://github.com/pyenv/pyenv?tab=readme-ov-file#1-automatic-installer-recommended) installed.

## Usage

1. git clone the [aioquic](https://github.com/aiortc/aioquic) repository and modify the retry token related code

```bash
bash setup.sh
```

2. create a python virtual environment and install the cloned aioquic in editable mode.

```bash
    # just a example
pyenv virtualenv aioquic-aes-retry
pyenv activate aioquic-aes-retry
pip install ninja2 starlette wsproto
cd aioquic
pip install -e .
```

3. run the aioquic based http3 server.

```bash
bash aioquic_h3_server.sh
```
