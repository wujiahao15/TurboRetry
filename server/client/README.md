# Benign client

- This client implementation is based on the aioquic and modifies its example code.

## Requirements

- Python: 3.12
- Python packages:
  - `pip install aioquic httpx pandas pyarrow loguru`
 
## Usage

```bash
bash run_client.sh --impl=<implementation_name> --tag=<tag_name>
# for example
bash run_client.sh --impl=aioquic --tag=baseline
```
