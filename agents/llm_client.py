import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

_api_key = os.environ.get("NEBIUS_API_KEY", "").strip()
if not _api_key or _api_key.startswith("your_"):
    raise RuntimeError(
        "NEBIUS_API_KEY is not set. Copy .env.example to .env and put your "
        "Nebius Token Factory key there (https://tokenfactory.nebius.com)."
    )

client = OpenAI(
    base_url="https://api.tokenfactory.nebius.com/v1/",
    api_key=_api_key,
    timeout=120.0,    # a hung request must not freeze the demo
    max_retries=3,    # automatic retry on 429 / 5xx / network errors
)

MODEL_NANO = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
MODEL_ULTRA = "nvidia/Nemotron-3-Ultra-550b-a55b"
MODEL_SUPER = "nvidia/nemotron-3-super-120b-a12b"
