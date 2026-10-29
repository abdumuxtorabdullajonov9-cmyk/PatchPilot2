"""Test muhiti: tashqi xizmatlarsiz (Nebius API, Docker, GitHub) ishlaydi."""
import os
import sys
import types

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("NEBIUS_API_KEY", "test-key")

# openai o'rnatilmagan bo'lsa ham testlar ishlashi uchun yengil stub
if "openai" not in sys.modules:
    try:
        import openai  # noqa: F401
    except ImportError:
        stub = types.ModuleType("openai")

        class _OpenAI:
            def __init__(self, *a, **k):
                pass

        stub.OpenAI = _OpenAI
        sys.modules["openai"] = stub
