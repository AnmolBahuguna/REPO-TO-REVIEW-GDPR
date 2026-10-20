from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.legal_assistant import build_index
from build_legal_corpus import main as build_corpus


if __name__ == "__main__":
    build_corpus()
    print(json.dumps(build_index(), indent=2))
