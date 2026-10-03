"""リポジトリ直下の conftest: `script/` を import パスに載せる。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPT_DIR = ROOT / "script"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
