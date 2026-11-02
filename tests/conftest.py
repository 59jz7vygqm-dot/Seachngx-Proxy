import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# gateway/ und filterd/ sind eigenstaendige Images; fuer die Tests werden
# ihre reinen Logikmodule direkt importiert.
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "filterd"))
