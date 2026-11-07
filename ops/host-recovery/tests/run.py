"""Run only repository-owned tests under Python isolated mode."""
import faulthandler
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Keep crash diagnostics, but do not walk live frames from a watchdog thread.
# Actions process/step limits enforce the separate CI budget.
faulthandler.enable()
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
