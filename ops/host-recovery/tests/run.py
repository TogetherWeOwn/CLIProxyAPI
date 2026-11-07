"""Run only repository-owned tests under Python isolated mode."""
import faulthandler
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Record stacks without interrupting tests or exposing frame locals. The Actions
# process/step limits enforce the separate CI budget, not recovery phase caps.
faulthandler.enable()
faulthandler.dump_traceback_later(300, repeat=True)
try:
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
finally:
    faulthandler.cancel_dump_traceback_later()
sys.exit(0 if result.wasSuccessful() else 1)
