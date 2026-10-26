import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lambda"))

# The handler reads these at call time; set them before any test runs.
os.environ.setdefault("INCIDENT_BUCKET", "unit-test-incident-bucket")
os.environ.setdefault("SNS_TOPIC_ARN", "")
