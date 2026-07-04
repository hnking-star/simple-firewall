from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE_PATH = BASE_DIR / 'firewall.db'
DEFAULT_INTERFACE = 'any'
DEFAULT_UPDATE_MODE = 'immediate'
DEFAULT_UPDATE_INTERVAL = 30
DEFAULT_UPDATE_BATCH_SIZE = 3
