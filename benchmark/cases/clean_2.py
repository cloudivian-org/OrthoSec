import json
from pathlib import Path


def load_config(path):
    return json.loads(Path(path).read_text())


def save_config(path, cfg):
    Path(path).write_text(json.dumps(cfg, indent=2))
