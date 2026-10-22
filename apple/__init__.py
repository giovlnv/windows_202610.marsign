import os
from functools import lru_cache
from pathlib import Path

import certifi

ROOT = Path(__file__).resolve().parent.parent


class AppleError(Exception):
    pass


def data_dir():
    base = os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share"
    path = Path(base) / "Marsign"
    path.mkdir(parents=True, exist_ok=True)
    return path


@lru_cache(maxsize=1)
def ca_bundle():
    bundle = data_dir() / "ca_bundle.pem"
    bundle.write_bytes(Path(certifi.where()).read_bytes() + b"\n" + (ROOT / "certs" / "apple_ca.pem").read_bytes())
    return str(bundle)
