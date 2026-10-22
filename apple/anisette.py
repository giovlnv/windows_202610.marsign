import io
import locale
import re
from datetime import datetime

import requests
from anisette import Anisette

from . import AppleError, data_dir

LIBS_URL = "https://anisette.dl.mikealmel.ooo/libs?arch=arm64-v8a"

# Apple rejects the Mac/Xcode identity at sign-in since 2026-10-12; a Windows identity is accepted.
CLIENT_INFO = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

_provider = None


def _download_libs():
    for _ in range(3):
        try:
            response = requests.get(LIBS_URL, timeout=60)
            response.raise_for_status()
            if response.content[:2] in (b"PK", b"\x1f\x8b"):
                return io.BytesIO(response.content)
        except requests.RequestException:
            pass
    raise AppleError("Could not download Apple's provisioning libraries; check your connection")


def _load():
    global _provider
    if _provider:
        return _provider
    state = data_dir() / "anisette.bin"
    provider = None
    if state.exists():
        try:
            provider = Anisette.load(str(state))
        except Exception:
            state.unlink()
    if provider is None:
        print("Setting up this PC as a trusted Apple device (first run only)...")
        provider = Anisette.init(_download_libs())
    if not provider.is_provisioned:
        provider.provision()
    provider.save_all(str(state))
    _provider = provider
    return provider


def _locale():
    try:
        tag = (locale.getlocale()[0] or "").replace("-", "_")
    except ValueError:
        tag = ""
    if re.fullmatch(r"[a-z]{2}_[A-Z]{2}", tag):
        return tag
    if "portuguese_brazil" in tag.lower():
        return "pt_BR"
    return "en_US"


def _timezone():
    name = datetime.now().astimezone().tzname() or ""
    if name.isascii() and name.strip() and not name.strip().lstrip("+-").isdigit():
        return name.strip()
    offset = int(datetime.now().astimezone().utcoffset().total_seconds() // 60)
    sign = "+" if offset >= 0 else "-"
    return f"GMT{sign}{abs(offset) // 60:02d}:{abs(offset) % 60:02d}"


def headers():
    data = dict(_load().get_data())
    data["X-MMe-Client-Info"] = CLIENT_INFO
    data["X-Apple-I-TimeZone"] = _timezone()
    data["X-Apple-Locale"] = _locale()
    return data
