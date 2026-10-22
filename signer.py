import hashlib
import io
import platform
import re
import plistlib
import subprocess
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ZSIGN_VERSION = "v1.1.2"
ZSIGN_BUILDS = {
    "Windows": ("zsign-windows-x64.zip", "96b5bf7029a52c67cdb78b68b3666d8ff1e31e5c435535964be2a482afc09e5c", "zsign.exe"),
    "Linux": ("zsign-linux-x86_64.tar.gz", "d55e6a8650949a260892a9687ac1dfe4a9c79c2e3ecfe00a0eeb09b7b694282e", "zsign"),
}
TOOLS = Path(__file__).parent / "tools"


def zsign_path():
    system = platform.system()
    if system not in ZSIGN_BUILDS:
        raise RuntimeError(f"No zsign build configured for {system}")
    return TOOLS / ZSIGN_BUILDS[system][2]


def ensure_zsign():
    exe = zsign_path()
    if exe.exists():
        return exe
    asset, sha256, name = ZSIGN_BUILDS[platform.system()]
    url = f"https://github.com/zhlynn/zsign/releases/download/{ZSIGN_VERSION}/{asset}"
    print(f"Downloading zsign {ZSIGN_VERSION}...")
    data = urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise RuntimeError("zsign download failed its checksum; not using it")
    TOOLS.mkdir(exist_ok=True)
    if asset.endswith(".zip"):
        exe.write_bytes(zipfile.ZipFile(io.BytesIO(data)).read(name))
    else:
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            exe.write_bytes(tar.extractfile(name).read())
    exe.chmod(0o755)
    return exe


def read_profile(path):
    raw = Path(path).read_bytes()
    start, end = raw.find(b"<?xml"), raw.find(b"</plist>")
    if start < 0 or end < 0:
        raise ValueError(f"Not a provisioning profile: {path}")
    profile = plistlib.loads(raw[start:end + len(b"</plist>")])
    app_id = profile["Entitlements"]["application-identifier"]
    team, bundle_id = app_id.split(".", 1)
    return {
        "name": profile.get("Name"),
        "team": team,
        "bundle_id": bundle_id,
        "expires": profile.get("ExpirationDate"),
        "devices": profile.get("ProvisionedDevices", []),
    }


def sign(ipa, p12, profile, password="", output=None):
    ipa = Path(ipa)
    output = Path(output) if output else ipa.with_name(f"{ipa.stem}-signed.ipa")
    info = read_profile(profile)
    if "*" in info["bundle_id"]:
        raise ValueError("Wildcard profiles aren't supported; use the app's own profile")
    cmd = [
        str(ensure_zsign()), "-f",
        "-k", str(p12), "-p", password,
        "-m", str(profile),
        "-b", info["bundle_id"],
        "-o", str(output), str(ipa),
    ]
    output.unlink(missing_ok=True)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or not output.exists():
        log = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
        lines = [l.strip(" >\t") for l in log.splitlines() if l.startswith(">>>")]
        errors = [l for l in lines if re.search(r"fail|unknown|invalid|can't|cannot", l, re.I)]
        raise RuntimeError("zsign failed: " + ("; ".join(errors[:3]) or f"exit code {result.returncode}"))
    return output, info
