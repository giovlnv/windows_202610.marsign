import json
import plistlib
import uuid

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from . import AppleError, account, anisette, ca_bundle, data_dir

BASE = "https://developerservices2.apple.com/services/QH65B2/"
CLIENT_ID = "XABBG36SBA"
# Apple limits certificates per machine name, so this one coexists with AltStore's or Xcode's.
MACHINE_NAME = "Marsign"
P12_PASSWORD = "marsign"


def _call(endpoint, params=None, team=None):
    s = account.session()
    body = {"clientId": CLIENT_ID, "protocolVersion": "QH65B2", "requestId": str(uuid.uuid4()).upper(),
            "userLocale": ["en_US"]}
    if team:
        body["teamId"] = team
    body.update(params or {})
    r = requests.post(f"{BASE}{endpoint}?clientId={CLIENT_ID}", data=plistlib.dumps(body), timeout=30,
                      verify=ca_bundle(), headers={
                          **anisette.base_headers(),
                          **anisette.headers(),
                          "X-Apple-GS-Token": s["token"],
                          "X-Apple-I-Identity-Id": s["adsid"],
                      })
    if r.status_code == 401:
        raise AppleError("Apple session expired; run: py marsign.py login")
    r.raise_for_status()
    result = plistlib.loads(r.content)
    if result.get("resultCode") not in (0, None, "0"):
        msg = result.get("userString") or result.get("resultString") or "unknown error"
        raise AppleError(f"Apple developer error {result.get('resultCode')}: {msg}")
    return result


def team():
    teams = _call("listTeams.action").get("teams", [])
    if not teams:
        raise AppleError("This Apple ID has no development team")
    return teams[0]["teamId"]


def _dir(team_id):
    path = data_dir() / "teams" / team_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def _public_der(obj):
    return obj.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def certificate(team_id, log=print):
    cache = _dir(team_id) / "certificate.json"
    certs = _call("ios/listAllDevelopmentCerts.action", team=team_id).get("certificates", [])
    if cache.exists():
        cached = json.loads(cache.read_text())
        if any(c.get("serialNumber") == cached["serial"] for c in certs):
            return cached
    for c in certs:
        if c.get("machineName") == MACHINE_NAME and c.get("serialNumber"):
            log(f"Revoking old Marsign certificate {c['serialNumber']}")
            _call("ios/revokeDevelopmentCert.action", {"serialNumber": c["serialNumber"]}, team=team_id)

    log("Requesting a new signing certificate")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, MACHINE_NAME)])).sign(key, hashes.SHA256())
    _call("ios/submitDevelopmentCSR.action", {
        "csrContent": csr.public_bytes(serialization.Encoding.PEM).decode(),
        "machineId": str(uuid.uuid4()).upper(),
        "machineName": MACHINE_NAME,
    }, team=team_id)

    mine = _public_der(key)
    for c in _call("ios/listAllDevelopmentCerts.action", team=team_id).get("certificates", []):
        content = c.get("certContent")
        if isinstance(content, bytes) and _public_der(x509.load_der_x509_certificate(content)) == mine:
            cached = {
                "serial": c["serialNumber"],
                "key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption()).decode(),
                "cert": content.hex(),
            }
            cache.write_text(json.dumps(cached))
            return cached
    raise AppleError("Apple issued a certificate but it could not be found")


def device(team_id, udid, name):
    norm = udid.replace("-", "").lower()
    for d in _call("ios/listDevices.action", team=team_id).get("devices", []):
        if d.get("deviceNumber", "").replace("-", "").lower() == norm:
            return
    clean = "".join(ch for ch in name if ch.isalnum() or ch == " ").strip() or "iPhone"
    _call("ios/addDevice.action", {"deviceNumber": udid, "name": clean}, team=team_id)


def app_id(team_id, bundle_id, name):
    def find():
        for a in _call("ios/listAppIds.action", team=team_id).get("appIds", []):
            if a.get("identifier") == bundle_id:
                return a
    existing = find()
    if existing:
        return existing
    clean = "".join(ch for ch in name if ch.isalnum() or ch == " ").strip() or "App"
    try:
        return _call("ios/addAppId.action", {"identifier": bundle_id, "name": clean}, team=team_id)["appId"]
    except AppleError:
        existing = find()
        if existing:
            return existing
        raise


def provision(bundle_id, app_name, udid, device_name, log=print):
    team_id = team()
    if not bundle_id.endswith("." + team_id):
        bundle_id = f"{bundle_id}.{team_id}"
    log(f"Team {team_id}")
    cert = certificate(team_id, log)
    log(f"Registering device {device_name}")
    device(team_id, udid, device_name)
    log(f"App ID {bundle_id}")
    app = app_id(team_id, bundle_id, app_name)
    profile = _call("ios/downloadTeamProvisioningProfile.action", {"appIdId": app["appIdId"]}, team=team_id)
    data = profile.get("provisioningProfile", {}).get("encodedProfile")
    if not isinstance(data, bytes):
        raise AppleError("Apple did not return a provisioning profile")

    folder = _dir(team_id)
    profile_path = folder / f"{bundle_id}.mobileprovision"
    profile_path.write_bytes(data)
    p12_path = folder / "identity.p12"
    p12_path.write_bytes(pkcs12.serialize_key_and_certificates(
        b"Marsign",
        serialization.load_pem_private_key(cert["key"].encode(), password=None),
        x509.load_der_x509_certificate(bytes.fromhex(cert["cert"])),
        None,
        serialization.BestAvailableEncryption(P12_PASSWORD.encode()),
    ))
    return {"p12": p12_path, "password": P12_PASSWORD, "profile": profile_path, "bundle_id": bundle_id}
