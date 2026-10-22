import base64
import hashlib
import hmac
import json
import plistlib
import time

import requests
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import AppleError, anisette, ca_bundle, data_dir

srp.rfc5054_enable()
srp.no_username_in_x()

GSA = "https://gsa.apple.com"
XCODE_APP = "com.apple.gs.xcode.auth"
XCODE_VERSION = "11.2 (11B41)"
PLIST_PROLOG = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
)


def _session_file():
    return data_dir() / "session.json"


def _http(method, url, headers, data=None):
    # Apple's sign-in edge returns HTML 503 on reused connections, so every call gets a fresh one.
    for _ in range(2):
        with requests.Session() as s:
            r = s.request(method, url, headers={**headers, "Connection": "close"},
                          data=data, timeout=30, verify=ca_bundle())
            r.content
        if not (r.status_code == 503 and b"<html" in r.content[:200].lower()):
            return r
    return r


def _plist(raw):
    try:
        return plistlib.loads(raw)
    except Exception:
        return plistlib.loads(PLIST_PROLOG + raw)


def _check(body):
    status = body.get("Status", body)
    if status.get("ec", 0) != 0:
        raise AppleError(f"Apple error {status['ec']}: {status.get('em', 'unknown')}")


def _gs(params, ani):
    cpd = {"bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud",
           "loc": ani["X-Apple-Locale"], **{k: v for k, v in ani.items() if k != "X-MMe-Client-Info"}}
    body = {"Header": {"Version": "1.0.1"}, "Request": {"cpd": cpd, **params}}
    r = _http("POST", f"{GSA}/grandslam/GsService2", {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": ani["X-MMe-Client-Info"],
    }, plistlib.dumps(body))
    if r.status_code >= 400:
        raise AppleError(f"Apple sign-in failed (HTTP {r.status_code}); try again")
    return _plist(r.content)["Response"]


def _hmac(key, label):
    return hmac.new(key, label.encode(), hashlib.sha256).digest()


def _srp_login(email, password):
    ani = anisette.headers()
    user = srp.User(email, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, a = user.start_authentication()
    init = _gs({"A2k": a, "ps": ["s2k", "s2k_fo"], "u": email, "o": "init"}, ani)
    _check(init)

    digest = hashlib.sha256(password.encode()).digest()
    if init.get("sp") == "s2k_fo":
        digest = digest.hex().encode()
    user.p = hashlib.pbkdf2_hmac("sha256", digest, init["s"], init["i"], 32)
    m1 = user.process_challenge(init["s"], init["B"])
    if m1 is None:
        raise AppleError("Sign-in failed: bad server challenge")

    done = _gs({"c": init["c"], "M1": m1, "u": email, "o": "complete"}, ani)
    _check(done)
    user.verify_session(done["M2"])
    if not user.authenticated():
        raise AppleError("Sign-in failed: server could not be verified")

    sk = user.get_session_key()
    cipher = Cipher(algorithms.AES(_hmac(sk, "extra data key:")), modes.CBC(_hmac(sk, "extra data iv:")[:16])).decryptor()
    unpad = padding.PKCS7(128).unpadder()
    spd = _plist(unpad.update(cipher.update(done["spd"]) + cipher.finalize()) + unpad.finalize())

    status = done.get("Status", {})
    second = status.get("au")
    if second == "repair":
        second = None
    elif status.get("hsc") == 409:
        second = "codeAlreadySent"
    return spd, second


def _twofa_headers(spd, json_body=False):
    token = base64.b64encode(f"{spd['adsid']}:{spd['GsIdmsToken']}".encode()).decode()
    return {
        "Content-Type": "application/json" if json_body else "text/x-xml-plist",
        "Accept": "application/json, text/html" if json_body else "text/x-xml-plist",
        "Accept-Language": "en-us",
        "User-Agent": "Xcode",
        "X-Apple-Identity-Token": token,
        "X-Apple-App-Info": XCODE_APP,
        "X-Xcode-Version": XCODE_VERSION,
        **anisette.headers(),
    }


def _second_factor(spd, kind, ask_code):
    if kind in ("trustedDeviceSecondaryAuth", "codeAlreadySent"):
        if kind != "codeAlreadySent":
            r = _http("GET", f"{GSA}/auth/verify/trusteddevice", _twofa_headers(spd))
            if r.status_code not in (200, 409):
                print(f"(Apple answered HTTP {r.status_code} when asked for a code; use the one on your device if it arrived)")
        code = ask_code("Enter the code shown on your Apple device: ")
        r = _http("GET", f"{GSA}/grandslam/GsService2/validate", {**_twofa_headers(spd), "security-code": code})
        if r.status_code >= 400:
            raise AppleError(f"Code rejected (HTTP {r.status_code})")
        _check(_plist(r.content))
    else:
        body = {"phoneNumber": {"id": 1}, "mode": "sms"}
        r = _http("PUT", f"{GSA}/auth/verify/phone", _twofa_headers(spd, True), json.dumps(body))
        if r.status_code not in (200, 201, 202, 423):
            raise AppleError(f"Apple did not send an SMS code (HTTP {r.status_code})")
        code = ask_code("Enter the code sent by SMS: ")
        body["securityCode"] = {"code": code}
        r = _http("POST", f"{GSA}/auth/verify/phone/securitycode", _twofa_headers(spd, True), json.dumps(body))
        if r.status_code != 200:
            raise AppleError(f"Code rejected (HTTP {r.status_code})")


def _app_token(spd):
    sk, adsid = spd["sk"], spd["adsid"]
    checksum = hmac.new(sk, b"apptokens" + adsid.encode() + XCODE_APP.encode(), hashlib.sha256).digest()
    res = _gs({"u": adsid, "app": [XCODE_APP], "c": spd["c"], "t": spd["GsIdmsToken"],
               "checksum": checksum, "o": "apptokens"}, anisette.headers())
    _check(res)
    et = res["et"]
    if et[:3] != b"XYZ":
        raise AppleError("Malformed app token from Apple")
    token = _plist(AESGCM(sk).decrypt(et[3:19], et[19:], b"XYZ"))["t"][XCODE_APP]
    return token["token"], token.get("expiry")


def login(email, password, ask_code):
    spd, second = _srp_login(email, password)
    if second:
        _second_factor(spd, second, ask_code)
        spd, second = _srp_login(email, password)
        if second:
            raise AppleError("Apple still wants a verification code; try again")
    token, expiry = _app_token(spd)
    session = {"email": email, "adsid": spd["adsid"], "token": token, "expiry": expiry}
    _session_file().write_text(json.dumps(session))
    return session


def session():
    path = _session_file()
    if not path.exists():
        raise AppleError("Not signed in; run: py marsign.py login")
    data = json.loads(path.read_text())
    expiry = data.get("expiry")
    if isinstance(expiry, (int, float)) and (expiry / 1000 if expiry > 1e11 else expiry) < time.time():
        raise AppleError("Apple session expired; run: py marsign.py login")
    return data


def logout():
    _session_file().unlink(missing_ok=True)
