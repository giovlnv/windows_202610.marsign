import base64
import hashlib
import json
import os
import plistlib
import time
import uuid

import requests
from websockets.sync.client import connect

from . import AppleError, ca_bundle, data_dir

SERVER = os.environ.get("MARSIGN_ANISETTE", "https://ani.jkcoxson.com")
XCODE_VERSION = "27.0 (27A5218g)"
# Apple serves the provisioning URL bag only to a Mac identity.
BAG_CLIENT_INFO = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

_client = None
_state = None
_cached = (0, None)


def _state_file():
    return data_dir() / "anisette.json"


def client():
    global _client
    if _client is None:
        r = requests.get(f"{SERVER}/v3/client_info", timeout=30)
        r.raise_for_status()
        _client = r.json()
        if "Windows" not in _client["client_info"]:
            raise AppleError(f"Anisette server doesn't report a Windows identity: {_client['client_info']}")
    return _client


def base_headers(json_body=False):
    c = client()
    kind = "application/json" if json_body else "text/x-xml-plist"
    return {
        "Content-Type": kind,
        "Accept": kind,
        "X-Mme-Client-Info": c["client_info"],
        "User-Agent": c["user_agent"],
        "X-Xcode-Version": XCODE_VERSION,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "Connection": "close",
    }


def _identity():
    ident = base64.b64decode(_state["identifier"])
    return str(uuid.UUID(bytes=ident)), hashlib.sha256(ident).hexdigest()


def _url_bag():
    h = {**base_headers(), "X-Mme-Client-Info": BAG_CLIENT_INFO}
    r = requests.get("https://gsa.apple.com/grandslam/GsService2/lookup", headers=h, timeout=30, verify=ca_bundle())
    r.raise_for_status()
    return plistlib.loads(r.content)["urls"]


def _gs_plist(url, request, extra):
    body = plistlib.dumps({"Header": {}, "Request": request})
    r = requests.post(url, data=body, headers={**base_headers(), **extra}, timeout=30, verify=ca_bundle())
    r.raise_for_status()
    return plistlib.loads(r.content)["Response"]


def _provision():
    print("Registering this PC with the anisette server (first run only)...")
    bag = _url_bag()
    device_id, md_lu = _identity()
    extra = {"X-Apple-I-MD-LU": md_lu, "X-Mme-Device-Id": device_id}
    ws_url = SERVER.replace("https://", "wss://").replace("http://", "ws://") + "/v3/provisioning_session"
    with connect(ws_url, open_timeout=30) as ws:
        while True:
            msg = json.loads(ws.recv(timeout=60))
            kind = msg.get("result")
            if kind == "GiveIdentifier":
                ws.send(json.dumps({"identifier": _state["identifier"]}))
            elif kind == "GiveStartProvisioningData":
                res = _gs_plist(bag["midStartProvisioning"], {}, extra)
                ws.send(json.dumps({"spim": res["spim"]}))
            elif kind == "GiveEndProvisioningData":
                res = _gs_plist(bag["midFinishProvisioning"], {"cpim": msg["cpim"]}, extra)
                ws.send(json.dumps({"ptm": res["ptm"], "tk": res["tk"]}))
            elif kind == "ProvisioningSuccess":
                _state["adi_pb"] = msg["adi_pb"]
                _state_file().write_text(json.dumps(_state))
                return
            else:
                raise AppleError(f"Anisette provisioning failed: {kind} {msg.get('message', '')}".strip())


def _load(reset=False):
    global _state
    path = _state_file()
    if reset or _state is None:
        _state = None if reset else (json.loads(path.read_text()) if path.exists() else None)
        if _state is None:
            _state = {"identifier": base64.b64encode(os.urandom(16)).decode(), "adi_pb": None}
            path.write_text(json.dumps(_state))
    if not _state.get("adi_pb"):
        _provision()


def headers(sim=None, _retry=True):
    global _cached
    if not sim and _cached[1] and time.time() - _cached[0] < 60:
        return dict(_cached[1])
    _load()
    device_id, md_lu = _identity()
    body = {"identifier": _state["identifier"], "adi_pb": _state["adi_pb"]}
    if sim:
        body.update({"sim": sim, "device_id": device_id, "md_lu": md_lu})
    r = requests.post(f"{SERVER}/v3/get_headers", json=body, timeout=30)
    r.raise_for_status()
    data = r.json()
    if data.get("result") != "Headers":
        message = data.get("message", "")
        if "-45061" in message and _retry:
            _load(reset=True)
            return headers(sim, _retry=False)
        raise AppleError(f"Anisette server error: {message or data}")
    result = {
        "X-Mme-Device-Id": device_id,
        "X-Apple-I-MD": data["X-Apple-I-MD"],
        "X-Apple-I-MD-M": data["X-Apple-I-MD-M"],
        "X-Apple-I-MD-RINFO": data.get("X-Apple-I-MD-RINFO", "17106176"),
    }
    _cached = (time.time(), result)
    return dict(result)
