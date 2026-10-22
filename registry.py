import json
import shutil
from datetime import datetime, timezone

from apple import data_dir


def _file():
    return data_dir() / "apps.json"


def load():
    path = _file()
    return json.loads(path.read_text()) if path.exists() else {}


def _save(apps):
    _file().write_text(json.dumps(apps, indent=2))


def record(ipa, app, signed_bundle_id, expires):
    folder = data_dir() / "ipas"
    folder.mkdir(exist_ok=True)
    stored = folder / f"{app['bundle_id']}.ipa"
    if ipa.resolve() != stored.resolve():
        shutil.copyfile(ipa, stored)
    apps = load()
    apps[signed_bundle_id] = {
        "name": app["name"],
        "version": app["version"],
        "ipa": str(stored),
        "expires": expires.replace(tzinfo=expires.tzinfo or timezone.utc).isoformat(),
    }
    _save(apps)


def forget(signed_bundle_id):
    apps = load()
    entry = apps.pop(signed_bundle_id, None)
    _save(apps)
    return entry


def days_left(entry):
    expires = datetime.fromisoformat(entry["expires"])
    return (expires - datetime.now(timezone.utc)).total_seconds() / 86400
