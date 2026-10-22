import argparse
import asyncio
import sys
from pathlib import Path

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
from pymobiledevice3.usbmux import list_devices


async def connect(udid=None):
    devices = await list_devices()
    if not devices:
        sys.exit("No iPhone found. Plug it in, unlock it and tap Trust if asked.")
    if udid is None:
        usb = [d for d in devices if d.is_usb]
        udid = (usb or devices)[0].serial
    return await create_using_usbmux(serial=udid)


async def cmd_devices(args):
    devices = await list_devices()
    if not devices:
        print("No devices found.")
        return
    for d in devices:
        lockdown = await create_using_usbmux(serial=d.serial)
        try:
            name = await lockdown.get_value(key="DeviceName")
            version = await lockdown.get_value(key="ProductVersion")
            print(f"{name}  iOS {version}  [{d.connection_type}]  {d.serial}")
        finally:
            await lockdown.close()


async def cmd_apps(args):
    lockdown = await connect(args.udid)
    try:
        async with InstallationProxyService(lockdown=lockdown) as proxy:
            apps = await proxy.get_apps(application_type="User")
        for bundle_id, info in sorted(apps.items()):
            name = info.get("CFBundleDisplayName") or info.get("CFBundleName", "?")
            version = info.get("CFBundleShortVersionString", "?")
            print(f"{name}  {version}  {bundle_id}")
    finally:
        await lockdown.close()


async def cmd_install(args):
    ipa = Path(args.ipa)
    if not ipa.is_file():
        sys.exit(f"File not found: {ipa}")

    def progress(percent, *_):
        print(f"\r{percent:3d}%", end="", flush=True)

    lockdown = await connect(args.udid)
    try:
        async with InstallationProxyService(lockdown=lockdown) as proxy:
            await proxy.install_from_local(ipa, handler=progress)
        print(f"\nInstalled {ipa.name}")
    finally:
        await lockdown.close()


def main():
    parser = argparse.ArgumentParser(prog="marsign")
    parser.add_argument("--udid", help="target a specific device")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("devices", help="list connected devices")
    sub.add_parser("apps", help="list installed user apps")
    install = sub.add_parser("install", help="install a signed .ipa")
    install.add_argument("ipa")

    args = parser.parse_args()
    handlers = {"devices": cmd_devices, "apps": cmd_apps, "install": cmd_install}
    try:
        asyncio.run(handlers[args.command](args))
    except ConnectionFailedToUsbmuxdError:
        sys.exit("Can't reach Apple's USB service. Open the Apple Devices app once, or restart\n\"Apple Mobile Device Service\" in services.msc.")
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        sys.exit(f"\nError: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
