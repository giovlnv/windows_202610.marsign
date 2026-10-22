import argparse
import asyncio
import sys
from pathlib import Path

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
from pymobiledevice3.usbmux import list_devices

import signer


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


def add_signing_args(parser, required):
    parser.add_argument("--p12", required=required, help="signing certificate (.p12)")
    parser.add_argument("--profile", required=required, help="provisioning profile (.mobileprovision)")
    parser.add_argument("--password", default="", help="password for the .p12")


def check_ipa(path):
    ipa = Path(path)
    if not ipa.is_file():
        sys.exit(f"File not found: {ipa}")
    return ipa


def do_sign(args, ipa):
    out, info = signer.sign(ipa, args.p12, args.profile, args.password, getattr(args, "output", None))
    print(f"Signed {info['bundle_id']} (team {info['team']}, profile expires {info['expires']:%Y-%m-%d}) -> {out}")
    return out


async def cmd_setup(args):
    print(f"zsign ready: {signer.ensure_zsign()}")


async def cmd_sign(args):
    do_sign(args, check_ipa(args.ipa))


async def cmd_profile(args):
    info = signer.read_profile(args.profile)
    print(f"Name:      {info['name']}")
    print(f"Bundle ID: {info['bundle_id']}")
    print(f"Team:      {info['team']}")
    print(f"Expires:   {info['expires']:%Y-%m-%d %H:%M}")
    print(f"Devices:   {', '.join(info['devices']) or 'none'}")


async def cmd_install(args):
    ipa = check_ipa(args.ipa)
    if args.p12 or args.profile:
        if not (args.p12 and args.profile):
            sys.exit("Signing needs both --p12 and --profile")
        ipa = do_sign(args, ipa)

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
    sub.add_parser("setup", help="download zsign")
    sign = sub.add_parser("sign", help="sign an .ipa")
    sign.add_argument("ipa")
    sign.add_argument("-o", "--output", help="output path (default: <name>-signed.ipa)")
    add_signing_args(sign, required=True)
    profile = sub.add_parser("profile", help="show what a provisioning profile allows")
    profile.add_argument("profile")
    install = sub.add_parser("install", help="install an .ipa, signing it first if --p12/--profile are given")
    install.add_argument("ipa")
    add_signing_args(install, required=False)

    args = parser.parse_args()
    handlers = {
        "devices": cmd_devices, "apps": cmd_apps, "setup": cmd_setup,
        "sign": cmd_sign, "profile": cmd_profile, "install": cmd_install,
    }
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
