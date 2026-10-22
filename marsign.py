import argparse
import asyncio
import getpass
import sys
import tempfile
from pathlib import Path

from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.usbmux import list_devices

import signer
from apple import AppleError, account, portal


async def connect(udid=None):
    devices = await list_devices()
    if not devices:
        sys.exit("No iPhone found. Plug it in, unlock it and tap Trust if asked.")
    if udid is None:
        usb = [d for d in devices if d.is_usb]
        udid = (usb or devices)[0].serial
    return await create_using_usbmux(serial=udid)


def check_ipa(path):
    ipa = Path(path)
    if not ipa.is_file():
        sys.exit(f"File not found: {ipa}")
    return ipa


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
            print(f"{name}  {info.get('CFBundleShortVersionString', '?')}  {bundle_id}")
    finally:
        await lockdown.close()


async def cmd_login(args):
    email = args.email or input("Apple ID: ").strip()
    password = getpass.getpass("Password (not saved): ")
    s = account.login(email, password, lambda prompt: input(prompt).strip())
    print(f"Signed in as {s['email']}")
    print(f"Team {portal.team()}")


async def cmd_logout(args):
    account.logout()
    print("Signed out")


async def cmd_setup(args):
    print(f"zsign ready: {signer.ensure_zsign()}")


async def cmd_profile(args):
    info = signer.read_profile(args.profile)
    print(f"Name:      {info['name']}")
    print(f"Bundle ID: {info['bundle_id']}")
    print(f"Team:      {info['team']}")
    print(f"Expires:   {info['expires']:%Y-%m-%d %H:%M}")
    print(f"Devices:   {', '.join(info['devices']) or 'none'}")


def manual_sign(args, ipa, output=None):
    if not (args.p12 and args.profile):
        sys.exit("Manual signing needs both --p12 and --profile")
    out, info = signer.sign(ipa, args.p12, args.profile, args.password, output)
    print(f"Signed {info['bundle_id']} (expires {info['expires']:%Y-%m-%d}) -> {out}")
    return out


async def cmd_sign(args):
    manual_sign(args, check_ipa(args.ipa), args.output)


async def cmd_install(args):
    ipa = check_ipa(args.ipa)
    lockdown = await connect(args.udid)
    try:
        if args.unsigned_ok:
            signed = ipa
        elif args.p12 or args.profile:
            signed = manual_sign(args, ipa)
        else:
            app = signer.ipa_info(ipa)
            device_name = await lockdown.get_value(key="DeviceName")
            print(f"{app['name']} {app['version']} -> {device_name}")
            udid = await lockdown.get_value(key="UniqueDeviceID")
            assets = portal.provision(app["bundle_id"], app["name"], udid, device_name)
            signed = Path(tempfile.gettempdir()) / f"marsign-{assets['bundle_id']}.ipa"
            _, info = signer.sign(ipa, assets["p12"], assets["profile"], assets["password"], signed)
            print(f"Signed {info['bundle_id']} (expires {info['expires']:%Y-%m-%d})")

        def progress(percent, *_):
            print(f"\r{percent:3d}%", end="", flush=True)

        async with InstallationProxyService(lockdown=lockdown) as proxy:
            await proxy.install_from_local(signed, handler=progress)
        print(f"\nInstalled {ipa.name}")
    finally:
        await lockdown.close()


def main():
    parser = argparse.ArgumentParser(prog="marsign")
    parser.add_argument("--udid", help="target a specific device")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("devices", help="list connected devices")
    sub.add_parser("apps", help="list installed user apps")
    login = sub.add_parser("login", help="sign in with your Apple ID")
    login.add_argument("email", nargs="?")
    sub.add_parser("logout", help="forget the saved Apple session")
    sub.add_parser("setup", help="download zsign")

    profile = sub.add_parser("profile", help="show what a provisioning profile allows")
    profile.add_argument("profile")

    def signing_args(p):
        p.add_argument("--p12", help="use this certificate instead of your Apple ID")
        p.add_argument("--profile", help="use this provisioning profile instead of your Apple ID")
        p.add_argument("--password", default="", help="password for --p12")

    sign = sub.add_parser("sign", help="sign an .ipa with a given certificate and profile")
    sign.add_argument("ipa")
    sign.add_argument("-o", "--output")
    signing_args(sign)

    install = sub.add_parser("install", help="sign with your Apple ID and install an .ipa")
    install.add_argument("ipa")
    install.add_argument("--unsigned-ok", action="store_true", help="install the .ipa as-is")
    signing_args(install)

    args = parser.parse_args()
    handlers = {
        "devices": cmd_devices, "apps": cmd_apps, "login": cmd_login, "logout": cmd_logout,
        "setup": cmd_setup, "profile": cmd_profile, "sign": cmd_sign, "install": cmd_install,
    }
    try:
        asyncio.run(handlers[args.command](args))
    except ConnectionFailedToUsbmuxdError:
        sys.exit("Can't reach Apple's USB service. Open the Apple Devices app once, or restart\n"
                 "\"Apple Mobile Device Service\" in services.msc.")
    except AppleError as e:
        sys.exit(f"\n{e}")
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        sys.exit(f"\nError: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
