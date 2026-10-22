import argparse
import asyncio
import getpass
import platform
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.usbmux import list_devices

import registry
import signer
from apple import AppleError, account, data_dir, portal


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
    note = "not saved" if args.no_save else "saved in Windows Credential Manager"
    password = getpass.getpass(f"Password ({note}): ")
    s = account.login(email, password, lambda prompt: input(prompt).strip(), save_password=not args.no_save)
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


async def push(lockdown, signed):
    def progress(percent, *_):
        print(f"\r{percent:3d}%", end="", flush=True)

    async with InstallationProxyService(lockdown=lockdown) as proxy:
        await proxy.install_from_local(signed, handler=progress)
    print()


async def sign_and_push(lockdown, ipa):
    app = signer.ipa_info(ipa)
    device_name = await lockdown.get_value(key="DeviceName")
    udid = await lockdown.get_value(key="UniqueDeviceID")
    print(f"{app['name']} {app['version']} -> {device_name}")
    assets = portal.provision(app["bundle_id"], app["name"], udid, device_name)
    signed = Path(tempfile.gettempdir()) / f"marsign-{assets['bundle_id']}.ipa"
    _, info = signer.sign(ipa, assets["p12"], assets["profile"], assets["password"], signed)
    print(f"Signed {info['bundle_id']} (expires {info['expires']:%Y-%m-%d})")
    await push(lockdown, signed)
    signed.unlink(missing_ok=True)
    registry.record(ipa, app, info["bundle_id"], info["expires"])
    print(f"Installed {app['name']}")


async def cmd_install(args):
    ipa = check_ipa(args.ipa)
    lockdown = await connect(args.udid)
    try:
        if args.unsigned_ok:
            await push(lockdown, ipa)
        elif args.p12 or args.profile:
            await push(lockdown, manual_sign(args, ipa))
        else:
            await sign_and_push(lockdown, ipa)
    finally:
        await lockdown.close()


async def cmd_wifi(args):
    lockdown = await connect(args.udid)
    try:
        await lockdown.set_enable_wifi_connections(True)
        name = await lockdown.get_value(key="DeviceName")
        print(f"Wi-Fi connections enabled for {name}. Keep the PC and iPhone on the same network.")
    finally:
        await lockdown.close()


async def cmd_status(args):
    apps = registry.load()
    if not apps:
        print("No apps installed through Marsign yet.")
    for bundle_id, entry in sorted(apps.items()):
        print(f"{entry['name']} {entry['version']}  {registry.days_left(entry):.1f} days left  {bundle_id}")


async def cmd_refresh(args):
    apps = registry.load()
    due = {b: e for b, e in apps.items() if args.force or registry.days_left(e) <= args.days}
    print(f"[{datetime.now():%Y-%m-%d %H:%M}] {len(due)} of {len(apps)} apps due for refresh")
    if not due:
        return
    lockdown = await connect(args.udid)
    try:
        failed = []
        for bundle_id, entry in due.items():
            ipa = Path(entry["ipa"])
            if not ipa.is_file():
                failed.append(f"{entry['name']}: stored .ipa missing, install it again")
                continue
            try:
                await sign_and_push(lockdown, ipa)
            except Exception as e:
                failed.append(f"{entry['name']}: {e}")
        if failed:
            sys.exit("Refresh failed for:\n  " + "\n  ".join(failed))
    finally:
        await lockdown.close()


async def cmd_uninstall(args):
    lockdown = await connect(args.udid)
    try:
        async with InstallationProxyService(lockdown=lockdown) as proxy:
            await proxy.uninstall(args.bundle_id)
        registry.forget(args.bundle_id)
        print(f"Removed {args.bundle_id}")
    finally:
        await lockdown.close()


TASK_NAME = "Marsign refresh"


async def cmd_schedule(args):
    if platform.system() != "Windows":
        sys.exit("Scheduling is only set up for Windows")
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    exe = pythonw if pythonw.exists() else Path(sys.executable)
    script = Path(__file__).resolve()
    log = data_dir() / "refresh.log"
    ps = f"""
$action = New-ScheduledTaskAction -Execute '{exe}' -Argument '"{script}" refresh --log' -WorkingDirectory '{script.parent}'
$trigger = New-ScheduledTaskTrigger -Daily -At {args.time}
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
"""
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True)
    print(f"Scheduled '{TASK_NAME}' daily at {args.time}; apps are re-signed when 2 days or less remain.")
    print(f"Missed runs (PC off or asleep) run at the next start. Log: {log}")


async def cmd_unschedule(args):
    subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], check=True)


def main():
    parser = argparse.ArgumentParser(prog="marsign")
    parser.add_argument("--udid", help="target a specific device")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("devices", help="list connected devices")
    sub.add_parser("apps", help="list installed user apps")
    login = sub.add_parser("login", help="sign in with your Apple ID")
    login.add_argument("email", nargs="?")
    login.add_argument("--no-save", action="store_true", help="don't save the password (no automatic refresh)")
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

    sub.add_parser("wifi", help="let Marsign reach this iPhone over Wi-Fi (run once over USB)")
    sub.add_parser("status", help="show apps installed through Marsign and days left")
    refresh = sub.add_parser("refresh", help="re-sign and reinstall apps close to expiring")
    refresh.add_argument("--days", type=float, default=2, help="refresh apps with this many days left or fewer")
    refresh.add_argument("--force", action="store_true", help="refresh every app now")
    refresh.add_argument("--log", action="store_true", help="append output to the refresh log")
    uninstall = sub.add_parser("uninstall", help="remove an app from the iPhone")
    uninstall.add_argument("bundle_id")
    schedule = sub.add_parser("schedule", help="refresh automatically every day (Windows Task Scheduler)")
    schedule.add_argument("--time", default="20:00", help="daily check time, HH:MM")
    sub.add_parser("unschedule", help="remove the scheduled refresh")

    args = parser.parse_args()
    if getattr(args, "log", False):
        log = open(data_dir() / "refresh.log", "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = log
    handlers = {
        "devices": cmd_devices, "apps": cmd_apps, "login": cmd_login, "logout": cmd_logout,
        "setup": cmd_setup, "profile": cmd_profile, "sign": cmd_sign, "install": cmd_install,
        "wifi": cmd_wifi, "status": cmd_status, "refresh": cmd_refresh, "uninstall": cmd_uninstall,
        "schedule": cmd_schedule, "unschedule": cmd_unschedule,
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
