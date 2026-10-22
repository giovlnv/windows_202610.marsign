# Marsign

Personal installer and weekly re-signer for my own iPhone apps (Marscade, Familiar), run from Windows.

## Setup

1. Install Python 3.10+ and the Apple Devices app (or iTunes).
2. `py -m pip install -r requirements.txt`
3. Plug the iPhone in, unlock it and tap **Trust**.

## Commands

    py marsign.py login                      sign in; the password is kept in Windows Credential Manager
    py marsign.py install app.ipa            sign with your Apple ID, install, and remember it for refresh
    py marsign.py status                     apps installed through Marsign and days left
    py marsign.py refresh [--force]          re-sign apps with 2 days or less left
    py marsign.py wifi                       let Marsign reach the iPhone over Wi-Fi (once, over USB)
    py marsign.py schedule [--time 20:00]    daily automatic refresh via Task Scheduler
    py marsign.py unschedule                 remove the scheduled refresh
    py marsign.py uninstall BUNDLE_ID        remove an app from the iPhone
    py marsign.py devices                    list connected iPhones
    py marsign.py apps                       list installed user apps
    py marsign.py logout                     forget the saved Apple session

Manual signing, without an Apple ID:

    py marsign.py setup                      download zsign (pinned version, checksum verified)
    py marsign.py profile dev.mobileprovision
    py marsign.py sign app.ipa --p12 cert.p12 --password PW --profile dev.mobileprovision
    py marsign.py install app.ipa --p12 cert.p12 --password PW --profile dev.mobileprovision

## Where things are kept

`%LOCALAPPDATA%\Marsign`: the Apple session token, this PC's device identity, the signing key and
certificate, provisioning profiles, a copy of each installed .ipa, and `refresh.log`. The Apple ID
password is kept in Windows Credential Manager (skip with `login --no-save`) so refreshes can sign in
again on their own; `logout` removes it.

Apple rejects locally generated device identity data now, so Marsign gets it from an anisette v3 server:
`mac-ani.jkcoxson.com` by default, the same as iloader. Alternatives are `new.ani.sidestore.io` and
`ani3.stikstore.app`; set `MARSIGN_ANISETTE` to use one.
The server sees this PC's device identifier, never the Apple ID, password or codes.

The certificate is registered under the machine name "Marsign", so it lives alongside AltStore's
or Xcode's instead of replacing them. Only older Marsign certificates are ever revoked.

## Credits

The Apple sign-in and developer-portal flow follows [iPASide](https://github.com/pwnapplehat/iPASide)
(MIT). Signing uses [zsign](https://github.com/zhlynn/zsign); device access uses
[pymobiledevice3](https://github.com/doronz88/pymobiledevice3); the anisette v3 protocol follows
[isideload](https://github.com/nab138/isideload), iloader's library.

## Roadmap

1. Install over USB (done)
2. Sign with zsign (done)
3. Free Apple ID certificate and provisioning profile (done)
4. One command for all apps, automatic weekly refresh over Wi-Fi (done)
