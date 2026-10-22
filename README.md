# Marsign

Personal installer and weekly re-signer for my own iPhone apps (Marscade, Familiar), run from Windows.

## Setup

1. Install Python 3.10+ and the Apple Devices app (or iTunes).
2. `py -m pip install -r requirements.txt`
3. Plug the iPhone in, unlock it and tap **Trust**.

## Commands

    py marsign.py login                      sign in with your Apple ID (2FA code asked once)
    py marsign.py install app.ipa            sign with your Apple ID and install
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
certificate, and provisioning profiles. The password is never saved.

Apple only accepts Windows-type device identity data now, so Marsign gets it from an anisette v3 server
(`https://ani.jkcoxson.com` by default, the one iloader uses; set `MARSIGN_ANISETTE` to change it).
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
4. One command for all apps, automatic weekly refresh over Wi-Fi
