# Marsign

Personal installer and weekly re-signer for my own iPhone apps (Marscade, Familiar), run from Windows.

## Setup

1. Install Python 3.10+ and the Apple Devices app (or iTunes).
2. `py -m pip install -r requirements.txt`
3. Plug the iPhone in, unlock it and tap **Trust**.

## Commands

    py marsign.py devices                    list connected iPhones
    py marsign.py apps                       list installed user apps
    py marsign.py setup                      download zsign (pinned version, checksum verified)
    py marsign.py profile dev.mobileprovision    show bundle ID, team, expiry, devices
    py marsign.py sign app.ipa --p12 cert.p12 --password PW --profile dev.mobileprovision
    py marsign.py install app.ipa            install an already-signed .ipa
    py marsign.py install app.ipa --p12 cert.p12 --password PW --profile dev.mobileprovision

## Roadmap

1. Install over USB (done)
2. Sign with zsign (done)
3. Free Apple ID certificate and provisioning profile
4. One command for all apps, automatic weekly refresh over Wi-Fi
