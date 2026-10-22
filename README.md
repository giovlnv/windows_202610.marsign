# Marsign

Personal installer and weekly re-signer for my own iPhone apps (Marscade, Familiar), run from Windows.

## Setup

1. Install Python 3.10+ and the Apple Devices app (or iTunes).
2. `py -m pip install -r requirements.txt`
3. Plug the iPhone in, unlock it and tap **Trust**.

## Commands

    py marsign.py devices            list connected iPhones
    py marsign.py apps               list installed user apps
    py marsign.py install app.ipa    install an already-signed .ipa

## Roadmap

1. Install over USB (current)
2. Sign with zsign
3. Free Apple ID certificate and provisioning profile
4. One command for all apps, automatic weekly refresh over Wi-Fi
