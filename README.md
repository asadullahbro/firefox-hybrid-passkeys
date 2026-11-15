# Passkeys with phone QR for Firefox on Linux

Firefox on Linux can't do the "use your phone" QR passkey sign-in (Mozilla bug
[1543674](https://bugzilla.mozilla.org/show_bug.cgi?id=1543674)). This project adds it:

- **Phone QR (FIDO hybrid / caBLE v2)**: shows a QR code, finds your phone over Bluetooth,
  talks to it through the tunnel server, and returns a normal WebAuthn result to the site.
  Verified signing in on webauthn.io and Google.
- **Local vault (optional)**: passkeys stored in the extension, encrypted with a passphrase
  you type in a separate extension window (not on the web page).

## How it works

```
web page --navigator.credentials--> content script (chooser + QR) --> background --native messaging--> host/ (Python)
                                                                                         |-- BLE advert scan (bleak)
                                                                                         |-- tunnel websocket + Noise KNpsk0
                                                                                         `-- CTAP2 over the tunnel to the phone
```

The protocol follows Chromium's `device/fido/cable` sources. Only the QR-initiated flow is
implemented, with no pairing/linking.

## Install

Needs Linux with Bluetooth (BlueZ), Python 3.10+, Firefox 140+.

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./install.sh                      # registers the native messaging host
```

Then load `extension/` via `about:debugging` -> This Firefox -> Load Temporary Add-on, or sign it
yourself as an unlisted add-on (`npx web-ext sign --channel unlisted`, needs a free addons.mozilla.org
API key) and install the `.xpi` from `about:addons`.

## Tested sites

| Site | Register | Sign in | Notes |
|---|---|---|---|
| webauthn.io | works | works | |
| Google | not tried | works | phone QR |
| GitHub | not tried | works | phone QR |
| Microsoft | not tried | works | phone QR |

Add a row (and any error message) when you try another site.

## Limits

- Phones verify you themselves; PIN/UV tokens are not supported.
- Only tested on the sites listed above. Other sites may check details these don't.
- The result object imitates `PublicKeyCredential`; sites that test `instanceof` may reject it.
- Protocol revision 1 phones only.
- Unaudited. The vault is PBKDF2-SHA256 (600k) + AES-GCM; use a long passphrase.

## Tests

```sh
.venv/bin/python tests/test_hybrid.py && .venv/bin/python tests/test_ctap_flow.py && node tests/test_authenticator.js
```

MIT licensed.
