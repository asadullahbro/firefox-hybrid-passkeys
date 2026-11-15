#!/usr/bin/env python3
"""Native-messaging host: lets the Firefox extension run a WebAuthn request on a
phone via the FIDO hybrid (QR code) transport.

Extension -> host : {"op":"start","kind":"create"|"get","origin":..., "options":{...publicKey JSON...}}
host -> extension : {"event":"qr","matrix":[[bool,...]],"text":"FIDO:/..."}
                    {"event":"status","text":"..."}
                    {"event":"done","credential":{...}} | {"event":"error","message":"..."}
Extension -> host : {"op":"cancel"}
"""
import json
import os
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hybrid  # noqa: E402
import qrcode  # noqa: E402
import base64  # noqa: E402
from fido2.client import ClientError, DefaultClientDataCollector  # noqa: E402
from fido2.ctap2 import Ctap2  # noqa: E402
from fido2.webauthn import AttestationObject, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions  # noqa: E402

_out_lock = threading.Lock()


def send(msg: dict) -> None:
    data = json.dumps(msg).encode()
    with _out_lock:
        sys.stdout.buffer.write(struct.pack("=I", len(data)) + data)
        sys.stdout.buffer.flush()


def read():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return None
    (n,) = struct.unpack("=I", raw)
    return json.loads(sys.stdin.buffer.read(n))


def qr_matrix(text: str):
    q = qrcode.QRCode(border=0, error_correction=qrcode.constants.ERROR_CORRECT_L)
    q.add_data(text)
    q.make(fit=True)
    return [[bool(c) for c in row] for row in q.get_matrix()]


def run(req: dict, cancel: threading.Event):
    kind = req["kind"]
    session = hybrid.QRSession.new("mc" if kind == "create" else "ga")
    send({"event": "qr", "matrix": qr_matrix(session.qr_text()), "text": session.qr_text()})
    send({"event": "status", "text": "Scan the QR code with your phone, keep Bluetooth on"})
    eid = hybrid.wait_for_advert(session.eid_key)
    if cancel.is_set():
        return
    send({"event": "status", "text": "Phone found, connecting"})
    device = hybrid.connect_tunnel(session, eid)
    try:
        send({"event": "status", "text": "Confirm on your phone"})
        send({"event": "done", "credential": do_ctap(Ctap2(device), req, cancel)})
    finally:
        device.close()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode()


def do_ctap(ctap, req: dict, cancel) -> dict:
    """Run the WebAuthn request on the phone. Phones verify the user themselves,
    so no PIN/UV token is used (that's what the high-level Fido2Client insists on)."""
    kind = req["kind"]
    collector = DefaultClientDataCollector(req["origin"])
    builtin_uv = bool(ctap.info.options.get("uv"))
    if kind == "create":
        opts = PublicKeyCredentialCreationOptions.from_dict(req["options"])
        cd, rp_id = collector.collect_client_data(opts)
        sel = opts.authenticator_selection
        options = {}
        if sel and (sel.require_resident_key or sel.resident_key in ("required", "preferred")):
            options["rk"] = True
        if builtin_uv and not (sel and sel.user_verification == "discouraged"):
            options["uv"] = True
        att = ctap.make_credential(
            cd.hash,
            {"id": rp_id, "name": opts.rp.name},
            {k: v for k, v in (("id", opts.user.id), ("name", opts.user.name), ("displayName", opts.user.display_name)) if v is not None},
            [{"type": p.type, "alg": p.alg} for p in opts.pub_key_cred_params],
            [{"type": d.type, "id": d.id} for d in (opts.exclude_credentials or [])] or None,
            None,
            options or None,
            event=cancel,
        )
        cred = att.auth_data.credential_data
        att_obj = AttestationObject.create(att.fmt, att.auth_data, att.att_stmt)
        ext = {"credProps": {"rk": bool(options.get("rk"))}} if (req["options"].get("extensions") or {}).get("credProps") else {}
        return {
            "id": b64u(cred.credential_id), "rawId": b64u(cred.credential_id), "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "response": {
                "clientDataJSON": b64u(cd), "attestationObject": b64u(att_obj),
                "authenticatorData": b64u(att.auth_data),
                "publicKeyAlgorithm": cred.public_key.get(3, -7), "transports": ["hybrid"],
            },
            "clientExtensionResults": ext,
        }
    opts = PublicKeyCredentialRequestOptions.from_dict(req["options"])
    cd, rp_id = collector.collect_client_data(opts)
    options = {}
    if builtin_uv and opts.user_verification != "discouraged":
        options["uv"] = True
    asr = ctap.get_assertion(
        rp_id, cd.hash, [{"type": d.type, "id": d.id} for d in (opts.allow_credentials or [])] or None, None, options or None, event=cancel
    )
    cid = asr.credential["id"]
    resp = {"clientDataJSON": b64u(cd), "authenticatorData": b64u(asr.auth_data), "signature": b64u(asr.signature)}
    if asr.user and asr.user.get("id"):
        resp["userHandle"] = b64u(asr.user["id"])
    return {"id": b64u(cid), "rawId": b64u(cid), "type": "public-key", "authenticatorAttachment": "cross-platform",
            "response": resp, "clientExtensionResults": {}}


def _default(o):
    import base64
    if isinstance(o, (bytes, bytearray)):
        return base64.urlsafe_b64encode(bytes(o)).rstrip(b"=").decode()
    if hasattr(o, "items"):
        return dict(o)
    raise TypeError(type(o))


def main():
    cancel = threading.Event()
    worker = None
    while True:
        msg = read()
        if msg is None:
            cancel.set()
            return
        if msg.get("op") == "cancel":
            cancel.set()
        elif msg.get("op") == "start" and (worker is None or not worker.is_alive()):
            cancel = threading.Event()

            def go(m=msg, c=cancel):
                try:
                    run(m, c)
                except ClientError as e:
                    send({"event": "error", "message": f"{e.code.name}: {e.cause or ''}"})
                except Exception as e:  # noqa: BLE001
                    send({"event": "error", "message": f"{type(e).__name__}: {e}"})

            worker = threading.Thread(target=go, daemon=True)
            worker.start()


if __name__ == "__main__":
    main()
