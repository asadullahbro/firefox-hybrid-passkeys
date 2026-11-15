"""Client side of the FIDO "hybrid" (caBLE v2) transport: QR code, BLE advert,
tunnel server, Noise KNpsk0 handshake and the encrypted CTAP2 channel.

Written from Chromium's device/fido/cable sources. QR-initiated flow only; no
pairing/linking is requested, so the phone never stores anything about us.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from threading import Event
from typing import Callable

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2.ctap import CtapDevice

KNOWN_DOMAINS = ["cable.ua5v.com", "cable.auth.com"]
BLE_UUIDS = ("0000fde2-0000-1000-8000-00805f9b34fb", "0000fff9-0000-1000-8000-00805f9b34fb")

EID_KEY, TUNNEL_ID, PSK = 1, 2, 3

MSG_SHUTDOWN, MSG_CTAP, MSG_UPDATE, MSG_JSON = 0, 1, 2, 3


class HybridError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Key derivation / QR payload
# --------------------------------------------------------------------------- #
def derive(secret: bytes, nonce: bytes, purpose: int, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=nonce or None,
        info=struct.pack("<I", purpose),
    ).derive(secret)


def _bytes_to_digits(data: bytes) -> str:
    widths = [0, 3, 5, 8, 10, 13, 15, 17]
    out = []
    for i in range(0, len(data), 7):
        chunk = data[i : i + 7]
        v = int.from_bytes(chunk, "little")
        out.append(str(v).zfill(widths[len(chunk)]))
    return "".join(out)


@dataclass
class QRSession:
    identity: ec.EllipticCurvePrivateKey
    secret: bytes  # 16 bytes
    request_type: str  # "ga" or "mc"

    @classmethod
    def new(cls, request_type: str) -> "QRSession":
        return cls(ec.generate_private_key(ec.SECP256R1()), os.urandom(16), request_type)

    @property
    def public_compressed(self) -> bytes:
        return self.identity.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )

    @property
    def public_uncompressed(self) -> bytes:
        return self.identity.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    def qr_text(self) -> str:
        payload = {
            0: self.public_compressed,
            1: self.secret,
            2: len(KNOWN_DOMAINS),
            3: int(time.time()),
            4: False,  # do not offer linking
            5: self.request_type,
        }
        return "FIDO:/" + _bytes_to_digits(cbor2.dumps(payload, canonical=True))

    @property
    def eid_key(self) -> bytes:
        return derive(self.secret, b"", EID_KEY, 64)

    @property
    def tunnel_id(self) -> bytes:
        return derive(self.secret, b"", TUNNEL_ID, 16)


# --------------------------------------------------------------------------- #
# BLE advert
# --------------------------------------------------------------------------- #
def decrypt_advert(advert: bytes, eid_key: bytes) -> bytes | None:
    """Returns the 16-byte decrypted EID, or None if the advert isn't ours."""
    if len(advert) != 20:
        return None
    aes_key, hmac_key = eid_key[:32], eid_key[32:]
    tag = hmac.new(hmac_key, advert[:16], hashlib.sha256).digest()[:4]
    if not hmac.compare_digest(tag, advert[16:]):
        return None
    dec = Cipher(algorithms.AES(aes_key), modes.ECB()).decryptor()
    eid = dec.update(advert[:16]) + dec.finalize()
    if eid[0] != 0:
        return None
    return eid


def eid_components(eid: bytes) -> tuple[bytes, int]:
    """(routing_id[3], tunnel_server_domain)."""
    routing_id = eid[11:14]
    domain = struct.unpack("<H", eid[14:16])[0]
    return routing_id, domain


def decode_domain(domain: int) -> str:
    if domain < 256:
        if domain >= len(KNOWN_DOMAINS):
            raise HybridError(f"unknown tunnel server domain id {domain}")
        return KNOWN_DOMAINS[domain]
    templ = b"caBLEv2 tunnel server domain" + struct.pack("<H", domain) + b"\x00"
    assert len(templ) == 31
    result = int.from_bytes(hashlib.sha256(templ).digest()[:8], "little")
    chars = "abcdefghijklmnopqrstuvwxyz234567"
    tld = result & 3
    result >>= 2
    ret = "cable."
    while result:
        ret += chars[result & 31]
        result >>= 5
    return ret + "." + ["com", "org", "net", "info"][tld]


async def _scan_for_advert(eid_key: bytes, timeout: float) -> bytes:
    from bleak import BleakScanner

    found: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def on_adv(_dev, adv):
        if found.done():
            return
        for uuid, data in adv.service_data.items():
            if uuid.lower() in BLE_UUIDS and len(data) == 20:
                eid = decrypt_advert(bytes(data), eid_key)
                if eid:
                    found.set_result(eid)
                    return

    async with BleakScanner(on_adv):
        try:
            return await asyncio.wait_for(found, timeout)
        except asyncio.TimeoutError:
            raise HybridError("no matching Bluetooth advert from the phone (is Bluetooth on near the phone?)")


def wait_for_advert(eid_key: bytes, timeout: float = 120.0) -> bytes:
    return asyncio.run(_scan_for_advert(eid_key, timeout))


# --------------------------------------------------------------------------- #
# Noise (KNpsk0 over P-256 / AES-GCM / SHA-256, as profiled by caBLE)
# --------------------------------------------------------------------------- #
def _hkdf2(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    out = HKDF(hashes.SHA256(), 64, salt=ck, info=b"").derive(ikm)
    return out[:32], out[32:]


class Noise:
    def __init__(self, name: bytes):
        self.ck = name.ljust(32, b"\x00")
        self.h = self.ck
        self.k = b""
        self.n = 0

    def mix_hash(self, data: bytes):
        self.h = hashlib.sha256(self.h + data).digest()

    def _init_key(self, k: bytes):
        self.k, self.n = k, 0

    def mix_key(self, ikm: bytes):
        self.ck, k = _hkdf2(self.ck, ikm)
        self._init_key(k)

    def mix_key_and_hash(self, ikm: bytes):
        out = HKDF(hashes.SHA256(), 96, salt=self.ck, info=b"").derive(ikm)
        self.ck = out[:32]
        self.mix_hash(out[32:64])
        self._init_key(out[64:96])

    def _nonce(self) -> bytes:
        nonce = struct.pack(">I", self.n) + b"\x00" * 8
        self.n += 1
        return nonce

    def encrypt_and_hash(self, pt: bytes) -> bytes:
        ct = AESGCM(self.k).encrypt(self._nonce(), pt, self.h)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct: bytes) -> bytes:
        pt = AESGCM(self.k).decrypt(self._nonce(), ct, self.h)
        self.mix_hash(ct)
        return pt

    def traffic_keys(self) -> tuple[bytes, bytes]:
        return _hkdf2(self.ck, b"")


class Crypter:
    """Post-handshake transport encryption (32-byte padding, counter nonces)."""

    PAD = 32

    def __init__(self, read_key: bytes, write_key: bytes):
        self.read_key, self.write_key = read_key, write_key
        self.rseq = self.wseq = 0

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00" * 8 + struct.pack(">I", counter)

    def encrypt(self, msg: bytes) -> bytes:
        padded = (len(msg) + 1 + self.PAD - 1) & ~(self.PAD - 1)
        zeros = padded - len(msg) - 1
        body = msg + b"\x00" * zeros + bytes([zeros])
        ct = AESGCM(self.write_key).encrypt(self._nonce(self.wseq), body, None)
        self.wseq += 1
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        pt = AESGCM(self.read_key).decrypt(self._nonce(self.rseq), ct, None)
        self.rseq += 1
        if not pt:
            raise HybridError("empty caBLE message")
        pad = pt[-1]
        if pad + 1 > len(pt):
            raise HybridError("bad caBLE padding")
        return pt[: len(pt) - pad - 1]


def initiator_message(qr: QRSession, psk: bytes):
    noise = Noise(b"Noise_KNpsk0_P256_AESGCM_SHA256")
    noise.mix_hash(b"\x01")
    noise.mix_hash(qr.public_uncompressed)
    noise.mix_key_and_hash(psk)
    eph = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    noise.mix_hash(eph_pub)
    noise.mix_key(eph_pub)
    ct = noise.encrypt_and_hash(b"")
    return noise, eph, eph_pub + ct


def process_response(noise: Noise, eph, qr: QRSession, response: bytes) -> Crypter:
    if len(response) != 65 + 16:
        raise HybridError("bad handshake response size")
    peer_bytes, ct = response[:65], response[65:]
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_bytes)
    noise.mix_hash(peer_bytes)
    noise.mix_key(peer_bytes)
    noise.mix_key(eph.exchange(ec.ECDH(), peer))
    noise.mix_key(qr.identity.exchange(ec.ECDH(), peer))
    if noise.decrypt_and_hash(ct) != b"":
        raise HybridError("unexpected handshake payload")
    write_key, read_key = noise.traffic_keys()
    return Crypter(read_key, write_key)


# --------------------------------------------------------------------------- #
# Tunnel + CTAP device
# --------------------------------------------------------------------------- #
class HybridDevice(CtapDevice):
    """A fido2 CtapDevice whose CBOR commands travel through the phone tunnel."""

    def __init__(self, ws, crypter: Crypter, get_info: bytes):
        self._ws, self._crypter, self.get_info_bytes = ws, crypter, get_info

    @classmethod
    def list_devices(cls, **kwargs):  # required by CtapDevice; this transport is never enumerated
        return iter(())

    @property
    def capabilities(self) -> int:
        return 0x04  # CBOR only (no MSG / U2F, no WINK)

    def call(self, cmd: int, data: bytes = b"", event: Event | None = None, on_keepalive: Callable | None = None) -> bytes:
        if cmd != 0x10:  # CTAPHID_CBOR
            raise HybridError("hybrid transport only carries CTAP2 (CBOR) commands")
        if data == b"\x04":  # authenticatorGetInfo: answered from the post-handshake copy
            return b"\x00" + self.get_info_bytes
        self._ws.send(self._crypter.encrypt(bytes([MSG_CTAP]) + data))
        while True:
            if event is not None and event.is_set():
                raise HybridError("cancelled")
            raw = self._ws.recv(timeout=300)
            msg = self._crypter.decrypt(raw if isinstance(raw, bytes) else raw.encode())
            kind, payload = msg[0], msg[1:]
            if kind == MSG_CTAP:
                return payload  # status byte + CBOR, exactly what fido2.Ctap2 expects
            if kind == MSG_UPDATE:
                continue
            raise HybridError(f"unexpected caBLE message type {kind}")

    def close(self) -> None:
        try:
            self._ws.send(self._crypter.encrypt(bytes([MSG_SHUTDOWN])))
        except Exception:
            pass
        try:
            self._ws.close()
        except Exception:
            pass


def connect_tunnel(qr: QRSession, eid: bytes) -> HybridDevice:
    from websockets.sync.client import connect

    routing_id, domain = eid_components(eid)
    host = decode_domain(domain)
    url = f"wss://{host}/cable/connect/{routing_id.hex()}/{qr.tunnel_id.hex()}"
    ws = connect(url, subprotocols=["fido.cable"], origin=f"wss://{host}", open_timeout=30)

    psk = derive(qr.secret, eid, PSK, 32)
    noise, eph, first = initiator_message(qr, psk)
    ws.send(first)
    response = ws.recv(timeout=60)
    crypter = process_response(noise, eph, qr, response)

    post = crypter.decrypt(ws.recv(timeout=60))
    try:
        info = cbor2.loads(post)
    except Exception:
        # revision 0: padded CBOR map; strip trailing zeros + count byte
        info = cbor2.loads(post.rstrip(b"\x00"))
    if not isinstance(info, dict) or 1 not in info:
        raise HybridError("phone did not send a CTAP getInfo response")
    return HybridDevice(ws, crypter, info[1])
