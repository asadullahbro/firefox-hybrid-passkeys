import os, sys, struct, hashlib, hmac
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))
import hybrid as h
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def digits_to_bytes(s):
    widths = {3:1,5:2,8:3,10:4,13:5,15:6,17:7}
    out=b""
    for i in range(0,len(s),17):
        c=s[i:i+17]; n=widths[len(c)]
        out+=int(c).to_bytes(8,"little")[:n]
    return out

def encrypt_advert(eid, key):
    enc = Cipher(algorithms.AES(key[:32]), modes.ECB()).encryptor()
    ct = enc.update(eid)+enc.finalize()
    return ct + hmac.new(key[32:], ct, hashlib.sha256).digest()[:4]

def respond(qr, psk, msg):
    n = h.Noise(b"Noise_KNpsk0_P256_AESGCM_SHA256")
    n.mix_hash(b"\x01"); n.mix_hash(qr.public_uncompressed); n.mix_key_and_hash(psk)
    pe = msg[:65]; n.mix_hash(pe); n.mix_key(pe)
    assert n.decrypt_and_hash(msg[65:]) == b""
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pe)
    e = ec.generate_private_key(ec.SECP256R1())
    ep = e.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    n.mix_hash(ep); n.mix_key(ep)
    n.mix_key(e.exchange(ec.ECDH(), peer))
    # initiator's identity public key
    ident = qr.identity.public_key()
    n.mix_key(e.exchange(ec.ECDH(), ident))
    resp = ep + n.encrypt_and_hash(b"")
    rk, wk = n.traffic_keys()   # k1 (initiator writes), k2
    return resp, h.Crypter(read_key=rk, write_key=wk)

def test_all():
    qr = h.QRSession.new("ga")
    t = qr.qr_text(); assert t.startswith("FIDO:/") and t[6:].isdigit()
    import cbor2
    m = cbor2.loads(digits_to_bytes(t[6:]))
    assert m[0]==qr.public_compressed and m[1]==qr.secret and m[5]=="ga"
    eid = bytes([0]) + os.urandom(10) + b"\x01\x02\x03" + struct.pack("<H", 0)
    adv = encrypt_advert(eid, qr.eid_key)
    assert h.decrypt_advert(adv, qr.eid_key) == eid
    assert h.decrypt_advert(adv[:19]+b"\x00", qr.eid_key) is None
    assert h.eid_components(eid) == (b"\x01\x02\x03", 0)
    assert h.decode_domain(0)=="cable.ua5v.com" and h.decode_domain(300).startswith("cable.")
    psk = h.derive(qr.secret, eid, h.PSK, 32)
    noise, eph, first = h.initiator_message(qr, psk)
    resp, phone = respond(qr, psk, first)
    cr = h.process_response(noise, eph, qr, resp)
    for i in range(3):
        assert phone.decrypt(cr.encrypt(b"hello%d"%i)) == b"hello%d"%i
        assert cr.decrypt(phone.encrypt(b"x"*70)) == b"x"*70
    print("ok")
test_all()
