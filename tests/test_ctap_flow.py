import os, sys, json, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))
import passkey_host as ph
from fido2.webauthn import AuthenticatorData, AttestedCredentialData, AttestationObject
from fido2.cose import ES256
from fido2.ctap2.base import AttestationResponse, AssertionResponse
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib, base64

key = ec.generate_private_key(ec.SECP256R1())
cose = ES256.from_cryptography_key(key.public_key())
cid = os.urandom(32)

class Info: options = {"uv": True, "rk": True}
class FakeCtap:
    info = Info()
    def make_credential(self, h, rp, user, params, excl, ext, options, event=None):
        assert rp["id"] == "webauthn.io" and params[0]["alg"] in (-8, -7, -257), params
        assert isinstance(user["id"], bytes) and options == {"rk": True, "uv": True}, (user, options)
        ad = AuthenticatorData.create(hashlib.sha256(b"webauthn.io").digest(), 0x45, 0, AttestedCredentialData.create(b"\0"*16, cid, cose))
        return AttestationResponse.__new__(AttestationResponse) if False else type("A", (), {"fmt": "none", "att_stmt": {}, "auth_data": ad})()
    def get_assertion(self, rp, h, allow, ext, options, event=None):
        ad = AuthenticatorData.create(hashlib.sha256(b"webauthn.io").digest(), 0x05, 3)
        return type("S", (), {"credential": {"id": cid, "type": "public-key"}, "auth_data": ad, "signature": b"sig", "user": {"id": b"u1"}})()

chal = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
create = {"kind": "create", "origin": "https://webauthn.io", "options": {
    "rp": {"name": "webauthn.io", "id": "webauthn.io"}, "user": {"id": "dTE", "name": "sad", "displayName": "sad"},
    "challenge": chal, "pubKeyCredParams": [{"type": "public-key", "alg": -7}], "excludeCredentials": [],
    "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"}, "extensions": {"credProps": True}}}
r = ph.do_ctap(FakeCtap(), create, threading.Event())
json.dumps(r)
assert r["id"] == ph.b64u(cid) and r["clientExtensionResults"] == {"credProps": {"rk": True}}
cdj = json.loads(base64.urlsafe_b64decode(r["response"]["clientDataJSON"] + "=="))
assert cdj["type"] == "webauthn.create" and cdj["origin"] == "https://webauthn.io" and cdj["challenge"] == chal
AttestationObject(base64.urlsafe_b64decode(r["response"]["attestationObject"] + "=="))
get = {"kind": "get", "origin": "https://webauthn.io", "options": {"challenge": chal, "rpId": "webauthn.io", "allowCredentials": [], "userVerification": "preferred"}}
g = ph.do_ctap(FakeCtap(), get, threading.Event())
json.dumps(g); assert g["response"]["userHandle"] == ph.b64u(b"u1")
print("ctap flow ok")
