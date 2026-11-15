"use strict";
// Software WebAuthn authenticator (ES256) with a passphrase-encrypted vault.
// Runs only in the background page; private keys never reach web pages.

// ---------- helpers ----------
const B64 = {
  enc(buf) {
    const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (const x of u) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  dec(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    const s = atob(str), u = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  },
};
const concat = (...a) => {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) { out.set(x, o); o += x.length; }
  return out;
};
const sha256 = async (d) => new Uint8Array(await crypto.subtle.digest("SHA-256", d));
class AuthError extends Error { constructor(name, msg) { super(msg || name); this.name = name; } }

// ---------- minimal CBOR encoder (ints, bytes, text, arrays, Maps) ----------
function cborHead(major, n) {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  if (n < 65536) return [(major << 5) | 25, n >> 8, n & 255];
  return [(major << 5) | 26, (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
}
function cbor(v) {
  if (typeof v === "number") return Uint8Array.from(v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v));
  if (typeof v === "string") { const b = new TextEncoder().encode(v); return concat(Uint8Array.from(cborHead(3, b.length)), b); }
  if (v instanceof Uint8Array) return concat(Uint8Array.from(cborHead(2, v.length)), v);
  if (Array.isArray(v)) return concat(Uint8Array.from(cborHead(4, v.length)), ...v.map(cbor));
  if (v instanceof Map) return concat(Uint8Array.from(cborHead(5, v.size)), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)]));
  throw new Error("cbor: unsupported type");
}

// ECDSA raw (r||s) -> ASN.1 DER
function rawToDer(sig) {
  const part = (x) => {
    let i = 0;
    while (i < x.length - 1 && x[i] === 0) i++;
    x = x.slice(i);
    if (x[0] & 0x80) x = concat(Uint8Array.of(0), x);
    return concat(Uint8Array.of(0x02, x.length), x);
  };
  const body = concat(part(sig.slice(0, 32)), part(sig.slice(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

// ---------- vault ----------
const KDF_ITER = 600000;
const AUTOLOCK_MS = 15 * 60 * 1000;
const Vault = {
  key: null, data: null, timer: null,

  async exists() { return !!(await browser.storage.local.get("vault")).vault; },
  get unlocked() { return !!this.data; },

  async _derive(pass, salt, iter) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  },
  _touch() { clearTimeout(this.timer); this.timer = setTimeout(() => this.lock(), AUTOLOCK_MS); },

  async setup(pass) {
    if (await this.exists()) throw new AuthError("InvalidStateError", "Vault already exists");
    if (typeof pass !== "string" || pass.length < 8) throw new AuthError("ConstraintError", "Passphrase must be at least 8 characters");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    this.key = await this._derive(pass, salt, KDF_ITER);
    this.data = { credentials: [] };
    this._salt = salt; this._iter = KDF_ITER;
    await this.save();
    this._touch();
  },

  async unlock(pass) {
    const { vault } = await browser.storage.local.get("vault");
    if (!vault) throw new AuthError("InvalidStateError", "No vault");
    const salt = B64.dec(vault.salt);
    const key = await this._derive(pass, salt, vault.iter);
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: B64.dec(vault.iv) }, key, B64.dec(vault.ct));
    } catch (_) { throw new AuthError("NotAllowedError", "Wrong passphrase"); }
    this.key = key; this.data = JSON.parse(new TextDecoder().decode(plain));
    this._salt = salt; this._iter = vault.iter;
    this._touch();
  },

  lock() { clearTimeout(this.timer); this.key = null; this.data = null; },

  async save() {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, this.key, new TextEncoder().encode(JSON.stringify(this.data)));
    await browser.storage.local.set({ vault: { v: 1, iter: this._iter, salt: B64.enc(this._salt), iv: B64.enc(iv), ct: B64.enc(new Uint8Array(ct)) } });
  },

  need() {
    if (!this.data) throw new AuthError("NotAllowedError", "Vault is locked");
    this._touch();
    return this.data;
  },
};

// ---------- WebAuthn logic ----------
function resolveRpId(origin, requested) {
  const url = new URL(origin);
  const host = url.hostname;
  const secure = url.protocol === "https:" || host === "localhost";
  if (!secure) throw new AuthError("SecurityError", "Passkeys need a secure origin");
  const rpId = requested || host;
  if (!(host === rpId || host.endsWith("." + rpId))) throw new AuthError("SecurityError", "RP ID does not match origin");
  if (!rpId.includes(".") && rpId !== "localhost") throw new AuthError("SecurityError", "RP ID is a public suffix");
  return rpId;
}

async function authData(rpId, flags, counter, attested) {
  const rpHash = await sha256(new TextEncoder().encode(rpId));
  const cnt = new Uint8Array(4);
  new DataView(cnt.buffer).setUint32(0, counter);
  let out = concat(rpHash, Uint8Array.of(flags), cnt);
  if (attested) {
    const len = new Uint8Array(2);
    new DataView(len.buffer).setUint16(0, attested.id.length);
    out = concat(out, new Uint8Array(16) /* AAGUID: all zero */, len, attested.id, attested.cose);
  }
  return out;
}

const Authenticator = {
  list(origin, requestedRpId, allowIds) {
    const rpId = resolveRpId(origin, requestedRpId);
    const creds = Vault.need().credentials.filter((c) => c.rpId === rpId && (!allowIds || !allowIds.length || allowIds.includes(c.id)));
    return creds.map((c) => ({ id: c.id, userName: c.userName, displayName: c.displayName, lastUsed: c.lastUsed || c.created }));
  },

  async create(origin, o) {
    const data = Vault.need();
    const rpId = resolveRpId(origin, o.rp && o.rp.id);
    if (!(o.pubKeyCredParams || []).some((p) => p.alg === -7)) throw new AuthError("NotSupportedError", "Only ES256 is supported");
    const excluded = (o.excludeCredentials || []).map((d) => d.id);
    if (data.credentials.some((c) => c.rpId === rpId && excluded.includes(c.id))) throw new AuthError("InvalidStateError", "Credential already registered");

    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)); // 04||x||y
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const id = crypto.getRandomValues(new Uint8Array(32));
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33, 65)]]));
    const ad = await authData(rpId, 0x45, 0, { id, cose }); // UP | UV | AT
    const attestationObject = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", ad]]));
    const clientDataJSON = JSON.stringify({ type: "webauthn.create", challenge: o.challenge, origin, crossOrigin: false });

    const idStr = B64.enc(id);
    data.credentials = data.credentials.filter((c) => !(c.rpId === rpId && c.userHandle === o.user.id));
    data.credentials.push({
      id: idStr, rpId, userHandle: o.user.id, userName: o.user.name, displayName: o.user.displayName,
      jwk, counter: 0, created: Date.now(),
    });
    await Vault.save();

    const ext = {};
    if (o.extensions && o.extensions.credProps) ext.credProps = { rk: true };
    return {
      id: idStr, rawId: idStr, type: "public-key", authenticatorAttachment: "platform",
      response: {
        clientDataJSON: B64.enc(new TextEncoder().encode(clientDataJSON)),
        attestationObject: B64.enc(attestationObject),
        authenticatorData: B64.enc(ad),
        publicKey: B64.enc(spki),
        publicKeyAlgorithm: -7,
        transports: ["internal"],
      },
      clientExtensionResults: ext,
    };
  },

  async get(origin, o, credentialId) {
    const data = Vault.need();
    const rpId = resolveRpId(origin, o.rpId);
    const allow = (o.allowCredentials || []).map((d) => d.id);
    const cred = data.credentials.find((c) => c.id === credentialId && c.rpId === rpId && (!allow.length || allow.includes(c.id)));
    if (!cred) throw new AuthError("NotAllowedError", "No matching passkey");

    cred.counter += 1;
    cred.lastUsed = Date.now();
    const ad = await authData(rpId, 0x05, cred.counter, null); // UP | UV
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: o.challenge, origin, crossOrigin: false }));
    const key = await crypto.subtle.importKey("jwk", cred.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, concat(ad, await sha256(clientDataJSON))));
    await Vault.save();
    return {
      id: cred.id, rawId: cred.id, type: "public-key", authenticatorAttachment: "platform",
      response: {
        clientDataJSON: B64.enc(clientDataJSON),
        authenticatorData: B64.enc(ad),
        signature: B64.enc(rawToDer(raw)),
        userHandle: cred.userHandle,
      },
      clientExtensionResults: {},
    };
  },

  async remove(id) {
    const data = Vault.need();
    data.credentials = data.credentials.filter((c) => c.id !== id);
    await Vault.save();
  },
  all() {
    return Vault.need().credentials.map((c) => ({ id: c.id, rpId: c.rpId, userName: c.userName, created: c.created, lastUsed: c.lastUsed }));
  },
};
