const fs = require("fs"), path = require("path"), vm = require("vm"), nodeCrypto = require("crypto");
const store = {};
const ctx = { browser: { storage: { local: { get: async (k) => (typeof k === "string" ? { [k]: store[k] } : {}), set: async (o) => Object.assign(store, JSON.parse(JSON.stringify(o))) } } },
  crypto: nodeCrypto.webcrypto, TextEncoder, TextDecoder, btoa, atob, URL, setTimeout, clearTimeout, console, Uint8Array, Map, DataView };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/authenticator.js"), "utf8") + "\nthis.A=Authenticator;this.V=Vault;this.B=B64;", ctx);
const { A, V, B } = ctx;
(async () => {
  const assert = require("assert");
  await assert.rejects(() => A.create("https://example.com", {}), /locked/);
  await V.setup("correct horse");
  const origin = "https://login.example.com";
  const chal = B.enc(nodeCrypto.randomBytes(32));
  const c = await A.create(origin, { rp: { id: "example.com" }, user: { id: B.enc(Buffer.from("u1")), name: "sad", displayName: "Sad" }, challenge: chal, pubKeyCredParams: [{ alg: -7 }], excludeCredentials: [] });
  // parse authData from attestationObject and check rpIdHash / flags / credId
  const ad = Buffer.from(B.dec(c.response.authenticatorData));
  assert.deepStrictEqual(ad.subarray(0, 32), nodeCrypto.createHash("sha256").update("example.com").digest());
  assert.strictEqual(ad[32], 0x45);
  assert.strictEqual(ad.readUInt16BE(53), 32);
  assert.deepStrictEqual(ad.subarray(55, 87), Buffer.from(B.dec(c.id)));
  // assertion + signature verification with the SPKI public key
  const g = await A.get(origin, { rpId: "example.com", challenge: chal, allowCredentials: [] }, c.id);
  const pub = nodeCrypto.createPublicKey({ key: Buffer.from(B.dec(c.response.publicKey)), format: "der", type: "spki" });
  const gad = Buffer.from(B.dec(g.response.authenticatorData)), cdj = Buffer.from(B.dec(g.response.clientDataJSON));
  assert.strictEqual(gad[32], 0x05); assert.strictEqual(gad.readUInt32BE(33), 1);
  const ok = nodeCrypto.verify("sha256", Buffer.concat([gad, nodeCrypto.createHash("sha256").update(cdj).digest()]), pub, Buffer.from(B.dec(g.response.signature)));
  assert.ok(ok, "signature must verify (DER)");
  assert.strictEqual(JSON.parse(cdj).origin, origin);
  // wrong rpId rejected, lock + wrong passphrase + unlock persists
  await assert.rejects(() => A.create("https://evil.com", { rp: { id: "example.com" }, user: { id: "x", name: "n" }, challenge: chal, pubKeyCredParams: [{ alg: -7 }] }), /RP ID/);
  const blob = JSON.stringify(store.vault); assert.ok(!blob.includes("jwk") && !blob.includes("example.com"), "vault must be encrypted");
  V.lock();
  await assert.rejects(() => V.unlock("wrong pass"), /Wrong passphrase/);
  await V.unlock("correct horse");
  assert.strictEqual(A.list(origin, "example.com").length, 1);
  console.log("authenticator ok");
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
