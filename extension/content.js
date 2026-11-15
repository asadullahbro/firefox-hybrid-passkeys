// Content script: hooks navigator.credentials and shows a chooser overlay.
// The overlay never handles secrets: the vault passphrase is typed in an
// extension window that web pages cannot observe.
(() => {
  // ---- Page hook via Firefox's content-script bridge (wrappedJSObject). ----
  // Unlike injecting a <script>, this runs synchronously at document_start and is
  // not affected by the page's CSP / Trusted Types (needed for sites like Google).
  const P = window.wrappedJSObject;
  const creds = P.navigator.credentials;
  const orig = { create: creds.create, get: creds.get };

  const b64enc = (src) => {
    const u = ArrayBuffer.isView(src) ? new Uint8Array(src.buffer, src.byteOffset, src.byteLength) : new Uint8Array(src);
    let s = "";
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const b64dec = (str) => {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    const s = atob(str), u = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  };
  const toBuf = (b64) => cloneInto(b64dec(b64).buffer, P);
  const list = (arr, f) => { const out = []; if (arr) for (let i = 0; i < arr.length; i++) out.push(f(arr[i])); return out; };
  const desc = (d) => ({ type: d.type, id: b64enc(d.id), transports: list(d.transports, (t) => String(t)) });

  function optionsToJSON(kind, pk) {
    const o = { challenge: b64enc(pk.challenge), timeout: pk.timeout, extensions: { credProps: !!(pk.extensions && pk.extensions.credProps) } };
    if (kind === "create") {
      o.rp = { id: pk.rp.id, name: pk.rp.name };
      o.user = { id: b64enc(pk.user.id), name: pk.user.name, displayName: pk.user.displayName };
      o.pubKeyCredParams = list(pk.pubKeyCredParams, (p) => ({ type: p.type, alg: p.alg }));
      o.excludeCredentials = list(pk.excludeCredentials, desc);
      const s = pk.authenticatorSelection;
      if (s) o.authenticatorSelection = { residentKey: s.residentKey, requireResidentKey: s.requireResidentKey, userVerification: s.userVerification, authenticatorAttachment: s.authenticatorAttachment };
      o.attestation = pk.attestation;
    } else {
      o.rpId = pk.rpId;
      o.userVerification = pk.userVerification;
      o.allowCredentials = list(pk.allowCredentials, desc);
    }
    return JSON.parse(JSON.stringify(o)); // drops undefined
  }

  function pageCredential(j) {
    const r = j.response;
    const resp = new P.Object();
    for (const k of ["clientDataJSON", "attestationObject", "authenticatorData", "signature"]) if (typeof r[k] === "string") resp[k] = toBuf(r[k]);
    if (typeof r.userHandle === "string") resp.userHandle = toBuf(r.userHandle);
    if (r.attestationObject) {
      const tr = r.transports || ["hybrid"];
      exportFunction(() => cloneInto(tr, P), resp, { defineAs: "getTransports" });
      exportFunction(() => toBuf(r.authenticatorData), resp, { defineAs: "getAuthenticatorData" });
      exportFunction(() => (typeof r.publicKey === "string" ? toBuf(r.publicKey) : null), resp, { defineAs: "getPublicKey" });
      exportFunction(() => (r.publicKeyAlgorithm === undefined ? -7 : r.publicKeyAlgorithm), resp, { defineAs: "getPublicKeyAlgorithm" });
    }
    const cred = new P.Object();
    cred.id = j.id;
    cred.rawId = toBuf(j.rawId || j.id);
    cred.type = "public-key";
    cred.authenticatorAttachment = j.authenticatorAttachment || "cross-platform";
    cred.response = resp;
    exportFunction(() => cloneInto(j.clientExtensionResults || {}, P), cred, { defineAs: "getClientExtensionResults" });
    exportFunction(() => cloneInto(j, P), cred, { defineAs: "toJSON" });
    return cred;
  }

  for (const kind of ["create", "get"]) {
    exportFunction(function (opts) {
      if (!opts || !opts.publicKey || opts.mediation === "conditional") return orig[kind].call(creds, opts);
      return new P.Promise(exportFunction((resolve, reject) => {
        let json;
        try { json = optionsToJSON(kind, opts.publicKey); }
        catch (e) { reject(new P.DOMException("Unsupported passkey options: " + e.message, "NotSupportedError")); return; }
        chooser({ kind, options: json }, (r) => {
          if (r.ok) resolve(pageCredential(r.credential));
          else if (r.fallback) resolve(orig[kind].call(creds, opts));
          else reject(new P.DOMException(r.message || "Cancelled", "NotAllowedError"));
        }).catch((e) => reject(new P.DOMException(String(e), "NotAllowedError")));
      }, P));
    }, creds, { defineAs: kind });
  }

  const send = (m) => browser.runtime.sendMessage(m);

  function el(tag, props = {}, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") e.className = v;
      else if (k.startsWith("on")) e[k] = v;
      else e.setAttribute(k, v);
    }
    for (const k of kids) e.append(k);
    return e;
  }

  const CSS = `
    .bg{position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;font:14px system-ui,sans-serif}
    .card{background:#fff;color:#111;border-radius:12px;padding:20px;width:340px;max-width:90vw;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.4)}
    h2{margin:0 0 6px;font-size:16px} p{margin:6px 0;color:#444}
    button{display:block;width:100%;margin:8px 0 0;padding:10px 12px;border-radius:8px;border:1px solid #888;background:#f4f4f4;color:#111;cursor:pointer;font:inherit;text-align:left}
    button.p{background:#0060df;color:#fff;border-color:#0060df}
    button.c{text-align:center;border-color:#ccc;background:#fff;color:#555}
    small{color:#666;display:block}
    canvas{margin:10px auto;display:block;image-rendering:pixelated;border:8px solid #fff}`;

  async function chooser({ kind, options }, reply) {
    const host = el("div");
    host.style.cssText = "all:initial !important;display:block !important;position:fixed !important;top:0 !important;left:0 !important;width:100vw !important;height:100vh !important;z-index:2147483647 !important;";
    const root = host.attachShadow({ mode: "closed" });
    const card = el("div", { class: "card" });
    root.append(el("style", {}, CSS), el("div", { class: "bg" }, card));
    (document.body || document.documentElement).appendChild(host);

    let port = null, finished = false;
    const done = (extra) => {
      if (finished) return;
      finished = true;
      try { if (port) { port.postMessage({ op: "cancel" }); port.disconnect(); } } catch (_) {}
      host.remove();
      reply(extra);
    };
    const cancel = () => done({ ok: false, message: "Cancelled" });
    const fail = (e) => done({ ok: false, message: (e && e.message) || String(e), name: e && e.name });

    const show = (title, msg, ...buttons) => { card.replaceChildren(el("h2", {}, title), el("p", {}, msg), ...buttons); };
    const btn = (label, onclick, cls = "", sub = "") => el("button", { class: cls, onclick }, label, ...(sub ? [el("small", {}, sub)] : []));

    const phone = () => {
      const qr = el("canvas");
      const msg = el("p", {}, "Starting…");
      card.replaceChildren(el("h2", {}, "Use your phone"), msg, qr, btn("Cancel", cancel, "c"));
      port = browser.runtime.connect({ name: "pkqr" });
      port.onMessage.addListener((m) => {
        if (m.event === "qr") {
          const n = m.matrix.length, scale = 6;
          qr.width = qr.height = n * scale;
          const g = qr.getContext("2d");
          g.fillStyle = "#fff"; g.fillRect(0, 0, qr.width, qr.height);
          g.fillStyle = "#000";
          m.matrix.forEach((row, y) => row.forEach((v, x) => v && g.fillRect(x * scale, y * scale, scale, scale)));
        } else if (m.event === "status") msg.textContent = m.text;
        else if (m.event === "done") done({ ok: true, credential: m.credential });
        else if (m.event === "error") done({ ok: false, message: m.message });
      });
      port.onDisconnect.addListener(() => done({ ok: false, message: "Phone helper not available" }));
      port.postMessage({ op: "start", kind, options });
      setTimeout(() => { if (!finished && msg.textContent === "Starting…") msg.textContent = "No reply from the phone helper after 10s. Firefox may be blocking it (snap sandbox)."; }, 10000);
    };
    const other = () => done({ ok: false, fallback: true });
    const footer = () => [btn("Use phone (QR code)", phone, "", "Scan with your phone"), btn("Security key / other", other), btn("Cancel", cancel, "c")];

    const run = async (op, extra) => {
      show("Working…", "");
      const r = await send({ op, options, ...extra });
      if (r.error) return fail(r.error);
      done({ ok: true, credential: r.credential });
    };

    async function main() {
      const st = await send({ op: "status" });
      if (!st.unlocked) {
        const label = st.exists ? "Unlock vault" : "Set up vault";
        return show("Use a passkey", st.exists ? "Your passkey vault is locked." : "Create a vault to store passkeys in this browser.",
          btn(label + "…", async () => {
            show("Waiting…", "Enter your passphrase in the window that opened.");
            const r = await send({ op: "request-unlock" });
            if (r && r.unlocked) main(); else show("Vault still locked", "", ...footer());
          }, "p", "Opens a separate window"),
          ...footer());
      }
      if (kind === "create") {
        const who = (options.user && (options.user.displayName || options.user.name)) || "";
        return show("Create a passkey", who ? "For " + who : "",
          btn("Save in this browser", () => run("create", {}), "p", "Encrypted with your vault passphrase"),
          ...footer());
      }
      const allowIds = (options.allowCredentials || []).map((d) => d.id);
      const r = await send({ op: "list", rpId: options.rpId, allowIds });
      if (r.error) return fail(r.error);
      const items = r.items.sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0));
      show("Sign in with a passkey", items.length ? "Choose an account." : "No saved passkey for this site.",
        ...items.map((c) => btn(c.displayName || c.userName || "Account", () => run("get", { credentialId: c.id }), "p", c.userName || "")),
        ...footer());
    }
    main().catch(fail);
  }
})();
