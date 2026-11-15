"use strict";
// Messages from content scripts (web pages' tabs) and the unlock window.
// Origin is taken from the sender tab, never from page-supplied data.

let unlockWaiters = [];
let unlockWinId = null;

function settleWaiters(ok) { const w = unlockWaiters; unlockWaiters = []; w.forEach((r) => r(ok)); }

async function openUnlockWindow() {
  const mode = (await Vault.exists()) ? "unlock" : "setup";
  const ok = new Promise((res) => unlockWaiters.push(res));
  if (unlockWinId === null) {
    const w = await browser.windows.create({ url: browser.runtime.getURL("unlock.html") + "?mode=" + mode, type: "popup", width: 420, height: 330 });
    unlockWinId = w.id;
  } else {
    browser.windows.update(unlockWinId, { focused: true });
  }
  return ok;
}
browser.windows.onRemoved.addListener((id) => {
  if (id === unlockWinId) { unlockWinId = null; settleWaiters(Vault.unlocked); }
});

const fail = (e) => ({ error: { name: e.name || "Error", message: e.message || String(e) } });

browser.runtime.onMessage.addListener((msg, sender) => {
  const isExt = sender.url && sender.url.startsWith(browser.runtime.getURL(""));
  const origin = !isExt && sender.url ? new URL(sender.url).origin : null; // sender.url = the page frame that sent it
  return (async () => {
    try {
      switch (msg.op) {
        // --- from the unlock window only ---
        case "setup": if (!isExt) throw new Error("forbidden"); await Vault.setup(msg.pass); settleWaiters(true); return { ok: true };
        case "unlock": if (!isExt) throw new Error("forbidden"); await Vault.unlock(msg.pass); settleWaiters(true); return { ok: true };
        case "manage-list": if (!isExt) throw new Error("forbidden"); return { items: Authenticator.all(), unlocked: Vault.unlocked };
        case "manage-remove": if (!isExt) throw new Error("forbidden"); await Authenticator.remove(msg.id); return { ok: true };
        case "manage-lock": if (!isExt) throw new Error("forbidden"); Vault.lock(); return { ok: true };
        case "manage-status": if (!isExt) throw new Error("forbidden"); return { exists: await Vault.exists(), unlocked: Vault.unlocked };
        // --- from page tabs ---
        case "status": return { exists: await Vault.exists(), unlocked: Vault.unlocked };
        case "request-unlock": return { unlocked: await openUnlockWindow() };
        case "list": if (!origin) throw new Error("no origin"); return { items: Authenticator.list(origin, msg.rpId, msg.allowIds) };
        case "create": if (!origin) throw new Error("no origin"); return { credential: await Authenticator.create(origin, msg.options) };
        case "get": if (!origin) throw new Error("no origin"); return { credential: await Authenticator.get(origin, msg.options, msg.credentialId) };
        default: throw new Error("unknown op");
      }
    } catch (e) { return fail(e); }
  })();
});

// Phone (QR / hybrid) via the native host.
browser.runtime.onConnect.addListener((port) => {
  if (port.name !== "pkqr") return;
  const origin = new URL(port.sender.url).origin;
  console.log("[pkqr] connectNative for", origin);
  let native;
  try { native = browser.runtime.connectNative("passkey_qr_host"); }
  catch (e) { console.log("[pkqr] connectNative threw", e); port.postMessage({ event: "error", message: "connectNative failed: " + e.message }); return; }
  native.onMessage.addListener((m) => { console.log("[pkqr] host says", m.event); port.postMessage(m); });
  native.onDisconnect.addListener(() => {
    const e = browser.runtime.lastError;
    console.log("[pkqr] native disconnected", e && e.message);
    try { port.postMessage({ event: "error", message: e ? e.message : "native host exited" }); } catch (_) {}
  });
  port.onMessage.addListener((m) => {
    if (m.op === "start") m.origin = origin;
    native.postMessage(m);
  });
  port.onDisconnect.addListener(() => { try { native.disconnect(); } catch (_) {} });
});
