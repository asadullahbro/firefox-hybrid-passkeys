const $ = (id) => document.getElementById(id);
async function render() {
  const st = await browser.runtime.sendMessage({ op: "manage-status" });
  const list = $("list"); list.replaceChildren();
  if (!st.exists) { list.textContent = "No vault yet. It is created the first time a site asks for a passkey."; return; }
  if (!st.unlocked) { list.textContent = "Vault is locked. Unlock it from any passkey prompt."; return; }
  $("lock").hidden = false;
  const { items } = await browser.runtime.sendMessage({ op: "manage-list" });
  if (!items.length) list.textContent = "No passkeys saved yet.";
  for (const c of items) {
    const row = document.createElement("div"); row.className = "row";
    const t = document.createElement("div"); t.append(c.rpId);
    const s = document.createElement("small"); s.textContent = c.userName || ""; t.append(s);
    const b = document.createElement("button"); b.textContent = "Delete";
    b.onclick = async () => { if (confirm("Delete the passkey for " + c.rpId + "? You may lose access to that account.")) { await browser.runtime.sendMessage({ op: "manage-remove", id: c.id }); render(); } };
    row.append(t, b); list.append(row);
  }
}
$("lock").onclick = async () => { await browser.runtime.sendMessage({ op: "manage-lock" }); location.reload(); };
render();
