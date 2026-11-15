const mode = new URLSearchParams(location.search).get("mode");
const $ = (id) => document.getElementById(id);
if (mode === "setup") {
  $("title").textContent = "Create your passkey vault";
  $("hint").textContent = "This passphrase encrypts every passkey stored in this browser. If you forget it the passkeys cannot be recovered.";
  $("p2").hidden = false; $("go").textContent = "Create vault";
} else {
  $("title").textContent = "Unlock passkey vault";
  $("hint").textContent = "Enter your passphrase to use stored passkeys.";
  $("go").textContent = "Unlock";
}
$("f").onsubmit = async (e) => {
  e.preventDefault();
  $("err").textContent = "";
  const pass = $("p1").value;
  if (mode === "setup") {
    if (pass.length < 8) return ($("err").textContent = "Use at least 8 characters.");
    if (pass !== $("p2").value) return ($("err").textContent = "Passphrases don't match.");
  }
  $("go").disabled = true;
  const r = await browser.runtime.sendMessage({ op: mode === "setup" ? "setup" : "unlock", pass });
  if (r && r.error) { $("err").textContent = r.error.name === "NotAllowedError" ? "Wrong passphrase." : r.error.message; $("go").disabled = false; $("p1").select(); }
  else window.close();
};
