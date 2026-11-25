const api = globalThis.browser || globalThis.chrome;
api.storage.local.get("token").then(({ token }) => { document.querySelector("#token").value = token || ""; });
document.querySelector("#save").addEventListener("click", async () => {
  const token = document.querySelector("#token").value.trim();
  if (token.length < 32) { document.querySelector("#status").textContent = "Use at least 32 characters."; return; }
  await api.storage.local.set({ token });
  document.querySelector("#status").textContent = "Saved locally in this browser profile.";
});
