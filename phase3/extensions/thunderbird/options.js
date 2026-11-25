browser.storage.local.get("token").then(({ token }) => { document.querySelector("#token").value = token || ""; });
browser.storage.local.get("deliveryStatus").then(({ deliveryStatus }) => {
  if (!deliveryStatus) return;
  const parts = [deliveryStatus.time, deliveryStatus.stage];
  if (deliveryStatus.mode) parts.push(`mode: ${deliveryStatus.mode}`);
  if (deliveryStatus.domainCount !== undefined) parts.push(`domains: ${deliveryStatus.domainCount}`);
  if (deliveryStatus.status) parts.push(`receiver HTTP: ${deliveryStatus.status}`);
  if (deliveryStatus.attempt) parts.push(`attempt: ${deliveryStatus.attempt}`);
  if (deliveryStatus.hasError) parts.push("send failed");
  if (deliveryStatus.message) parts.push(deliveryStatus.message);
  document.querySelector("#delivery-status").textContent = parts.join(" · ");
});
document.querySelector("#save").addEventListener("click", async () => {
  const token = document.querySelector("#token").value.trim();
  if (token.length < 32) { document.querySelector("#status").textContent = "Use at least 32 characters."; return; }
  await browser.storage.local.set({ token });
  document.querySelector("#status").textContent = "Saved locally in this Thunderbird profile.";
});
