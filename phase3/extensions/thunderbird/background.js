const pending = new Map();
function report(stage, extra = {}) {
  browser.storage.local.set({ deliveryStatus: { stage, time: new Date().toISOString(), ...extra } })
    .catch(error => console.warn("KernelGuard could not save delivery status", error));
}
function domains(details) {
  const addresses = [details.to, details.cc, details.bcc]
    .flatMap(value => Array.isArray(value) ? value : value ? [value] : []);
  return [...new Set(addresses.flatMap(value => {
    const matches = String(value).match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi) || [];
    return matches.map(address => address.slice(address.lastIndexOf("@") + 1).toLowerCase());
  }))];
}
browser.compose.onBeforeSend.addListener((tab, details) => {
  const value = domains(details);
  pending.set(tab.id, value);
  report("beforeSend", { domainCount: value.length });
});
browser.compose.onAfterSend.addListener(async (tab, sendInfo) => {
  const value = sendInfo.details ? domains(sendInfo.details) : pending.get(tab.id);
  pending.delete(tab.id);
  report("afterSend", { mode: sendInfo.mode, hasError: Boolean(sendInfo.error),
    domainCount: value?.length || 0 });
  if (sendInfo.error || sendInfo.mode !== "sendNow" || !value?.length) return;
  const { token } = await browser.storage.local.get("token");
  if (!token) { report("missingToken"); return; }
  const eventId = sendInfo.headerMessageId || `${Date.now()}:${crypto.randomUUID()}`;
  const body = JSON.stringify({ type: "email_sent", application: "thunderbird",
    event_id: eventId.replace(/[^A-Za-z0-9:_-]/g, "_").slice(0, 160), value });
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch("http://127.0.0.1:5003/v1/activity", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body
      });
      report("receiverResponse", { status: response.status, attempt });
      if (response.ok) return;
      if (response.status !== 503 || attempt === 3) {
        console.warn("KernelGuard receiver rejected mail activity", response.status);
        return;
      }
    } catch (error) {
      report("receiverUnavailable", { message: String(error), attempt });
      if (attempt === 3) {
        console.warn("KernelGuard receiver unavailable", error);
        return;
      }
    }
    await new Promise(resolve => setTimeout(resolve, attempt * 2000));
  }
});
report("ready");
