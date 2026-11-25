const api = globalThis.browser || globalThis.chrome;
api.history.onVisited.addListener(async (item) => {
  if (!item.url || !/^https?:\/\//i.test(item.url)) return;
  const { token } = await api.storage.local.get("token");
  if (!token) return;
  const url = new URL(item.url);
  url.search = "";
  url.hash = "";
  url.username = "";
  url.password = "";
  try {
    const response = await fetch("http://127.0.0.1:5003/v1/activity", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
      body: JSON.stringify({ type: "web_visit", application: "chromium",
        event_id: `${item.id}:${Math.trunc(item.lastVisitTime || 0)}`, value: url.toString() })
    });
    if (!response.ok) console.warn("KernelGuard receiver rejected web activity", response.status);
  } catch (error) { console.warn("KernelGuard receiver unavailable", error); }
});
