// Thin API client. Uses relative paths so this dashboard works whether it's
// served by the FastAPI backend directly, or embedded elsewhere and pointed
// at a different API base via window.CTIP_API_BASE.
const CTIP = window.CTIP || {};
CTIP.API_BASE = window.CTIP_API_BASE || "";

CTIP.api = {
  async _get(path, params) {
    const url = new URL(CTIP.API_BASE + path, window.location.origin);
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
      });
    }
    const resp = await fetch(url.toString());
    if (!resp.ok) throw new Error(`API error ${resp.status}: ${path}`);
    return resp.json();
  },

  getOverview() { return this._get("/api/stats/overview"); },
  getFeedStatus() { return this._get("/api/stats/feeds"); },
  getAlertHistory() { return this._get("/api/stats/alerts", { limit: 20 }); },
  getThreats(params) { return this._get("/api/threats", params); },
  getMapPoints() { return this._get("/api/map/points", { limit: 500 }); },
  getMitreMatrix() { return this._get("/api/mitre/matrix"); },
  getCves(params) { return this._get("/api/cve", params); },
  getCampaigns() { return this._get("/api/campaigns", { limit: 300 }); },
  search(q) { return this._get("/api/search", { q }); },
  exportCsvUrl() { return CTIP.API_BASE + "/api/export/threats.csv"; },
};

CTIP.ws = {
  socket: null,
  onEvents: null,

  connect(onOpenChange) {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const base = CTIP.API_BASE
      ? CTIP.API_BASE.replace(/^http/, "ws")
      : `${proto}//${window.location.host}`;

    const url = `${base}/ws/live`;
    try {
      this.socket = new WebSocket(url);
    } catch (e) {
      onOpenChange(false);
      return;
    }

    this.socket.onopen = () => onOpenChange(true);
    this.socket.onclose = () => {
      onOpenChange(false);
      setTimeout(() => this.connect(onOpenChange), 4000); // auto-reconnect
    };
    this.socket.onerror = () => this.socket.close();
    this.socket.onmessage = (evt) => {
      try {
        const payload = JSON.parse(evt.data);
        if (payload.type === "threat_events" && this.onEvents) {
          this.onEvents(payload.data);
        }
      } catch (e) { /* ignore malformed frames */ }
    };
  },
};

window.CTIP = CTIP;
