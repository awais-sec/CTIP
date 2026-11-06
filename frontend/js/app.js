(function () {
  const REFRESH_MS = 60000;

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str ?? "";
    return div.innerHTML;
  }

  function fmtNumber(n) {
    return new Intl.NumberFormat().format(n ?? 0);
  }

  // ---------------- Stat cards ----------------
  function renderStats(overview) {
    document.querySelectorAll("[data-stat]").forEach((el) => {
      const key = el.dataset.stat;
      const valueEl = el.querySelector(".stat-value");
      const map = { kev_count: "kev_count" };
      valueEl.textContent = fmtNumber(overview[map[key] || key]);
    });

    const demoBanner = document.getElementById("demo-banner");
    demoBanner.classList.toggle("hidden", !overview.demo_mode_active);
    if (overview.demo_mode_active) {
      const total = overview.total_iocs || 1;
      const pct = Math.round((overview.synthetic_count / total) * 100);
      const isFull = overview.synthetic_count >= total;
      demoBanner.querySelector("span:last-child").textContent = isFull
        ? "DEMO MODE — live feeds returned no data this cycle, so every indicator below is synthetically generated for demonstration. Configure live feeds in .env to ingest real threat intelligence."
        : `PARTIAL DEMO DATA — ${overview.synthetic_count} of ${overview.total_iocs} indicators (${pct}%) are synthetically generated to fill out sparse live results; the rest are real. Items are tagged "demo" throughout.`;
    }
  }

  // ---------------- MITRE matrix ----------------
  function renderMitre(matrix) {
    const el = document.getElementById("mitre-matrix");
    const sorted = [...matrix].sort((a, b) => b.count - a.count);
    el.innerHTML = sorted
      .map(
        (t) => `
      <div class="mitre-cell" style="opacity:${t.count ? 1 : 0.45}">
        <div class="mitre-cell-id">${t.id}</div>
        <div class="mitre-cell-name">${escapeHtml(t.name)}</div>
        <div class="mitre-cell-tactic">${escapeHtml(t.tactic)}</div>
        <div class="mitre-cell-count">${t.count}</div>
      </div>`
      )
      .join("");
  }

  // ---------------- CVE list ----------------
  function renderCves(cves) {
    const el = document.getElementById("cve-list");
    if (!cves.length) {
      el.innerHTML = '<div class="empty-state">No CVE data yet.</div>';
      return;
    }
    el.innerHTML = cves
      .map(
        (c) => `
      <div class="cve-item">
        <div class="cve-top">
          <span class="cve-id">${escapeHtml(c.cve_id)}</span>
          <span class="cve-score">${c.cvss_score != null ? "CVSS " + c.cvss_score : ""} ${c.severity ? "· " + c.severity : ""}</span>
        </div>
        ${c.description ? `<div class="cve-desc">${escapeHtml(c.description.slice(0, 180))}${c.description.length > 180 ? "…" : ""}</div>` : ""}
        <div class="cve-badges">
          ${c.is_kev ? '<span class="badge-kev">CISA KEV</span>' : ""}
          ${c.ransomware_use ? '<span class="badge-ransomware">Ransomware use</span>' : ""}
          ${c.is_synthetic ? '<span class="tag tag-demo">demo</span>' : ""}
        </div>
      </div>`
      )
      .join("");
  }

  async function loadCves(kevOnly) {
    const cves = await CTIP.api.getCves({ limit: 40, kev_only: kevOnly || undefined });
    renderCves(cves);
    return cves;
  }

  // ---------------- Feed status ----------------
  function renderFeedStatus(statuses) {
    const el = document.getElementById("feed-status");
    if (!statuses.length) {
      el.innerHTML = '<div class="empty-state">Waiting for the first ingestion cycle…</div>';
      return;
    }
    el.innerHTML = statuses
      .map((s) => {
        const cls = s.last_run_at == null ? "status-pending" : s.last_success ? "status-ok" : "status-fail";
        const label = s.last_run_at == null ? "pending" : s.last_success ? `${s.events_ingested} events` : "failed";
        return `
        <div class="feed-status-row">
          <span class="feed-status-name">${escapeHtml(s.feed_name)}</span>
          <span class="${cls}">${label}</span>
        </div>`;
      })
      .join("");
  }

  // ---------------- Alert history ----------------
  function renderAlerts(alerts) {
    const el = document.getElementById("alert-history");
    if (!alerts.length) {
      el.innerHTML = '<div class="empty-state">No alerts fired yet.</div>';
      return;
    }
    el.innerHTML = alerts
      .map(
        (a) => `
      <div class="alert-item">
        <div>${escapeHtml(a.message.split("\n")[0])}</div>
        <div class="alert-item-meta">${a.channel} · ${a.severity} · ${new Date(a.sent_at).toLocaleString()}</div>
      </div>`
      )
      .join("");
  }

  // ---------------- Search ----------------
  function initSearch() {
    const input = document.getElementById("search-input");
    const results = document.getElementById("search-results");
    let debounceTimer = null;

    input.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      const q = input.value.trim();
      if (q.length < 2) {
        results.classList.add("hidden");
        return;
      }
      debounceTimer = setTimeout(async () => {
        try {
          const res = await CTIP.api.search(q);
          renderSearchResults(res);
        } catch (e) { /* ignore */ }
      }, 250);
    });

    document.addEventListener("click", (e) => {
      if (!e.target.closest(".search-wrap")) results.classList.add("hidden");
    });

    function renderSearchResults(res) {
      const total = res.threats.length + res.cves.length;
      if (!total) {
        results.innerHTML = '<div class="search-empty">No matches</div>';
        results.classList.remove("hidden");
        return;
      }
      const threatItems = res.threats
        .slice(0, 8)
        .map(
          (t) => `
        <div class="search-result-item">
          <div class="search-result-title">${escapeHtml(t.ioc_value)}</div>
          <div class="search-result-meta">${t.threat_type} · ${t.severity_label} · ${t.source_feed}</div>
        </div>`
        )
        .join("");
      const cveItems = res.cves
        .slice(0, 8)
        .map(
          (c) => `
        <div class="search-result-item">
          <div class="search-result-title">${escapeHtml(c.cve_id)}</div>
          <div class="search-result-meta">${c.severity || ""} ${c.is_kev ? "· CISA KEV" : ""}</div>
        </div>`
        )
        .join("");
      results.innerHTML = threatItems + cveItems;
      results.classList.remove("hidden");
    }
  }

  // ---------------- Live pill ----------------
  function setLivePill(connected) {
    const pill = document.getElementById("live-pill");
    const text = document.getElementById("live-pill-text");
    pill.classList.toggle("connected", connected);
    text.textContent = connected ? "LIVE" : "RECONNECTING…";
  }

  // ---------------- Feed filters ----------------
  let lastTotalEvents = 0;

  function getActiveFilters() {
    return {
      severity_label: document.getElementById("filter-severity").value,
      threat_type: document.getElementById("filter-type").value,
    };
  }

  function populateTypeOptions(topThreatTypes) {
    const select = document.getElementById("filter-type");
    const current = select.value;
    const existing = new Set(Array.from(select.options).map((o) => o.value));

    topThreatTypes.forEach((t) => {
      if (!existing.has(t.threat_type)) {
        const opt = document.createElement("option");
        opt.value = t.threat_type;
        opt.textContent = t.threat_type;
        select.appendChild(opt);
      }
    });
    select.value = current; // preserve selection across repopulation
  }

  function updateFeedCountLabel(shownCount, filters) {
    const label = document.getElementById("feed-count-label");
    const isFiltered = filters.severity_label || filters.threat_type;
    label.textContent = isFiltered
      ? `${fmtNumber(shownCount)} of ${fmtNumber(lastTotalEvents)} events`
      : `${fmtNumber(lastTotalEvents)} events`;
  }

  async function loadFeed() {
    const filters = getActiveFilters();
    CTIP.feed.setFilters(filters);
    const threats = await CTIP.api.getThreats({ limit: 40, ...filters });
    CTIP.feed.renderInitial(threats);
    updateFeedCountLabel(threats.length, filters);
  }

  function initFeedFilters() {
    document.getElementById("filter-severity").addEventListener("change", () => {
      loadFeed().catch((err) => console.error("Filter reload failed:", err));
    });
    document.getElementById("filter-type").addEventListener("change", () => {
      loadFeed().catch((err) => console.error("Filter reload failed:", err));
    });
    document.getElementById("filter-clear").addEventListener("click", () => {
      document.getElementById("filter-severity").value = "";
      document.getElementById("filter-type").value = "";
      loadFeed().catch((err) => console.error("Filter reload failed:", err));
    });
  }

  // ---------------- Full refresh ----------------
  async function fullRefresh() {
    const [overview, mapPoints, mitre, cves, feedStatuses, alerts, campaigns] = await Promise.all([
      CTIP.api.getOverview(),
      CTIP.api.getMapPoints(),
      CTIP.api.getMitreMatrix(),
      loadCves(document.getElementById("kev-only-toggle").checked),
      CTIP.api.getFeedStatus(),
      CTIP.api.getAlertHistory(),
      CTIP.api.getCampaigns(),
    ]);

    lastTotalEvents = overview.total_iocs;
    renderStats(overview);
    CTIP.map.render(mapPoints);
    CTIP.charts.renderTrend(overview.severity_trend);
    CTIP.charts.renderTypes(overview.top_threat_types);
    CTIP.charts.renderCountries(overview.top_countries);
    renderMitre(mitre);
    renderFeedStatus(feedStatuses);
    renderAlerts(alerts);
    CTIP.campaigns.render(campaigns);
    populateTypeOptions(overview.top_threat_types);

    await loadFeed();
  }

  // ---------------- Init ----------------
  document.addEventListener("DOMContentLoaded", async () => {
    await CTIP.map.init();
    CTIP.feed.init();
    initSearch();
    initFeedFilters();

    document.getElementById("export-csv").addEventListener("click", () => {
      window.open(CTIP.api.exportCsvUrl(), "_blank");
    });

    document.getElementById("kev-only-toggle").addEventListener("change", (e) => {
      loadCves(e.target.checked);
    });

    fullRefresh().catch((err) => console.error("Initial load failed:", err));
    setInterval(() => fullRefresh().catch((err) => console.error("Refresh failed:", err)), REFRESH_MS);

    CTIP.ws.onEvents = (events) => {
      CTIP.feed.prependEvents(events);
    };
    CTIP.ws.connect(setLivePill);
  });
})();
