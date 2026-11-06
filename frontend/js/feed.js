window.CTIP = window.CTIP || {};

CTIP.feed = (() => {
  const MAX_ITEMS = 60;
  let container = null;
  let activeFilters = { severity_label: "", threat_type: "" };

  function init() {
    container = document.getElementById("feed-list");
  }

  function setFilters(filters) {
    activeFilters = { severity_label: filters.severity_label || "", threat_type: filters.threat_type || "" };
  }

  function matchesActiveFilters(event) {
    if (activeFilters.severity_label && event.severity_label !== activeFilters.severity_label) return false;
    if (activeFilters.threat_type && event.threat_type !== activeFilters.threat_type) return false;
    return true;
  }

  function timeAgo(iso) {
    if (!iso) return "";
    const diffMs = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str ?? "";
    return div.innerHTML;
  }

  function itemHtml(event) {
    const sev = event.severity_label || "low";
    const demoTag = event.is_synthetic ? '<span class="tag tag-demo">demo</span>' : "";
    return `
      <div class="feed-item" data-id="${event.id}">
        <span class="feed-sev-bar ${sev}"></span>
        <div class="feed-item-body">
          <div class="feed-item-top">
            <span class="feed-ioc" title="${escapeHtml(event.ioc_value)}">${escapeHtml(event.ioc_value)}</span>
            <span class="feed-time">${timeAgo(event.last_seen)}</span>
          </div>
          <div class="feed-item-meta">
            <span class="tag tag-${sev}">${sev}</span>
            <span class="tag tag-neutral">${escapeHtml(event.threat_type)}</span>
            ${event.malware_family ? `<span class="tag tag-neutral">${escapeHtml(event.malware_family)}</span>` : ""}
            ${demoTag}
          </div>
        </div>
      </div>`;
  }

  function renderInitial(events) {
    if (!container) return;
    if (!events.length) {
      const hasFilters = activeFilters.severity_label || activeFilters.threat_type;
      container.innerHTML = hasFilters
        ? '<div class="empty-state">No events match the current filters.</div>'
        : '<div class="empty-state">No threat events yet — waiting on the first ingestion cycle.</div>';
      return;
    }
    container.innerHTML = events.map(itemHtml).join("");
  }

  function prependEvents(events) {
    if (!container || !events || !events.length) return;
    const matching = events.filter(matchesActiveFilters);
    if (!matching.length) return;

    const emptyState = container.querySelector(".empty-state");
    if (emptyState) container.innerHTML = "";

    const html = matching.map(itemHtml).join("");
    container.insertAdjacentHTML("afterbegin", html);

    // Trim to keep the DOM light on a long-running dashboard
    while (container.children.length > MAX_ITEMS) {
      container.removeChild(container.lastElementChild);
    }
  }

  return { init, renderInitial, prependEvents, setFilters };
})();
