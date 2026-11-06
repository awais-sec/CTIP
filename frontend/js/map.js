window.CTIP = window.CTIP || {};

CTIP.map = (() => {
  let leafletMap = null;
  let markerLayer = null;

  const SEV_COLOR = {
    critical: "#e0342a",
    high: "#e05c2a",
    medium: "#c8971a",
    low: "#00d4ff",
  };

  async function init() {
    leafletMap = L.map("map", {
      worldCopyJump: true,
      zoomControl: true,
      attributionControl: true,
      minZoom: 2,
    }).setView([20, 10], 2);

    const mapEl = document.getElementById("map");
    let useNativeDark = false;

    try {
      const config = await fetch("/api/config/public").then((r) => r.json());
      if (config.maptiler_api_key) {
        // A real dark cartographic style, purpose-built for dashboards —
        // no CSS filter hacks needed. Free tier: 100k tile loads/month,
        // no card required, from https://cloud.maptiler.com
        L.tileLayer(
          `https://api.maptiler.com/maps/${config.map_style}/{z}/{x}/{y}.png?key=${config.maptiler_api_key}`,
          {
            attribution:
              '&copy; <a href="https://www.maptiler.com/copyright/" target="_blank">MapTiler</a> &copy; <a href="https://www.openstreetmap.org/copyright" target="_blank">OpenStreetMap</a> contributors',
            maxZoom: 19,
            tileSize: 512,
            zoomOffset: -1,
          }
        ).addTo(leafletMap);
        useNativeDark = true;
      }
    } catch (e) {
      // Config fetch failed for any reason — fall through to the free
      // no-key fallback below rather than leaving the map blank.
    }

    if (!useNativeDark) {
      // Fallback: plain OpenStreetMap tiles, the one raster provider that
      // remains genuinely free with no signup. Recolored via a CSS filter
      // scoped to .map:not(.map-native-dark) (see style.css), so markers/
      // popups stay full-color and unaffected either way.
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        subdomains: "abc",
        maxZoom: 19,
      }).addTo(leafletMap);
    }

    mapEl.classList.toggle("map-native-dark", useNativeDark);
    markerLayer = L.layerGroup().addTo(leafletMap);
  }

  function radiusForSeverity(score) {
    return 3 + Math.max(0, score) / 14;
  }

  function render(points) {
    if (!leafletMap) return;
    markerLayer.clearLayers();

    points.forEach((p) => {
      if (p.lat == null || p.lon == null) return;
      const color = SEV_COLOR[p.severity_label] || SEV_COLOR.low;

      const marker = L.circleMarker([p.lat, p.lon], {
        radius: radiusForSeverity(p.severity_score),
        color,
        weight: 1,
        fillColor: color,
        fillOpacity: 0.55,
        opacity: 0.9,
      });

      const demoTag = p.is_synthetic
        ? '<div style="margin-top:4px;color:#c8971a;letter-spacing:0.5px;">DEMO DATA</div>'
        : "";

      marker.bindPopup(
        `<strong>${escapeHtml(p.ioc_value)}</strong><br/>` +
          `${escapeHtml(p.threat_type)} · ${p.severity_label.toUpperCase()} (${p.severity_score})<br/>` +
          `${escapeHtml(p.country || "Unknown")}` +
          demoTag
      );

      marker.addTo(markerLayer);
    });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str ?? "";
    return div.innerHTML;
  }

  return { init, render };
})();
