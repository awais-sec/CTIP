window.CTIP = window.CTIP || {};

CTIP.campaigns = (() => {
  let simulation = null;

  const SEV_COLOR = {
    critical: "#e0342a",
    high: "#e05c2a",
    medium: "#c8971a",
    low: "#00d4ff",
  };

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str ?? "";
    return div.innerHTML;
  }

  function severityForScore(score) {
    if (score >= 85) return "critical";
    if (score >= 65) return "high";
    if (score >= 40) return "medium";
    return "low";
  }

  function renderList(campaigns) {
    const el = document.getElementById("campaign-list");
    const label = document.getElementById("campaign-count-label");
    if (label) label.textContent = `${campaigns.length} cluster${campaigns.length === 1 ? "" : "s"}`;

    if (!campaigns.length) {
      el.innerHTML =
        '<div class="empty-state">No correlated campaigns yet — need at least 2 IOCs sharing a malware family or hosting network.</div>';
      return;
    }

    el.innerHTML = campaigns
      .map((c) => {
        const sev = severityForScore(c.max_severity);
        const kindLabel = c.kind === "malware_family" ? "malware family" : "shared infrastructure";
        const typeTags = c.threat_types
          .slice(0, 4)
          .map((t) => `<span class="tag tag-neutral">${escapeHtml(t)}</span>`)
          .join("");
        return `
        <div class="campaign-item">
          <div class="campaign-top">
            <span class="campaign-name">${escapeHtml(c.label)}</span>
            <span class="tag tag-${sev}">${sev}</span>
          </div>
          <div class="campaign-meta">${c.member_count} IOCs · ${escapeHtml(kindLabel)} · ${c.countries.length} countries</div>
          <div class="campaign-tags">${typeTags}</div>
        </div>`;
      })
      .join("");
  }

  function renderGraph(graph) {
    const svgEl = document.getElementById("campaign-graph");
    const wrap = document.getElementById("campaign-graph-wrap");
    if (!svgEl || !wrap || typeof d3 === "undefined") return;

    if (simulation) {
      simulation.stop();
      simulation = null;
    }

    const width = wrap.clientWidth || 600;
    const height = wrap.clientHeight || 420;
    const svg = d3.select(svgEl).attr("viewBox", `0 0 ${width} ${height}`);
    svg.selectAll("*").remove();

    if (!graph.nodes.length) {
      svg
        .append("text")
        .attr("x", width / 2)
        .attr("y", height / 2)
        .attr("text-anchor", "middle")
        .attr("fill", "#8a8070")
        .attr("font-family", "'DM Mono', monospace")
        .attr("font-size", "11px")
        .text("Not enough correlated activity yet to draw a graph.");
      return;
    }

    const nodes = graph.nodes.map((n) => ({ ...n }));
    const links = graph.edges.map((e) => ({ ...e }));

    const zoomLayer = svg.append("g");
    svg.call(
      d3.zoom().scaleExtent([0.4, 4]).on("zoom", (event) => zoomLayer.attr("transform", event.transform))
    );

    const link = zoomLayer
      .append("g")
      .attr("stroke", "rgba(200,220,232,0.18)")
      .attr("stroke-width", 1)
      .selectAll("line")
      .data(links)
      .join("line");

    const node = zoomLayer
      .append("g")
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", (d) => 4 + (d.severity_score || 0) / 14)
      .attr("fill", (d) => SEV_COLOR[d.severity_label] || SEV_COLOR.low)
      .attr("stroke", "#0f1117")
      .attr("stroke-width", 1.2)
      .call(dragBehavior());

    node.append("title").text((d) => `${d.ioc_value}\n${d.threat_type} · ${d.severity_label}\n${d.country || "unknown"}`);

    // The graph is typically dozens of separate star-shaped clusters (one
    // per campaign), not one connected structure. forceCenter alone only
    // recenters their combined average — individual disconnected clusters
    // can still drift arbitrarily far apart under mutual charge repulsion.
    // A weak forceX/forceY keeps everything gravitating toward the middle,
    // and clamping each node's position on every tick guarantees nothing
    // ever renders outside the visible viewBox, however many clusters
    // there are.
    const pad = 14;
    simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink(links)
          .id((d) => d.id)
          .distance(34)
          .strength(0.7)
      )
      .force("charge", d3.forceManyBody().strength(-40))
      .force("x", d3.forceX(width / 2).strength(0.035))
      .force("y", d3.forceY(height / 2).strength(0.09))
      .force("collide", d3.forceCollide(10))
      .on("tick", () => {
        nodes.forEach((d) => {
          d.x = Math.max(pad, Math.min(width - pad, d.x));
          d.y = Math.max(pad, Math.min(height - pad, d.y));
        });
        link
          .attr("x1", (d) => d.source.x)
          .attr("y1", (d) => d.source.y)
          .attr("x2", (d) => d.target.x)
          .attr("y2", (d) => d.target.y);
        node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);
      });

    function dragBehavior() {
      function started(event, d) {
        if (!event.active) simulation.alphaTarget(0.25).restart();
        d.fx = d.x;
        d.fy = d.y;
      }
      function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
      }
      function ended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      }
      return d3.drag().on("start", started).on("drag", dragged).on("end", ended);
    }
  }

  function render(data) {
    renderList(data.campaigns || []);
    renderGraph(data.graph || { nodes: [], edges: [] });
  }

  return { render };
})();
