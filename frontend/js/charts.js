window.CTIP = window.CTIP || {};

CTIP.charts = (() => {
  let trendChart = null;
  let typesChart = null;
  let countriesChart = null;

  const COLORS = {
    accent: "#e05c2a",
    grid: "rgba(200, 220, 232, 0.06)",
    text: "#8a8070",
    palette: ["#e05c2a", "#00d4ff", "#c8971a", "#39ff8a", "#e0342a", "#1e3a5f", "#f5f0e8", "#8a8070"],
  };

  Chart.defaults.font.family = "'DM Mono', monospace";
  Chart.defaults.font.size = 10;
  Chart.defaults.color = COLORS.text;

  function renderTrend(trend) {
    const ctx = document.getElementById("chart-trend");
    const labels = trend.map((t) => t.bucket.slice(5, 16).replace(" ", " "));
    const data = trend.map((t) => t.count);

    if (trendChart) {
      trendChart.data.labels = labels;
      trendChart.data.datasets[0].data = data;
      trendChart.update();
      return;
    }

    trendChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "New indicators",
            data,
            borderColor: COLORS.accent,
            backgroundColor: "rgba(224,92,42,0.12)",
            tension: 0.35,
            fill: true,
            pointRadius: 0,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: COLORS.grid }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 6 } },
          y: { grid: { color: COLORS.grid }, beginAtZero: true },
        },
      },
    });
  }

  function renderTypes(topTypes) {
    const ctx = document.getElementById("chart-types");
    const labels = topTypes.map((t) => t.threat_type);
    const data = topTypes.map((t) => t.count);

    if (typesChart) {
      typesChart.data.labels = labels;
      typesChart.data.datasets[0].data = data;
      typesChart.update();
      return;
    }

    typesChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{ data, backgroundColor: COLORS.palette, borderColor: "#141c28", borderWidth: 2 }],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: "right", labels: { boxWidth: 10, padding: 10, font: { size: 10 } } },
        },
      },
    });
  }

  function renderCountries(topCountries) {
    const ctx = document.getElementById("chart-countries");
    const labels = topCountries.map((c) => c.country_code || "??");
    const data = topCountries.map((c) => c.count);

    if (countriesChart) {
      countriesChart.data.labels = labels;
      countriesChart.data.datasets[0].data = data;
      countriesChart.update();
      return;
    }

    countriesChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{ data, backgroundColor: COLORS.accent, borderRadius: 3, maxBarThickness: 22 }],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: COLORS.grid }, beginAtZero: true },
          y: { grid: { display: false } },
        },
      },
    });
  }

  return { renderTrend, renderTypes, renderCountries };
})();
