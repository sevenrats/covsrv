CHART_VIEW = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Coverage Dashboard</title>
    <style>
      :root {
        --chart-h: 360px;
      }

      body {
        font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
        margin: 0;
        padding: 24px 40px;
        width: 100%;
        box-sizing: border-box;
      }

      .top {
        display:flex;
        gap:16px;
        align-items:baseline;
        flex-wrap:wrap;
      }

      .pill {
        padding:6px 12px;
        border-radius:999px;
        background:#f2f2f2;
        font-size:14px;
      }

      /* Muted text + buttons row */
      .muted-row {
        margin-top:8px;
        display:flex;
        flex-wrap:wrap;
        align-items:flex-end; /* bottom-align buttons with text */
        gap:14px;
        color:#666;
        font-size:14px;
      }

      a { color:inherit; text-decoration: underline; }

      .btn {
        padding:4px 10px;        /* shorter */
        border-radius:6px;
        border:1px solid #e2e2e2;
        background:#fafafa;
        font-size:12px;          /* slightly smaller */
        line-height:1.2;
        text-decoration:none;
        transition:all 0.15s ease;
        color:#333;
      }

      .btn:hover {
        background:#f0f0f0;
        border-color:#d0d0d0;
      }

      .grid {
        display:grid;
        grid-template-columns:1fr;
        gap:24px;
        margin-top:24px;
      }

      @media (min-width: 1000px) {
        .grid {
          grid-template-columns: 1fr 1fr;
          align-items: stretch;
        }
      }

      .card {
        border:1px solid #e7e7e7;
        border-radius:18px;
        padding:20px;
        background:white;
        box-shadow:0 1px 2px rgba(0,0,0,0.03);
      }

      .card h2 {
        margin:0 0 16px 0;
        font-size:18px;
      }

      .chart-box {
        height: var(--chart-h);
      }

      .chart-box canvas {
        width: 100% !important;
        height: 100% !important;
        display: block;
      }

      #uncoveredList {
        margin-top:16px;
        padding-left:20px;
        max-height:160px;
        overflow-y:auto;
        font-size:14px;
      }
    </style>
  </head>

  <body>
    <div class="top">
      <h1 style="margin:0;">Coverage</h1>
      <span class="pill" id="latestMeta">Loading latest…</span>
    </div>

    <div class="muted-row">
      <span>
        Uncovered-lines are from the latest report for this ref. Trend is historical.
      </span>

      <a class="btn" href="/download/json__DOWNLOAD_SUFFIX__">JSON</a>
      <a class="btn" href="/download/lcov__DOWNLOAD_SUFFIX__">LCOV</a>
      <a class="btn" href="/download/xml__DOWNLOAD_SUFFIX__">XML</a>
    </div>

    <div class="grid">
      <div class="card">
        <h2>Overall coverage trend</h2>
        <div class="chart-box"><canvas id="trendChart"></canvas></div>
      </div>

      <div class="card">
        <h2>Uncovered lines by file (latest)</h2>
        <div class="chart-box"><canvas id="uncoveredPie"></canvas></div>
        <ol id="uncoveredList"></ol>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
      async function loadTrend() {
        const res = await fetch("__TREND_URL__?limit=__TREND_LIMIT__");
        return await res.json();
      }

      async function loadUncovered() {
        const res = await fetch("__UNCOVERED_URL__?limit=__PIE_LIMIT__");
        return await res.json();
      }

      function tsToLabel(ts) {
        const d = new Date(ts * 1000);
        return d.toLocaleString();
      }

      function shorten(path) {
        if (!path) return path;
        if (path.length <= 40) return path;
        return "…" + path.slice(path.length - 39);
      }

      (async function main() {
        const [trend, uncovered] = await Promise.all([loadTrend(), loadUncovered()]);

        const meta = document.getElementById("latestMeta");
        const latest = uncovered && uncovered.latest ? uncovered.latest : null;

        if (latest) {
          const rawUrl = "__RAW_URL__" + latest.git_hash + "/"; // html templates will append the hash to this
          meta.innerHTML =
            `Latest: ${latest.repo} @ ` +
            `<a href="${rawUrl}">${latest.git_hash}</a> · ` +
            `${latest.overall_percent.toFixed(2)}% · ` +
            `${tsToLabel(latest.received_ts)}`;
        } else {
          meta.textContent = "No reports yet.";
        }

        const tlabels = (trend.points || []).map(p => tsToLabel(p.received_ts));
        const tvals = (trend.points || []).map(p => p.overall_percent);

        new Chart(document.getElementById("trendChart"), {
          type: "line",
          data: {
            labels: tlabels,
            datasets: [{ label: "Overall % covered", data: tvals, tension: 0.2 }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { min: 0, max: 100 } }
          }
        });

        const plabels = (uncovered.files || []).map(x => shorten(x.filename));
        const pvals = (uncovered.files || []).map(x => x.uncovered_lines);

        new Chart(document.getElementById("uncoveredPie"), {
          type: "pie",
          data: {
            labels: plabels,
            datasets: [{ label: "Uncovered lines", data: pvals }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false
          }
        });

        const ulist = document.getElementById("uncoveredList");
        ulist.innerHTML = "";
        (uncovered.files || []).forEach(x => {
          const li = document.createElement("li");
          li.textContent = `${x.filename} — ${x.uncovered_lines} lines`;
          ulist.appendChild(li);
        });
      })();
    </script>
  </body>
</html>

"""
