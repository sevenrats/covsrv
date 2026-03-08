import "./register";
import { Line } from "react-chartjs-2";
import type { ChartOptions } from "chart.js";
import { useNavigate } from "react-router-dom";
import { cssVar } from "./colors";
import type { TrendPoint } from "../../api/client";

interface TrendChartProps {
  points: TrendPoint[];
  /** Base URL for clicking a point: base + git_hash + "/chart" */
  rawUrlBase: string;
}

export default function TrendChart({ points, rawUrlBase }: TrendChartProps) {
  const navigate = useNavigate();

  const lineClr = cssVar("--clr-trend-line");
  const fillClr = cssVar("--clr-trend-fill");

  const data = {
    labels: points.map(() => ""),
    datasets: [
      {
        data: points.map((p) => p.overall_percent),
        tension: 0.25,
        borderColor: lineClr,
        backgroundColor: fillClr,
        pointBackgroundColor: lineClr,
        pointRadius: 4,
        pointHoverRadius: 7,
        fill: true,
      },
    ],
  };

  const options: ChartOptions<"line"> = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: { min: 0, max: 100, display: true, grid: { display: true }, ticks: { stepSize: 25 } },
      x: { display: false },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          title(ctx) {
            const p = points[ctx[0]!.dataIndex];
            if (!p) return "";
            return new Date(p.received_ts * 1000).toLocaleString();
          },
          label(ctx) {
            const p = points[ctx.dataIndex];
            if (!p) return "";
            return `${p.overall_percent.toFixed(2)}% — ${p.git_hash.slice(0, 8)}`;
          },
        },
      },
    },
    onClick(_evt, elements) {
      if (elements.length > 0 && rawUrlBase) {
        const idx = elements[0]!.index;
        const p = points[idx];
        if (p) navigate(`${rawUrlBase}${p.git_hash}/chart`);
      }
    },
  };

  return (
    <div className="chart-box">
      <Line data={data} options={options} />
    </div>
  );
}
