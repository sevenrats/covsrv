import "./register";
import { Doughnut } from "react-chartjs-2";
import type { ChartOptions } from "chart.js";
import { covColor, cssVar } from "./colors";

interface CoverageGaugeProps {
  percent: number;
}

export default function CoverageGauge({ percent }: CoverageGaugeProps) {
  const color = covColor(percent);
  const empty = cssVar("--clr-cov-empty");

  const data = {
    labels: ["Covered", "Uncovered"],
    datasets: [
      {
        data: [percent, 100 - percent],
        backgroundColor: [color, empty],
        borderWidth: 0,
      },
    ],
  };

  const options: ChartOptions<"doughnut"> = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "75%",
    plugins: {
      legend: { display: false },
      tooltip: { enabled: true },
    },
  };

  return (
    <div className="chart-box gauge-wrapper">
      <Doughnut data={data} options={options} />
      <div className="gauge-label">
        <div className="gauge-value" style={{ color }}>
          {percent.toFixed(1)}%
        </div>
        <div className="gauge-caption">coverage</div>
      </div>
    </div>
  );
}
