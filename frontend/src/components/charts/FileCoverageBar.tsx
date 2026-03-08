import "./register";
import { Bar } from "react-chartjs-2";
import type { ChartOptions } from "chart.js";
import { covColorT } from "./colors";
import { shorten } from "../../utils";
import type { WorstFile } from "../../api/client";

interface FileCoverageBarProps {
  files: WorstFile[];
}

export default function FileCoverageBar({ files }: FileCoverageBarProps) {
  const labels = files.map((f) => shorten(f.filename));
  const values = files.map((f) => f.percent_covered);

  const data = {
    labels,
    datasets: [
      {
        label: "% covered",
        data: values,
        backgroundColor: values.map((v) => covColorT(v)),
        borderRadius: 4,
      },
    ],
  };

  const options: ChartOptions<"bar"> = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: "y" as const,
    scales: {
      x: { min: 0, max: 100, title: { display: true, text: "Coverage %" } },
    },
    plugins: {
      legend: { display: false },
    },
  };

  return (
    <div className="chart-box">
      <Bar data={data} options={options} />
    </div>
  );
}
