import "./register";
import { Pie } from "react-chartjs-2";
import type { ChartOptions } from "chart.js";
import { useNavigate } from "react-router-dom";
import { piePalette } from "./colors";
import { shorten } from "../../utils";
import type { UncoveredFile } from "../../api/client";

interface UncoveredPieProps {
  files: UncoveredFile[];
  /** URL for clicking a slice: base + "?file=" + encodedFilename */
  rawFramedUrl?: string;
  /** Origin chart URL to pass as "from" so the raw view can navigate back */
  fromUrl?: string;
}

export default function UncoveredPie({ files, rawFramedUrl, fromUrl }: UncoveredPieProps) {
  const navigate = useNavigate();
  const palette = piePalette();

  const labels = files.map((f) => shorten(f.filename));
  const values = files.map((f) => f.uncovered_lines);
  const fullNames = files.map((f) => f.filename);
  const colors = labels.map((_, i) => palette[i % palette.length]!);

  const data = {
    labels,
    datasets: [
      {
        label: "Uncovered lines",
        data: values,
        backgroundColor: colors,
      },
    ],
  };

  const options: ChartOptions<"pie"> = {
    responsive: true,
    maintainAspectRatio: false,
    onClick(_evt, elements) {
      if (elements.length > 0 && rawFramedUrl) {
        const idx = elements[0]!.index;
        const file = fullNames[idx];
        if (file) {
          const params = new URLSearchParams({ file });
          if (fromUrl) params.set("from", fromUrl);
          navigate(`${rawFramedUrl}?${params.toString()}`);
        }
      }
    },
  };

  return (
    <>
      <div className="chart-box">
        <Pie data={data} options={options} />
      </div>
      {files.length > 0 && (
        <ol className="uncovered-list">
          {files.map((f) => (
            <li key={f.filename}>
              {f.filename} &mdash; {f.uncovered_lines} lines
            </li>
          ))}
        </ol>
      )}
    </>
  );
}
