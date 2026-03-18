import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import Navbar from "../components/Navbar";
import Card from "../components/Card";
import { TrendChart, UncoveredPie } from "../components/charts";
import {
  fetchBranchTrend,
  fetchBranchUncovered,
  fetchBranches,
  type TrendPoint,
  type UncoveredFile,
  type LatestMeta,
} from "../api/client";
import { repoBase, hashChartUrl, tsToLabel, type RouteParams } from "../utils";

export default function BranchDashboard() {
  const params = useParams<{ provider: string; owner: string; name: string; "*": string }>();

  const provider = params.provider ?? "";
  const owner = params.owner ?? "";
  const name = params.name ?? "";
  // Branch is everything after /b/ (can contain slashes)
  const branch = params["*"] ?? "main";

  const rp: RouteParams = { provider, owner, name };

  const [points, setPoints] = useState<TrendPoint[]>([]);
  const [files, setFiles] = useState<UncoveredFile[]>([]);
  const [latest, setLatest] = useState<LatestMeta | null>(null);
  const [branches, setBranches] = useState<string[]>([]);
  const [repoUrl, setRepoUrl] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      fetchBranchTrend(provider, owner, name, branch),
      fetchBranchUncovered(provider, owner, name, branch),
      fetchBranches(provider, owner, name),
    ]).then(([trend, uncovered, branchesRes]) => {
      setPoints(trend.points ?? []);
      setFiles(uncovered.files ?? []);
      setLatest(uncovered.latest);
      setBranches(branchesRes.branches ?? []);
      if (branchesRes.provider_url) {
        setRepoUrl(`${branchesRes.provider_url}/${owner}/${name}`);
      }
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [provider, owner, name, branch]);

  // Build nav pill
  let pillContent: React.ReactNode = `branch ${branch}`;
  if (latest) {
    const chartUrl = hashChartUrl(rp, latest.git_hash);
    pillContent = (
      <>
        branch {branch} @{" "}
        <Link to={chartUrl}>{latest.git_hash.slice(0, 10)}</Link>
      </>
    );
  }

  // Build meta pill
  let metaParts: string[] = [];
  if (latest) {
    metaParts.push(`${latest.overall_percent.toFixed(1)}% covered`);
    if (typeof latest.total_files === "number")
      metaParts.push(`${latest.total_files} files changed`);
    if (typeof latest.total_uncovered === "number")
      metaParts.push(`${latest.total_uncovered} uncovered lines`);
    metaParts.push(tsToLabel(latest.received_ts));
  }

  // framed-raw URL (for the pie click-through)
  const rawFramedUrl = latest ? `${repoBase(rp)}/h/${latest.git_hash}` : "";
  // spreadsheet / raw report button
  const spreadsheetUrl = latest ? `${repoBase(rp)}/h/${latest.git_hash}` : "";
  // current page URL (used as "from" when navigating to raw view)
  const currentUrl = `${repoBase(rp)}/b/${branch}`;
  const downloadBase = `/${provider}/${owner}/${name}`;

  return (
    <>
      <Navbar
        repoUrl={repoUrl}
        branches={branches}
        branchesBaseUrl={repoBase(rp)}
        currentBranch={branch}
        pill={pillContent}
        extraButtons={
          spreadsheetUrl ? (
            <Link className="nav-btn" to={`${spreadsheetUrl}?from=${encodeURIComponent(currentUrl)}`} title="Raw HTML Report">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <polyline points="16 18 22 12 16 6" />
                <polyline points="8 6 2 12 8 18" />
              </svg>
            </Link>
          ) : undefined
        }
      />

      <div className="content">
        <div className="top">
          <h1 style={{ margin: 0, fontSize: 34 }}>{name}</h1>
          {metaParts.length > 0 && (
            <span className="pill">{metaParts.join(" · ")}</span>
          )}
        </div>

        <div className="download-row">
          <a className="btn" href={`/download/json${downloadBase}/b/${branch}`} download="coverage.json">
            JSON
          </a>
          <a className="btn" href={`/download/lcov${downloadBase}/b/${branch}`} download="coverage.lcov">
            LCOV
          </a>
          <a className="btn" href={`/download/xml${downloadBase}/b/${branch}`} download="coverage.xml">
            XML
          </a>
        </div>

        {loading ? (
          <p style={{ marginTop: 24, color: "var(--clr-text-muted)" }}>Loading…</p>
        ) : (
          <div className="grid">
            <Card title="Overall coverage trend">
              <TrendChart
                points={points}
                rawUrlBase={`${repoBase(rp)}/h/`}
              />
            </Card>

            <Card title="Uncovered lines by file (latest)">
              <UncoveredPie files={files} rawFramedUrl={rawFramedUrl} fromUrl={currentUrl} />
            </Card>
          </div>
        )}
      </div>
    </>
  );
}
