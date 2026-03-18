import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import Navbar from "../components/Navbar";
import Card from "../components/Card";
import { FileCoverageBar, UncoveredPie } from "../components/charts";
import {
  fetchHashUncovered,
  fetchHashWorstFiles,
  fetchBranches,
  fetchHashBranches,
  type UncoveredFile,
  type WorstFile,
  type LatestMeta,
} from "../api/client";
import { repoBase, branchUrl, tsToLabel, type RouteParams } from "../utils";

export default function HashDashboard() {
  const params = useParams<{
    provider: string;
    owner: string;
    name: string;
    gitHash: string;
  }>();

  const provider = params.provider ?? "";
  const owner = params.owner ?? "";
  const name = params.name ?? "";
  const gitHash = params.gitHash ?? "";

  const rp: RouteParams = { provider, owner, name };

  const [uncoveredFiles, setUncoveredFiles] = useState<UncoveredFile[]>([]);
  const [worstFiles, setWorstFiles] = useState<WorstFile[]>([]);
  const [latest, setLatest] = useState<LatestMeta | null>(null);
  const [branches, setBranches] = useState<string[]>([]);
  const [hashBranches, setHashBranches] = useState<string[]>([]);
  const [repoUrl, setRepoUrl] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      fetchHashUncovered(provider, owner, name, gitHash),
      fetchHashWorstFiles(provider, owner, name, gitHash),
      fetchBranches(provider, owner, name),
      fetchHashBranches(provider, owner, name, gitHash),
    ])
      .then(([uncovered, worst, branchesRes, hashBranchesRes]) => {
        setUncoveredFiles(uncovered.files ?? []);
        setLatest(uncovered.latest);
        setWorstFiles(worst.files ?? []);
        setBranches(branchesRes.branches ?? []);
        setHashBranches(hashBranchesRes.branches ?? []);
        if (branchesRes.provider_url) {
          setRepoUrl(`${branchesRes.provider_url}/${owner}/${name}`);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [provider, owner, name, gitHash]);

  // Nav pill
  const hashBranch = hashBranches[0] ?? "";
  const pillContent = hashBranch ? (
    <>
      sha {gitHash.slice(0, 10)} ·{" "}
      <Link to={branchUrl(rp, hashBranch)}>{hashBranch}</Link>
    </>
  ) : (
    <>sha {gitHash.slice(0, 10)}</>
  );

  // Meta pill
  const metaParts: string[] = [];
  if (latest) {
    metaParts.push(`${latest.overall_percent.toFixed(1)}% covered`);
    if (typeof latest.total_files === "number")
      metaParts.push(`${latest.total_files} files changed`);
    if (typeof latest.total_uncovered === "number")
      metaParts.push(`${latest.total_uncovered} uncovered lines`);
    metaParts.push(tsToLabel(latest.received_ts));
  }

  const rawFramedUrl = `${repoBase(rp)}/h/${gitHash}`;
  const downloadBase = `/${provider}/${owner}/${name}`;

  return (
    <>
      <Navbar
        repoUrl={repoUrl}
        branches={branches}
        branchesBaseUrl={repoBase(rp)}
        pill={pillContent}
        extraButtons={
          <Link className="nav-btn" to={rawFramedUrl} title="Raw HTML Report">
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
          <a
            className="btn"
            href={`/download/json${downloadBase}/h/${gitHash}`}
            download="coverage.json"
          >
            JSON
          </a>
          <a
            className="btn"
            href={`/download/lcov${downloadBase}/h/${gitHash}`}
            download="coverage.lcov"
          >
            LCOV
          </a>
          <a
            className="btn"
            href={`/download/xml${downloadBase}/h/${gitHash}`}
            download="coverage.xml"
          >
            XML
          </a>
        </div>

        {loading ? (
          <p style={{ marginTop: 24, color: "var(--clr-text-muted)" }}>
            Loading…
          </p>
        ) : (
          <div className="grid">
            <Card title="Worst files by coverage">
              <FileCoverageBar files={worstFiles} />
            </Card>

            <Card title="Uncovered lines by file">
              <UncoveredPie files={uncoveredFiles} rawFramedUrl={rawFramedUrl} />
            </Card>
          </div>
        )}
      </div>
    </>
  );
}
