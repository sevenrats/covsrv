import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Card from "../components/Card";
import {
  fetchHome,
  type HomeProviderGroup,
  type HomeRepoSummary,
} from "../api/client";
import { tsToLabel } from "../utils";
import { covColor } from "../components/charts/colors";

export default function HomePage() {
  const [providers, setProviders] = useState<HomeProviderGroup[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHome()
      .then((data) => {
        setProviders(data.providers ?? []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const totalRepos = providers.reduce((n, p) => n + p.repos.length, 0);
  const totalProviders = providers.length;

  // Collect repos needing attention (coverage dropped)
  const regressions: HomeRepoSummary[] = [];
  const improving: HomeRepoSummary[] = [];
  for (const p of providers) {
    for (const r of p.repos) {
      if (r.delta !== null && r.delta < -1) regressions.push(r);
      if (r.delta !== null && r.delta > 1) improving.push(r);
    }
  }

  return (
    <>
      <Navbar pill="Coverage Dashboard" />
      <div className="content">
        {loading ? (
          <p style={{ color: "var(--clr-text-muted)" }}>Loading…</p>
        ) : totalRepos === 0 ? (
          <div className="home-empty">
            <h2>No repositories tracked yet</h2>
            <p style={{ color: "var(--clr-text-muted)" }}>
              Push a coverage report to get started. See{" "}
              <a href="/docs">the docs</a> for instructions.
            </p>
          </div>
        ) : (
          <>
            {/* Summary stats */}
            <div className="home-stats">
              <div className="home-stat">
                <span className="home-stat-value">{totalRepos}</span>
                <span className="home-stat-label">
                  {totalRepos === 1 ? "repo" : "repos"}
                </span>
              </div>
              <div className="home-stat">
                <span className="home-stat-value">{totalProviders}</span>
                <span className="home-stat-label">
                  {totalProviders === 1 ? "provider" : "providers"}
                </span>
              </div>
              {regressions.length > 0 && (
                <div className="home-stat home-stat--warn">
                  <span className="home-stat-value">{regressions.length}</span>
                  <span className="home-stat-label">regressing</span>
                </div>
              )}
              {improving.length > 0 && (
                <div className="home-stat home-stat--good">
                  <span className="home-stat-value">{improving.length}</span>
                  <span className="home-stat-label">improving</span>
                </div>
              )}
            </div>

            {/* Provider groups */}
            {providers.map((pg) => (
              <ProviderSection key={pg.provider} group={pg} />
            ))}
          </>
        )}
      </div>
    </>
  );
}

function ProviderSection({ group }: { group: HomeProviderGroup }) {
  const { provider, logged_in, repos } = group;

  return (
    <div className="home-provider-section">
      <div className="home-provider-header">
        <h2>
          {provider}
          <span className="home-provider-count">
            {repos.length} {repos.length === 1 ? "repo" : "repos"}
          </span>
        </h2>
        {!logged_in && (
          <a href={`/auth/${provider}/login`} className="btn">
            Log in to see private repos
          </a>
        )}
      </div>

      {repos.length === 0 ? (
        <p style={{ color: "var(--clr-text-muted)", fontSize: 14 }}>
          {logged_in
            ? "No tracked repos visible for this provider."
            : "Log in to see your private repos, or push a report to a public repo."}
        </p>
      ) : (
        <div className="home-repo-grid">
          {repos.map((r) => (
            <RepoCard key={`${r.provider}/${r.repo}`} repo={r} />
          ))}
        </div>
      )}
    </div>
  );
}

function RepoCard({ repo }: { repo: HomeRepoSummary }) {
  const branch = repo.default_branch ?? "main";
  const dashUrl = `/${repo.provider}/${repo.owner}/${repo.name}/b/${branch}`;

  return (
    <Card>
      <div className="home-repo-card">
        <div className="home-repo-top">
          <Link to={dashUrl} className="home-repo-name">
            {repo.owner}/<strong>{repo.name}</strong>
          </Link>
          {repo.coverage !== null && <CoverageBadge percent={repo.coverage} delta={repo.delta} />}
        </div>
        <div className="home-repo-meta">
          <span title="Branches">{repo.branch_count} branches</span>
          <span title="Last report">{tsToLabel(repo.last_seen_ts)}</span>
        </div>
      </div>
    </Card>
  );
}

function CoverageBadge({
  percent,
  delta,
}: {
  percent: number;
  delta: number | null;
}) {
  const color = covColor(percent);
  const deltaStr =
    delta !== null
      ? delta > 0
        ? ` +${delta.toFixed(1)}`
        : ` ${delta.toFixed(1)}`
      : "";
  const deltaClass =
    delta !== null ? (delta > 0 ? "home-delta--up" : delta < 0 ? "home-delta--down" : "") : "";

  return (
    <span className="home-cov-badge" style={{ borderColor: color }}>
      <span style={{ color }}>{percent.toFixed(1)}%</span>
      {deltaStr && <span className={`home-delta ${deltaClass}`}>{deltaStr}</span>}
    </span>
  );
}
