/* ── API client for covsrv ── */

export interface TrendPoint {
  git_hash: string;
  received_ts: number;
  overall_percent: number;
}

export interface TrendResponse {
  repo: string;
  kind: string;
  ref: string;
  points: TrendPoint[];
}

export interface UncoveredFile {
  filename: string;
  uncovered_lines: number;
}

export interface LatestMeta {
  repo: string;
  git_hash: string;
  received_ts: number;
  overall_percent: number;
  total_files: number;
  total_uncovered: number;
}

export interface UncoveredResponse {
  latest: LatestMeta | null;
  files: UncoveredFile[];
}

export interface WorstFile {
  filename: string;
  percent_covered: number;
}

export interface WorstFilesResponse {
  latest: LatestMeta | null;
  files: WorstFile[];
}

export interface BranchesResponse {
  branches: string[];
  provider_url?: string;
}

export interface HashBranchesResponse {
  branches: string[];
}

function apiBase(
  provider: string,
  owner: string,
  name: string,
): string {
  return `/api/${provider}/${owner}/${name}`;
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (res.status === 403) {
    // Redirect to access denied
    const owner = url.split("/")[3] ?? "";
    const name = url.split("/")[4] ?? "";
    window.location.href = `/access-denied?owner=${encodeURIComponent(owner)}&name=${encodeURIComponent(name)}`;
    throw new Error("Access denied");
  }
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export function fetchBranchTrend(
  provider: string,
  owner: string,
  name: string,
  branch: string,
  limit = 200,
): Promise<TrendResponse> {
  return fetchJson(
    `${apiBase(provider, owner, name)}/b/${branch}/trend?limit=${limit}`,
  );
}

export function fetchBranchUncovered(
  provider: string,
  owner: string,
  name: string,
  branch: string,
  limit = 12,
): Promise<UncoveredResponse> {
  return fetchJson(
    `${apiBase(provider, owner, name)}/b/${branch}/latest/uncovered-lines?limit=${limit}`,
  );
}

export function fetchHashUncovered(
  provider: string,
  owner: string,
  name: string,
  gitHash: string,
  limit = 12,
): Promise<UncoveredResponse> {
  return fetchJson(
    `${apiBase(provider, owner, name)}/h/${gitHash}/latest/uncovered-lines?limit=${limit}`,
  );
}

export function fetchHashWorstFiles(
  provider: string,
  owner: string,
  name: string,
  gitHash: string,
  limit = 12,
): Promise<WorstFilesResponse> {
  return fetchJson(
    `${apiBase(provider, owner, name)}/h/${gitHash}/latest/worst-files?limit=${limit}`,
  );
}

export function fetchBranches(
  provider: string,
  owner: string,
  name: string,
): Promise<BranchesResponse> {
  return fetchJson(
    `${apiBase(provider, owner, name)}/branches`,
  );
}

export function fetchHashBranches(
  provider: string,
  owner: string,
  name: string,
  gitHash: string,
): Promise<HashBranchesResponse> {
  return fetchJson(
    `${apiBase(provider, owner, name)}/h/${gitHash}/branches`,
  );
}

/* ── Home page ── */

export interface HomeRepoSummary {
  provider: string;
  owner: string;
  name: string;
  repo: string;
  last_seen_ts: number;
  branch_count: number;
  coverage: number | null;
  delta: number | null;
  default_branch: string | null;
}

export interface HomeProviderGroup {
  provider: string;
  logged_in: boolean;
  repos: HomeRepoSummary[];
}

export interface HomeResponse {
  providers: HomeProviderGroup[];
}

export function fetchHome(): Promise<HomeResponse> {
  return fetchJson("/api/home");
}
