/** Build commonly-used URL paths from route params. */

export interface RouteParams {
  provider: string;
  owner: string;
  name: string;
}

export function repoBase(p: RouteParams): string {
  return `/${p.provider}/${p.owner}/${p.name}`;
}

export function downloadUrl(
  token: string,
  p: RouteParams,
  kind: "h" | "b",
  ref: string,
): string {
  return `/download/${token}/${p.provider}/${p.owner}/${p.name}/${kind}/${ref}`;
}

export function rawHashUrl(p: RouteParams, gitHash: string): string {
  return `/${p.provider}/${p.owner}/${p.name}/h/${gitHash}`;
}

export function hashChartUrl(p: RouteParams, gitHash: string): string {
  return `/${p.provider}/${p.owner}/${p.name}/h/${gitHash}/chart`;
}

export function branchUrl(p: RouteParams, branch: string): string {
  return `/${p.provider}/${p.owner}/${p.name}/b/${branch}`;
}

export function tsToLabel(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

export function shorten(path: string, maxLen = 40): string {
  if (!path) return path;
  if (path.length <= maxLen) return path;
  return "\u2026" + path.slice(path.length - (maxLen - 1));
}
