import { useEffect, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import Navbar from "../components/Navbar";
import { fetchBranches } from "../api/client";
import { repoBase, type RouteParams } from "../utils";

export default function FramedRaw() {
  const params = useParams<{
    provider: string;
    owner: string;
    name: string;
    gitHash: string;
  }>();
  const [searchParams] = useSearchParams();

  const provider = params.provider ?? "";
  const owner = params.owner ?? "";
  const name = params.name ?? "";
  const gitHash = params.gitHash ?? "";

  const rp: RouteParams = { provider, owner, name };

  const [branches, setBranches] = useState<string[]>([]);
  const [repoUrl, setRepoUrl] = useState<string | undefined>();
  const [showOverlay, setShowOverlay] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const rawSrc = `/raw/${provider}/${owner}/${name}/h/${gitHash}/`;
  const chartUrl = `${repoBase(rp)}/h/${gitHash}/chart`;
  const targetFile = searchParams.get("file");

  useEffect(() => {
    fetchBranches(provider, owner, name)
      .then((res) => {
        setBranches(res.branches ?? []);
        if (res.provider_url) {
          setRepoUrl(`${res.provider_url}/${owner}/${name}`);
        }
      })
      .catch(() => {});
  }, [provider, owner, name]);

  // Auto-navigate to a specific file inside the iframe
  useEffect(() => {
    if (!targetFile) return;
    setShowOverlay(true);

    const iframe = iframeRef.current;
    if (!iframe) return;

    function norm(s: string) {
      return s.replace(/\s*\/\s*/g, "/").replace(/\s*\\\s*/g, "/");
    }
    const normTarget = norm(targetFile);

    function reveal() {
      setShowOverlay(false);
    }

    function findAndClick(doc: Document): boolean {
      const links = doc.querySelectorAll("a");
      for (const link of links) {
        if (norm(link.textContent?.trim() ?? "") === normTarget) {
          link.click();
          iframe!.addEventListener(
            "load",
            () => reveal(),
            { once: true },
          );
          return true;
        }
      }
      return false;
    }

    function onInitialLoad() {
      try {
        const doc =
          iframe!.contentDocument ?? iframe!.contentWindow?.document;
        if (!doc) { reveal(); return; }
        if (findAndClick(doc)) return;

        let attempts = 0;
        const poll = setInterval(() => {
          attempts++;
          try {
            if (findAndClick(doc)) {
              clearInterval(poll);
            } else if (attempts >= 50) {
              clearInterval(poll);
              reveal();
            }
          } catch {
            clearInterval(poll);
            reveal();
          }
        }, 100);
      } catch {
        reveal();
      }
    }

    iframe.addEventListener("load", onInitialLoad, { once: true });
    return () => iframe.removeEventListener("load", onInitialLoad);
  }, [targetFile]);

  return (
    <div className="framed-raw" style={{ height: "100vh", overflow: "hidden" }}>
      <Navbar
        repoUrl={repoUrl}
        branches={branches}
        branchesBaseUrl={repoBase(rp)}
        extraButtons={
          <Link className="nav-btn" to={chartUrl} title="Chart">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="18" y1="20" x2="18" y2="10" />
              <line x1="12" y1="20" x2="12" y2="4" />
              <line x1="6" y1="20" x2="6" y2="14" />
            </svg>
          </Link>
        }
      />

      <iframe ref={iframeRef} src={rawSrc} title="Coverage Report" style={{
        visibility: showOverlay ? "hidden" : "visible",
      }} />

      {showOverlay && (
        <div
          style={{
            position: "fixed",
            top: 48,
            left: 0,
            right: 0,
            bottom: 0,
            background: "var(--clr-bg)",
            zIndex: 50,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <div style={{ textAlign: "center", color: "var(--clr-text-muted)", fontFamily: "system-ui, sans-serif" }}>
            <svg
              width="36"
              height="36"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              style={{ animation: "covsrv-spin 1s linear infinite" }}
            >
              <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
            </svg>
            <div style={{ marginTop: 10, fontSize: 14 }}>Loading file&hellip;</div>
          </div>
        </div>
      )}
    </div>
  );
}
