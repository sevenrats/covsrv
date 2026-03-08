import { Link, useSearchParams } from "react-router-dom";

export default function AccessDenied() {
  const [params] = useSearchParams();
  const owner = params.get("owner") ?? "";
  const name = params.get("name") ?? "";

  return (
    <div className="access-denied-page">
      <div className="access-denied-card">
        <svg
          className="icon"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          <line x1="12" y1="16" x2="12" y2="19" />
        </svg>
        <h1>Access Denied</h1>
        <p>
          You don't have permission to view{" "}
          <strong>
            {owner}/{name}
          </strong>
          .<br />
          If you believe this is a mistake, ask the repository owner to grant you
          access.
        </p>
        <Link className="btn" to="/">
          &larr; Home
        </Link>
      </div>
    </div>
  );
}
