import "./Navbar.css";

import { useState, useRef, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTheme } from "../hooks/useTheme";

interface NavbarProps {
  /** GitHub / Gitea repo URL */
  repoUrl?: string;
  /** Available branches for this repo */
  branches?: string[];
  /** Base URL for branch links, e.g. /provider/owner/name */
  branchesBaseUrl?: string;
  /** Currently-active branch (highlighted in dropdown) */
  currentBranch?: string;
  /** Informational pill text (supports JSX) */
  pill?: React.ReactNode;
  /** Extra buttons rendered between branch dropdown and spacer */
  extraButtons?: React.ReactNode;
}

export default function Navbar({
  repoUrl,
  branches = [],
  branchesBaseUrl = "",
  currentBranch = "",
  pill,
  extraButtons,
}: NavbarProps) {
  const navigate = useNavigate();
  const { theme, toggle } = useTheme();

  const [branchOpen, setBranchOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const branchRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close dropdowns on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (branchRef.current && !branchRef.current.contains(e.target as Node)) {
        setBranchOpen(false);
      }
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    }
    document.addEventListener("click", handleClick);
    return () => document.removeEventListener("click", handleClick);
  }, []);

  return (
    <nav className="navbar">
      {/* Back: always use router navigation */}
      <button
        className="nav-btn"
        title="Back"
        type="button"
        onClick={() => navigate(-1)}
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="15 18 9 12 15 6" />
        </svg>
      </button>

      {/* Branch dropdown */}
      {branches.length > 0 && (
        <div className="branch-dropdown" ref={branchRef}>
          <button
            className="nav-btn"
            title="Branches"
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setBranchOpen((v) => !v);
              setMenuOpen(false);
            }}
          >
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="6" y1="3" x2="6" y2="15" />
              <circle cx="18" cy="6" r="3" />
              <circle cx="6" cy="18" r="3" />
              <path d="M18 9a9 9 0 0 1-9 9" />
            </svg>
          </button>
          <div className={`branch-menu${branchOpen ? " open" : ""}`}>
            {branches.map((b) => (
              <Link
                key={b}
                to={`${branchesBaseUrl}/b/${b}`}
                className={b === currentBranch ? "active" : undefined}
                onClick={() => setBranchOpen(false)}
              >
                {b}
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Extra buttons */}
      {extraButtons}

      {/* Repository link */}
      {repoUrl && (
        <a className="nav-btn" href={repoUrl} title="Repository" target="_blank" rel="noopener noreferrer">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.009-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
          </svg>
        </a>
      )}

      {/* Pill */}
      {pill && <span className="nav-pill">{pill}</span>}

      <span className="nav-spacer" />

      {/* Theme toggle */}
      <button
        className="nav-btn"
        title="Toggle theme"
        type="button"
        onClick={toggle}
      >
        {theme === "dark" ? (
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="12" cy="12" r="5" />
            <line x1="12" y1="1" x2="12" y2="3" />
            <line x1="12" y1="21" x2="12" y2="23" />
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
            <line x1="1" y1="12" x2="3" y2="12" />
            <line x1="21" y1="12" x2="23" y2="12" />
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
          </svg>
        ) : (
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
        )}
      </button>

      {/* Hamburger menu */}
      <div className="menu-wrap" ref={menuRef}>
        <button
          className="nav-btn"
          title="Menu"
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setMenuOpen((v) => !v);
            setBranchOpen(false);
          }}
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
        <div className={`context-menu${menuOpen ? " open" : ""}`} />
      </div>
    </nav>
  );
}
