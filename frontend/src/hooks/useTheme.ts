import { useCallback, useSyncExternalStore } from "react";

function getTheme(): "light" | "dark" {
  return document.documentElement.getAttribute("data-theme") === "dark"
    ? "dark"
    : "light";
}

function subscribe(cb: () => void): () => void {
  // Listen for storage events (cross-tab) and our own custom event.
  const handler = () => cb();
  window.addEventListener("covsrv-theme-change", handler);
  window.addEventListener("storage", handler);
  return () => {
    window.removeEventListener("covsrv-theme-change", handler);
    window.removeEventListener("storage", handler);
  };
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getTheme);

  const toggle = useCallback(() => {
    const next = getTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("covsrv-theme", next);
    window.dispatchEvent(new Event("covsrv-theme-change"));
  }, []);

  return { theme, toggle } as const;
}
