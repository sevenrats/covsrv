import { Routes, Route, Navigate } from "react-router-dom";
import BranchDashboard from "./pages/BranchDashboard";
import HashDashboard from "./pages/HashDashboard";
import FramedRaw from "./pages/FramedRaw";
import AccessDenied from "./pages/AccessDenied";
import HomePage from "./pages/HomePage";

export default function App() {
  return (
    <Routes>
      {/* Home page */}
      <Route path="/" element={<HomePage />} />

      {/* Branch dashboard */}
      <Route
        path="/:provider/:owner/:name/b/*"
        element={<BranchDashboard />}
      />

      {/* Hash dashboard (chart view) */}
      <Route
        path="/:provider/:owner/:name/h/:gitHash/chart"
        element={<HashDashboard />}
      />

      {/* Framed raw HTML report */}
      <Route
        path="/:provider/:owner/:name/h/:gitHash"
        element={<FramedRaw />}
      />

      {/* Access denied */}
      <Route path="/access-denied" element={<AccessDenied />} />

      {/* Repo home → redirect to /b/main */}
      <Route
        path="/:provider/:owner/:name/"
        element={<RepoRedirect />}
      />
      <Route
        path="/:provider/:owner/:name"
        element={<RepoRedirect />}
      />
    </Routes>
  );
}

function RepoRedirect() {
  // Extract from URL and redirect to /b/main
  const path = window.location.pathname.replace(/\/+$/, "");
  return <Navigate to={`${path}/b/main`} replace />;
}
