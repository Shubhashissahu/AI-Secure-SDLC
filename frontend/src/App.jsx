import { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import ErrorBoundary from "./components/ErrorBoundary";
import Dashboard from "./page/Dashboard";
import Repositories from "./page/Repositories";
import Scans from "./page/Scans";
import Findings from "./page/Findings";
import FindingDetail from "./page/FindingDetail";
import Login from "./page/Login";

function Layout({ children }) {
  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <Navbar />
      <main className="max-w-7xl mx-auto px-6 py-8">{children}</main>
    </div>
  );
}

/**
 * FIX #20: App now manages auth state and gates all routes behind login.
 * FIX #26: ErrorBoundary wraps the entire app to prevent full white-screen
 * crashes from uncaught render errors.
 */
function App() {
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);

  // Rehydrate user from localStorage token on initial load
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      try {
        // Decode JWT payload (no verification — backend verifies on every API call)
        const payload = JSON.parse(atob(token.split(".")[1]));
        // Check expiry
        if (payload.exp && payload.exp * 1000 > Date.now()) {
          setUser({ id: payload.sub, role: payload.role });
        } else {
          localStorage.removeItem("token");
        }
      } catch {
        localStorage.removeItem("token");
      }
    }
    setAuthChecked(true);
  }, []);

  function handleLogin(loggedInUser) {
    setUser(loggedInUser);
  }

  // Don't render anything until we've checked localStorage
  if (!authChecked) return null;

  // Unauthenticated — show login
  if (!user) {
    return (
      <ErrorBoundary>
        <Login onLogin={handleLogin} />
      </ErrorBoundary>
    );
  }

  // Authenticated — show full app
  return (
    <ErrorBoundary>
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/repositories" element={<Repositories />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout>
      </Router>
    </ErrorBoundary>
  );
}

export default App;
