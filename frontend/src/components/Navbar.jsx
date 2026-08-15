import { NavLink } from "react-router-dom";

const navLinks = [
  { to: "/", label: "Command Center", icon: "📊" },
  { to: "/repositories", label: "Repositories", icon: "📁" },
  { to: "/scans", label: "Scans", icon: "🔍" },
  { to: "/findings", label: "Findings", icon: "🔐" },
];

function Navbar() {
  function handleLogout() {
    localStorage.removeItem("token");
    window.location.reload();
  }

  return (
    <nav className="bg-slate-900/90 border-b border-slate-800 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
      {/* Brand Logo */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-lg shadow-md shadow-blue-500/20">
          🛡️
        </div>
        <div>
          <span className="font-extrabold text-white tracking-tight text-base block leading-none">
            SecureFlow
          </span>
          <span className="text-[10px] text-slate-400 font-medium tracking-wide">
            Next-Gen AppSec
          </span>
        </div>
      </div>

      {/* Navigation Links */}
      <div className="flex items-center gap-1 bg-slate-950/60 border border-slate-800 rounded-xl p-1">
        {navLinks.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 ${
                isActive
                  ? "bg-blue-600 text-white shadow-md shadow-blue-600/20"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`
            }
          >
            <span className="text-sm">{icon}</span>
            <span>{label}</span>
          </NavLink>
        ))}
      </div>

      {/* Right: status + logout */}
      <div className="hidden sm:flex items-center gap-4 text-xs">
        <span className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="text-slate-400 font-mono text-[11px]">Pipeline Active</span>
        </span>
        <button
          id="navbar-logout"
          onClick={handleLogout}
          className="text-slate-400 hover:text-white text-[11px] font-semibold border border-slate-700 hover:border-slate-600 px-3 py-1 rounded-lg transition-colors"
        >
          Sign Out
        </button>
      </div>
    </nav>
  );
}

export default Navbar;

