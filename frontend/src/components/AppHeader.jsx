import { useEffect, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import Icon from "./Icon";
import { clearAuthSession } from "../lib/auth";

const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/workspace", label: "Map View" },
  { to: "/firewall-simulator", label: "Firewall Simulator" },
  { to: "/logs", label: "Logs" },
  { to: "/assets", label: "Assets" },
  { to: "/settings", label: "Settings" },
];

export default function AppHeader() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchText, setSearchText] = useState("");

  useEffect(() => {
    if (location.pathname !== "/search") {
      return;
    }
    const params = new URLSearchParams(location.search);
    setSearchText(params.get("q") || "");
  }, [location.pathname, location.search]);

  function handleSearchSubmit(event) {
    event.preventDefault();
    const query = searchText.trim();
    if (!query) {
      navigate("/search");
      return;
    }
    navigate(`/search?q=${encodeURIComponent(query)}`);
  }

  function handleSignOut() {
    clearAuthSession();
    navigate("/login");
  }

  return (
    <header className="flex items-center justify-between whitespace-nowrap border-b border-neutral-200 bg-white px-6 py-3 z-20">
      {/* Left: logo + nav */}
      <div className="flex items-center gap-8">
        <div className="flex items-center gap-3 text-slate-900">
          <div className="size-8 text-primary flex items-center justify-center">
            <Icon name="hub" size={32} />
          </div>
          <h2 className="text-lg font-bold leading-tight tracking-tight">
            VPC Flow Log Analyzer
          </h2>
        </div>

        <nav className="hidden md:flex items-center gap-6">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.label}
              to={item.to}
              className={({ isActive }) =>
                `text-sm font-medium transition-colors ${
                  isActive
                    ? "text-primary border-b-2 border-primary pb-0.5"
                    : "text-slate-500 hover:text-primary"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>

      {/* Right: search + actions */}
      <div className="flex items-center gap-4">
        <form onSubmit={handleSearchSubmit} className="hidden lg:flex relative items-center">
          <span className="material-symbols-outlined absolute left-3 text-slate-400 text-[20px]">
            search
          </span>
          <input
            value={searchText}
            onChange={(event) => setSearchText(event.target.value)}
            className="bg-neutral-light/50 border-none rounded-lg py-2 pl-10 pr-10 w-80 text-sm text-slate-900 placeholder-slate-500 focus:ring-2 focus:ring-primary focus:outline-none"
            placeholder="Search anything (IP, port, tag, protocol, group)"
            type="text"
          />
          <button
            type="submit"
            className="absolute right-1.5 p-1 rounded text-slate-500 hover:text-primary hover:bg-white/70 transition-colors"
            title="Search"
          >
            <Icon name="arrow_forward" size={16} />
          </button>
        </form>

        <div className="flex items-center gap-3">
          <button className="flex items-center justify-center size-9 rounded-full bg-neutral-light/50 hover:bg-neutral-200 text-slate-600 transition-colors">
            <Icon name="notifications" size={20} />
          </button>
          <button
            type="button"
            onClick={handleSignOut}
            className="flex items-center justify-center size-9 rounded-full bg-neutral-light/50 hover:bg-neutral-200 text-slate-600 transition-colors"
            title="Sign out"
          >
            <Icon name="logout" size={18} />
          </button>
          <div className="size-9 rounded-full bg-primary/15 border border-neutral-200 flex items-center justify-center text-primary text-sm font-bold">
            A
          </div>
        </div>
      </div>
    </header>
  );
}
