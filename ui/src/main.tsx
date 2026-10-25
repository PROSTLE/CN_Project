import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, NavLink, Navigate, Route, Routes, useParams } from "react-router-dom";
import { api, post } from "./api";
import type { Meta } from "./api";
import { Why } from "./components/Why";
import { Audit } from "./pages/Audit";
import { Live } from "./pages/Live";
import { Demo, Experiments, Models, Settings } from "./pages/Other";
import { Review } from "./pages/Review";
import { Rules } from "./pages/Rules";
import "./styles.css";

type User = { username: string; role: string };

function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [err, setErr] = useState("");
  return (
    <div style={{ maxWidth: 340, margin: "12vh auto" }} className="panel">
      <h2 style={{ letterSpacing: ".08em" }}>GLASSWALL</h2>
      <form onSubmit={async (e) => { e.preventDefault(); try { onLogin(await post<User>("/api/auth/login", { username: u, password: p })); } catch (x) { setErr(String(x)); } }}>
        <input style={{ width: "100%", marginBottom: 8 }} placeholder="username" value={u} onChange={(e) => setU(e.target.value)} autoFocus />
        <input style={{ width: "100%", marginBottom: 8 }} type="password" placeholder="password" value={p} onChange={(e) => setP(e.target.value)} />
        <button className="primary" style={{ width: "100%" }}>Sign in</button>
        {err && <p style={{ color: "var(--block)" }}>{err}</p>}
      </form>
    </div>
  );
}

function TopBar({ meta, user, onLogout }: { meta: Meta; user: User; onLogout: () => void }) {
  const b = meta.brain;
  const live = b && b.age_s < 5;
  const v = meta.last_verification;
  return (
    <div className="topbar">
      <span className="chip">{meta.env.label}</span>
      <span className="chip">{meta.env.tpm}</span>
      <span className="chip">enforcement: {meta.enforcement_path?.path ?? "—"}</span>
      <span className="chip mono">model set {meta.model_set ? meta.model_set.set_hash.slice(0, 10) : "none"}</span>
      <span className={`chip ${v ? (v.ok ? "ok" : "bad") : ""}`}>ledger {v ? (v.ok ? "✓ verified" : `✗ broken @${v.first_bad_seq}`) : "not verified yet"}</span>
      <span className="chip">policy {meta.policy.mode}</span>
      <span className={`chip ${live ? "ok" : "bad"}`}>brain {live ? "live" : "offline"}</span>
      {!meta.learned && <span className="chip bad">NOT CALIBRATED</span>}
      <span style={{ flex: 1 }} />
      <span className="chip">{user.username} ({user.role})</span>
      <button onClick={onLogout}>Sign out</button>
      <button onClick={() => { const r = document.documentElement; r.dataset.theme = r.dataset.theme === "dark" ? "light" : "dark"; }} aria-label="toggle theme">◐</button>
    </div>
  );
}

function FlowPage({ meta }: { meta: Meta }) {
  const { id } = useParams();
  return <Why id={Number(id)} meta={meta} />;
}

function App() {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [meta, setMeta] = useState<Meta | null>(null);
  useEffect(() => { api<User>("/api/auth/me").then(setUser).catch(() => setUser(null)); }, []);
  useEffect(() => {
    if (!user) return;
    const t = () => api<Meta>("/api/meta").then(setMeta).catch(() => {});
    t();
    const h = setInterval(t, 3000);
    return () => clearInterval(h);
  }, [user]);
  if (user === undefined) return null;
  if (user === null) return <Login onLogin={setUser} />;
  if (!meta) return <div className="empty">Loading…</div>;
  const links: [string, string][] = [["/live", "Live flows"], ["/review", "Review queue"], ["/rules", "Rule studio"], ["/audit", "Audit & ledger"],
    ["/models", "Models & drift"], ["/experiments", "Experiments"], ["/demo", "Demo"], ["/settings", "Settings"]];
  return (
    <BrowserRouter>
      <div className="layout">
        <nav className="side"><div className="brand">GLASSWALL</div>{links.map(([to, n]) => <NavLink key={to} to={to}>{n}</NavLink>)}</nav>
        <main>
          <TopBar meta={meta} user={user} onLogout={async () => { await post("/api/auth/logout"); setUser(null); }} />
          <Routes>
            <Route path="/" element={<Navigate to="/live" />} />
            <Route path="/live" element={<Live meta={meta} />} />
            <Route path="/flows/:id" element={<FlowPage meta={meta} />} />
            <Route path="/review" element={<Review meta={meta} />} />
            <Route path="/rules" element={<Rules meta={meta} />} />
            <Route path="/audit" element={<Audit meta={meta} />} />
            <Route path="/models" element={<Models meta={meta} />} />
            <Route path="/experiments" element={<Experiments />} />
            <Route path="/demo" element={<Demo meta={meta} />} />
            <Route path="/settings" element={<Settings meta={meta} />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
