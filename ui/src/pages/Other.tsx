import { useEffect, useState } from "react";
import { api, fmt, post, ts } from "../api";
import type { Meta } from "../api";

type Any = Record<string, any>;

export function Models({ meta }: { meta: Meta }) {
  const [m, setM] = useState<Any | null>(null);
  const [dr, setDr] = useState<Any | null>(null);
  useEffect(() => { api<Any>("/api/models").then(setM); api<Any>("/api/drift").then(setDr); }, []);
  if (!m) return <div className="empty">Loading…</div>;
  return (
    <div>
      <div className="panel"><h3>Model sets</h3>
        {m.model_sets.length === 0 ? <div className="empty">No model set trained yet.</div> :
          <table><thead><tr><th>id</th><th>active</th><th>set hash</th><th>classes</th><th>dataset</th><th>dropped constant</th></tr></thead>
            <tbody>{m.model_sets.map((s: Any) => <tr key={s.id}><td className="mono">{s.id}</td><td>{s.active ? "✓" : ""}</td><td className="mono">{s.set_hash.slice(0, 16)}</td>
              <td>{s.meta.classes.map((c: number) => meta.classes[c].name).join(", ")}</td><td className="mono">{s.dataset}</td><td className="mono">{s.meta.dropped_constant.join(", ")}</td></tr>)}</tbody></table>}
      </div>
      <div className="panel"><h3>Calibrated (LEARNED) values — config_versions</h3>
        <table><thead><tr><th>id</th><th>active</th><th>created</th><th>k</th><th>α</th><th>τ_lo</th><th>τ_hi</th><th>rule min agreement</th><th>source run</th></tr></thead>
          <tbody>{m.config_versions.map((c: Any) => <tr key={c.id}><td>{c.id}</td><td>{c.active ? "✓" : ""}</td><td className="mono">{ts(c.created_at)}</td>
            <td>{c.values.ecs.k}</td><td>{c.values.ecs.alpha}</td><td>{fmt(c.values.decision.tau_lo, 4)}</td><td>{fmt(c.values.decision.tau_hi, 4)}</td>
            <td>{fmt(c.values.rules.min_agreement, 4)}</td><td className="mono">{c.source_run_id}</td></tr>)}</tbody></table>
      </div>
      <div className="grid2">
        <div className="panel"><h3>ACI state (per class α_t)</h3>
          <table><thead><tr><th>class</th><th>α_t</th><th>updates</th><th>misses</th></tr></thead>
            <tbody>{m.aci_state.map((a: Any) => <tr key={a.class_id}><td>{meta.classes[a.class_id].name}</td><td>{fmt(a.alpha_t, 4)}</td><td>{a.n_updates}</td><td>{a.n_err}</td></tr>)}</tbody></table>
        </div>
        <div className="panel"><h3>Drift (ADWIN on ensemble attack score)</h3>
          {!dr?.events.length ? <div className="muted">No drift detected.</div> :
            <table><thead><tr><th>time</th><th>stream</th><th>action</th></tr></thead><tbody>{dr.events.slice(0, 20).map((e: Any) => <tr key={e.id}><td className="mono">{ts(e.created_at)}</td><td>{e.stream}</td><td>{e.action}</td></tr>)}</tbody></table>}
        </div>
      </div>
    </div>
  );
}

export function Experiments() {
  const [rows, setRows] = useState<Any[]>([]);
  const [sel, setSel] = useState<Any | null>(null);
  useEffect(() => { api<Any[]>("/api/experiments").then((r) => { setRows(r); setSel(r[0] ?? null); }); }, []);
  if (!rows.length) return <div className="empty">No experiment has been run yet.</div>;
  return (
    <div className="grid2" style={{ gridTemplateColumns: "300px 1fr" }}>
      <div className="panel" style={{ padding: 0 }}>
        <table><tbody>{rows.map((r) => <tr key={r.id} className="click" onClick={() => setSel(r)} style={sel?.id === r.id ? { background: "var(--panel2)" } : {}}>
          <td><b>{r.name}</b><div className="mono muted" style={{ fontSize: 11 }}>{r.id} · {ts(r.created_at)}</div></td></tr>)}</tbody></table>
      </div>
      {sel && <div className="panel"><h3>{sel.name}</h3><div className="muted mono" style={{ fontSize: 11 }}>env: {sel.env} · config {String(sel.config_sha).slice(0, 12)} · seed {sel.seed} · evidence {sel.evidence_dir}</div>
        {sel.report_md ? <pre>{sel.report_md}</pre> : <pre>{JSON.stringify(sel.results, null, 1)}</pre>}</div>}
    </div>
  );
}

const CHECK = ["D1 benign traffic green; Why? drawer on a benign flow", "D2 nmap scan → BLOCK → proposed rule + certificate → canary → promoted → kernel rule drops next scan",
  "D3 low-and-slow brute force → QUARANTINE, low ECS, admin overrules, verdict flows back", "D4 explainer manipulation → disagreement / ECS collapse → adversarial flag",
  "D5 edit one ledger row → verification fails red; TPM quote shows which model was live", "D6 results slide (Experiments page)"];

export function Demo({ meta }: { meta: Meta }) {
  const [runs, setRuns] = useState<Any[]>([]);
  const [msg, setMsg] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState<boolean[]>(() => { try { return JSON.parse(localStorage.getItem("gw_demo") ?? "[]"); } catch { return []; } });
  const load = () => api<Any[]>("/api/demo/runs").then(setRuns).catch(() => {});
  useEffect(() => { load(); const h = setInterval(load, 3000); return () => clearInterval(h); }, []);
  const toggle = (i: number) => { const n = [...done]; n[i] = !n[i]; setDone(n); try { localStorage.setItem("gw_demo", JSON.stringify(n)); } catch { /* ignore */ } };
  const start = async (s: string) => { try { const r = await post<Any>("/api/demo/attack", { scenario: s }); setMsg(`started ${r.started} (${r.duration_s}s)`); } catch (e) { setMsg(String(e)); } setTimeout(() => setMsg(""), 4000); };
  const tamper = async () => { try { const r = await post<Any>("/api/demo/tamper", { confirm }); setMsg(`ledger seq ${r.tampered_seq} edited: ${r.decision_before} → ${r.decision_after}. Now run Verify on the Audit page.`); setConfirm(""); } catch (e) { setMsg(String(e)); } };
  return (
    <div>
      <div className="panel"><h3>Allow-listed scenarios (config/scenarios.yaml)</h3>
        <div className="row">{Object.entries(meta.scenarios).map(([k, v]) => <button key={k} onClick={() => start(k)} title={`${v.class}, ${v.duration}s`}>{k}{v.evasion ? " (evasion)" : ""}</button>)}</div>
      </div>
      <div className="grid2">
        <div className="panel"><h3>Demo checklist</h3>{CHECK.map((c, i) => <label key={i} style={{ display: "block" }}><input type="checkbox" checked={!!done[i]} onChange={() => toggle(i)} /> {c}</label>)}</div>
        <div className="panel"><h3>Ledger tamper (D5)</h3>
          <p className="muted">Edits one ledger payload directly in the database, as an attacker with file access would. This is permanent for this database.</p>
          <div className="row"><input placeholder="type TAMPER" value={confirm} onChange={(e) => setConfirm(e.target.value)} /><button className="danger" disabled={confirm !== "TAMPER"} onClick={tamper}>Tamper</button></div>
        </div>
      </div>
      <div className="panel"><h3>Recent runs</h3>
        {!runs.length ? <div className="muted">None yet.</div> : <table><thead><tr><th>scenario</th><th>class</th><th>source</th><th>duration</th><th>exit</th></tr></thead>
          <tbody>{runs.map((r) => <tr key={r.run_id}><td>{r.scenario}</td><td>{r.class}</td><td className="mono">{r.src_ip}</td><td>{fmt((r.t_end_ns - r.t_start_ns) / 1e9, 1)}s</td><td>{r.exit}</td></tr>)}</tbody></table>}
      </div>
      {msg && <div className="toast">{msg}</div>}
    </div>
  );
}

export function Settings({ meta }: { meta: Meta }) {
  return (
    <div className="grid2">
      <div className="panel"><h3>Learned values (read-only)</h3>
        {meta.learned ? <pre>{JSON.stringify(meta.learned, null, 1)}</pre> : <div className="bad">Not calibrated — the brain refuses to decide until scripts/calibrate.py has run.</div>}
      </div>
      <div className="panel"><h3>Policy</h3><pre>{JSON.stringify(meta.policy, null, 1)}</pre></div>
      <div className="panel"><h3>Safety allow-list (immutable here)</h3><pre>{JSON.stringify(meta.safety_allowlist, null, 1)}</pre></div>
      <div className="panel"><h3>Semantic groups</h3><table><tbody>{Object.entries(meta.groups).map(([g, n]) => <tr key={g}><td>{g}</td><td>{n}</td></tr>)}</tbody></table></div>
    </div>
  );
}
