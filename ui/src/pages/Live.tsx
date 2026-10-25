import { useEffect, useRef, useState } from "react";
import { api, fmt, PROTO, ts } from "../api";
import type { DecisionLite, Meta } from "../api";
import { Badge, MiniEcs, SetChips } from "../components/viz";
import { Why } from "../components/Why";

type Stats = { total: number; per_s: number; by_decision: Record<string, number>; adversarial: number; p50_ms: number | null;
  p99_ms: number | null; promoted_rules: number; drift_events: number; open_tickets: number };

export function Live({ meta }: { meta: Meta }) {
  const [rows, setRows] = useState<DecisionLite[]>([]);
  const [paused, setPaused] = useState(false);
  const [pending, setPending] = useState<DecisionLite[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [win, setWin] = useState(60);
  const [st, setSt] = useState<Stats | null>(null);
  const [conn, setConn] = useState<"connecting" | "open" | "closed">("connecting");
  const [f, setF] = useState({ action: "", adv: false, src: "" });
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => { api<DecisionLite[]>("/api/decisions?limit=300").then(setRows).catch(() => {}); }, []);
  useEffect(() => {
    let ws: WebSocket | null = null, stop = false;
    const open = () => {
      ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
      setConn("connecting");
      ws.onopen = () => setConn("open");
      ws.onclose = () => { setConn("closed"); if (!stop) setTimeout(open, 2000); };
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data);
        if (msg.channel !== "decisions") return;
        const fresh = (msg.payload as DecisionLite[]).slice().reverse();
        if (pausedRef.current) setPending((p) => [...fresh, ...p].slice(0, 2000));
        else setRows((r) => [...fresh, ...r].slice(0, 1000));
      };
    };
    open();
    return () => { stop = true; ws?.close(); };
  }, []);
  useEffect(() => {
    const t = () => api<Stats>(`/api/stats?window_s=${win}`).then(setSt).catch(() => {});
    t();
    const h = setInterval(t, 2000);
    return () => clearInterval(h);
  }, [win]);

  const shown = rows.filter((r) => (!f.action || r.decision === f.action) && (!f.adv || r.adversarial) && (!f.src || r.cli.includes(f.src)));
  const pct = (k: string) => (st && st.total ? `${((100 * (st.by_decision[k] ?? 0)) / st.total).toFixed(1)}%` : "—");
  return (
    <div>
      <div className="row" style={{ marginBottom: 8 }}>
        <span>Window</span>
        {[60, 600, 3600].map((w) => <button key={w} className={w === win ? "primary" : ""} onClick={() => setWin(w)}>{w === 60 ? "1m" : w === 600 ? "10m" : "1h"}</button>)}
        <span className={`chip ${conn === "open" ? "ok" : "bad"}`}>stream {conn}</span>
      </div>
      <div className="kpis">
        <div className="kpi"><div className="v">{st ? fmt(st.per_s, 1) : "—"}</div><div className="l">decisions / s</div></div>
        <div className="kpi"><div className="v">{pct("ALLOW")}</div><div className="l">ALLOW (+shadow {pct("ALLOW_SHADOW")})</div></div>
        <div className="kpi"><div className="v">{pct("BLOCK")}</div><div className="l">BLOCK</div></div>
        <div className="kpi"><div className="v">{pct("QUARANTINE")}</div><div className="l">QUARANTINE</div></div>
        <div className="kpi"><div className="v">{st?.adversarial ?? "—"}</div><div className="l">adversarial flags</div></div>
        <div className="kpi"><div className="v">{st?.p50_ms != null ? fmt(st.p50_ms, 1) : "—"} / {st?.p99_ms != null ? fmt(st.p99_ms, 0) : "—"}</div><div className="l">p50 / p99 event→decision ms</div></div>
        <div className="kpi"><div className="v">{st?.promoted_rules ?? "—"}</div><div className="l">promoted rules</div></div>
        <div className="kpi"><div className="v">{st?.drift_events ?? "—"}</div><div className="l">drift events</div></div>
      </div>
      <div className="row" style={{ marginBottom: 8 }}>
        <select value={f.action} onChange={(e) => setF({ ...f, action: e.target.value })} aria-label="action filter">
          <option value="">all actions</option>{["ALLOW", "ALLOW_SHADOW", "BLOCK", "QUARANTINE"].map((a) => <option key={a}>{a}</option>)}
        </select>
        <label><input type="checkbox" checked={f.adv} onChange={(e) => setF({ ...f, adv: e.target.checked })} /> adversarial only</label>
        <input placeholder="source ip" value={f.src} onChange={(e) => setF({ ...f, src: e.target.value })} />
        <button onClick={() => { if (paused) { setRows((r) => [...pending, ...r].slice(0, 1000)); setPending([]); } setPaused(!paused); }}>
          {paused ? `Resume (${pending.length} new)` : "Pause"}
        </button>
      </div>
      <div className="panel tablewrap" style={{ padding: 0 }}>
        {shown.length === 0 ? <div className="empty">No traffic yet — start the lab and the brain.</div> : (
          <table>
            <thead><tr><th>time</th><th>src → dst</th><th>proto</th><th>pkts</th><th>cp</th><th>decision</th><th>ECS</th><th>class / p</th><th>set</th><th>top groups (GBDT)</th><th>rule</th><th>ledger</th></tr></thead>
            <tbody>
              {shown.slice(0, 400).map((r) => {
                const pn = meta.classes[r.pred_class]?.name;
                return (
                  <tr key={r.id} className="click" onClick={() => setSel(r.id)}>
                    <td className="mono">{ts(r.created_at)}</td>
                    <td className="mono">{r.cli}:{r.cport} → {r.srv}:{r.sport}</td>
                    <td>{PROTO[r.proto] ?? r.proto}</td><td>{r.n_pkts}</td><td>{r.checkpoint}</td>
                    <td><Badge d={r.decision} adv={r.adversarial} /></td>
                    <td><MiniEcs v={r.ecs} meta={meta} /></td>
                    <td>{pn} {fmt(r.probs[pn], 2)}</td>
                    <td><SetChips set={r.conf_set} meta={meta} /></td>
                    <td className="mono" style={{ fontSize: 11 }}>{(r.topk.gbdt ?? []).slice(0, 3).map(([g]) => g).join(" ")}</td>
                    <td>{r.rule_id ?? ""}</td><td>{r.ledger_seq ? "✓" : ""}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      {sel !== null && <Why id={sel} meta={meta} onClose={() => setSel(null)} />}
    </div>
  );
}
