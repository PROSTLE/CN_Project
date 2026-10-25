import { useEffect, useState } from "react";
import { api, fmt, post, ts } from "../api";
import type { Meta } from "../api";
import { Badge, SetChips } from "../components/viz";
import { Why } from "../components/Why";

type Ticket = Record<string, any>;

export function Review({ meta }: { meta: Meta }) {
  const [status, setStatus] = useState("open");
  const [rows, setRows] = useState<Ticket[]>([]);
  const [sel, setSel] = useState<Ticket | null>(null);
  const [opened, setOpened] = useState(0);
  const [form, setForm] = useState({ class_id: 0, action: "ALLOW", apply_to_source: true, notes: "" });
  const [msg, setMsg] = useState("");
  const [hideExpl, setHideExpl] = useState(false);
  const load = () => api<Ticket[]>(`/api/review?status=${status}`).then(setRows).catch((e) => setMsg(String(e)));
  useEffect(() => { load(); const h = setInterval(load, 3000); return () => clearInterval(h); }, [status]);
  const open = (t: Ticket) => { setSel(t); setOpened(performance.now()); setForm({ ...form, class_id: t.pred_class, notes: "" }); };
  const submit = async () => {
    try {
      const r = await post<{ message: string; labels: number }>(`/api/review/${sel!.id}/verdict`, { ...form, time_to_decision_s: (performance.now() - opened) / 1000 });
      setMsg(`${r.message} (${r.labels} labels)`); setSel(null); load();
    } catch (e) { setMsg(String(e)); }
    setTimeout(() => setMsg(""), 4000);
  };
  return (
    <div>
      <div className="tabs">{["open", "closed"].map((s) => <button key={s} className={s === status ? "on" : ""} onClick={() => setStatus(s)}>{s}</button>)}
        <label style={{ marginLeft: 12 }}><input type="checkbox" checked={hideExpl} onChange={(e) => setHideExpl(e.target.checked)} /> human-study mode (hide explanations)</label></div>
      <div className="panel" style={{ padding: 0 }}>
        {rows.length === 0 ? <div className="empty">No {status} tickets.</div> : (
          <table>
            <thead><tr><th>opened</th><th>source</th><th>reason</th><th>ECS</th><th>set</th><th>model</th><th>decisions</th><th>kernel</th>{status === "closed" && <th>verdict</th>}</tr></thead>
            <tbody>{rows.map((t) => (
              <tr key={t.id} className="click" onClick={() => open(t)}>
                <td className="mono">{ts(t.opened_at)}</td><td className="mono">{t.cli}</td>
                <td>{t.reason} {t.adversarial ? <span className="badge b-ADV">⚠</span> : null}</td>
                <td>{fmt(t.ecs, 2)}</td><td><SetChips set={t.conf_set} meta={meta} /></td>
                <td>{meta.classes[t.pred_class]?.name}</td><td>{t.n_decisions}</td><td>{t.kernel_action}</td>
                {status === "closed" && <td>{t.verdict_action} / {meta.classes[t.verdict_class]?.name} by {t.closed_by} in {fmt(t.time_to_decision_s, 1)}s</td>}
              </tr>))}
            </tbody>
          </table>
        )}
      </div>
      {sel && (
        <>
          {!hideExpl ? <Why id={sel.last_decision_id} meta={meta} onClose={() => setSel(null)} /> : (
            <div className="drawer"><button className="close" onClick={() => setSel(null)}>✕</button>
              <h3>Ticket #{sel.id} — source {sel.cli}</h3><p>Explanations hidden (study arm "without").</p><Badge d={sel.decision} />
            </div>)}
          {status === "open" && (
            <div className="panel" style={{ position: "fixed", bottom: 0, right: 0, width: "min(760px,100vw)", zIndex: 11, marginBottom: 0 }}>
              <h3>Verdict for ticket #{sel.id} ({sel.cli})</h3>
              <div className="row">
                <select value={form.class_id} onChange={(e) => setForm({ ...form, class_id: Number(e.target.value) })} aria-label="class">
                  {meta.classes.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
                <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })} aria-label="action">
                  <option>ALLOW</option><option>BLOCK</option>
                </select>
                <label><input type="checkbox" checked={form.apply_to_source} onChange={(e) => setForm({ ...form, apply_to_source: e.target.checked })} /> apply to source</label>
                <input style={{ flex: 1 }} placeholder="notes (required to overrule)" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
                <button className="primary" onClick={submit}>Submit</button>
              </div>
            </div>
          )}
        </>
      )}
      {msg && <div className="toast">{msg}</div>}
    </div>
  );
}
