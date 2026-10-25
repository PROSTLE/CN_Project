import { useEffect, useState } from "react";
import { api, fmt, post, ts } from "../api";
import type { Meta } from "../api";

type Rule = Record<string, any>;
const TABS: [string, string[]][] = [["Canary", ["CANARY"]], ["Promoted", ["PROMOTED"]], ["Proposed", ["PROPOSED"]],
  ["Rejected / failed", ["REJECTED", "FIDELITY_FAILED", "CANARY_FAILED"]], ["Expired / rolled back", ["EXPIRED", "ROLLED_BACK"]]];

export function Rules({ meta }: { meta: Meta }) {
  const [rows, setRows] = useState<Rule[]>([]);
  const [tab, setTab] = useState(0);
  const [sel, setSel] = useState<Rule | null>(null);
  const [msg, setMsg] = useState("");
  const [now, setNow] = useState(Date.now() / 1000);
  const load = () => api<Rule[]>("/api/rules").then(setRows).catch(() => {});
  useEffect(() => { load(); const h = setInterval(() => { load(); setNow(Date.now() / 1000); }, 2000); return () => clearInterval(h); }, []);
  const act = async (op: string) => {
    try { await post(`/api/rules/${sel!.id}/${op}`, {}); setMsg(`${op} queued — executed by the brain`); }
    catch (e) { setMsg(String(e)); }
    setTimeout(() => setMsg(""), 4000);
  };
  const open = async (id: number) => setSel(await api<Rule>(`/api/rules/${id}`));
  const shown = rows.filter((r) => TABS[tab][1].includes(r.status));
  return (
    <div>
      <div className="tabs">{TABS.map(([n, s], i) => <button key={n} className={i === tab ? "on" : ""} onClick={() => setTab(i)}>{n} ({rows.filter((r) => s.includes(r.status)).length})</button>)}</div>
      <div className="grid2">
        <div className="panel" style={{ padding: 0 }}>
          {shown.length === 0 ? <div className="empty">No rules here. Rules are proposed by the compiler from live BLOCK/QUARANTINE clusters.</div> : (
            <table><thead><tr><th>id</th><th>rule</th><th>class</th><th>status</th><th>slot</th><th>TTL</th></tr></thead>
              <tbody>{shown.map((r) => (
                <tr key={r.id} className="click" onClick={() => open(r.id)}>
                  <td>{r.id}</td><td className="mono">{r.text} → {r.action}</td><td>{meta.classes[r.class_id]?.name}</td>
                  <td><span className="chip">{r.status}</span></td><td>{r.kernel_slot ?? ""}</td>
                  <td>{r.expires_at ? `${Math.max(0, r.expires_at - now).toFixed(0)}s` : ""}</td>
                </tr>))}</tbody></table>)}
        </div>
        {sel && (
          <div className="panel">
            <h3>Rule #{sel.id} <span className="chip">{sel.status}</span> {sel.certified ? <span className="chip ok">certified</span> : <span className="chip bad">not certified</span>}</h3>
            <pre>{sel.text} → {sel.action}</pre>
            <div className="row">
              <button disabled={sel.status !== "CANARY"} onClick={() => act("accept")}>Accept now</button>
              <button onClick={() => act("reject")}>Reject</button>
              <button disabled={sel.status !== "PROMOTED"} onClick={() => act("expire")}>Expire</button>
              <button disabled={sel.status !== "PROMOTED"} onClick={() => act("fp")}>Report false positive</button>
            </div>
            <h3 style={{ marginTop: 12 }}>Fidelity (held-out recent traffic)</h3>
            {sel.fidelity && <table><tbody>
              <tr><td>agreement with model</td><td>{fmt(sel.fidelity.agreement, 4)} (min {fmt(sel.fidelity.min_agreement, 4)}, learned)</td></tr>
              <tr><td>FPR on model-benign</td><td>{fmt(sel.fidelity.fpr, 4)} (max {fmt(sel.fidelity.max_fpr, 4)})</td></tr>
              <tr><td>recall on cluster</td><td>{fmt(sel.fidelity.recall, 4)}</td></tr>
              <tr><td>rows fit / holdout</td><td>{sel.fidelity.n_fit} / {sel.fidelity.n_holdout}</td></tr>
              <tr><td>top groups</td><td>{(sel.fidelity.top_groups ?? []).map((g: string) => `${g} ${meta.groups[g]}`).join(", ")}</td></tr></tbody></table>}
            {sel.canary && <><h3 style={{ marginTop: 12 }}>Canary (LOG_ONLY)</h3><pre>{JSON.stringify(sel.canary, null, 1)}</pre></>}
            {sel.fp && <><h3>Live FP monitor</h3><pre>{JSON.stringify(sel.fp, null, 1)}</pre></>}
            {sel.rollbacks?.length > 0 && <><h3>Rollbacks</h3><pre>{JSON.stringify(sel.rollbacks, null, 1)}</pre></>}
            <h3>Signed certificate</h3>
            <div className="mono" style={{ fontSize: 11 }}>Ed25519 signature {String(sel.signature).slice(0, 32)}… (key {String(sel.signing_pubkey).slice(0, 16)}…)</div>
            <details><summary>certificate JSON</summary><pre>{JSON.stringify(sel.certificate, null, 1)}</pre></details>
            <h3>Provenance</h3>
            <div className="muted">{sel.provenance.length} originating decisions; ledger: {sel.ledger.map((l: Rule) => `${l.kind}@${l.seq}`).join(", ")}</div>
            <div className="muted">created {ts(sel.created_at)} {sel.reason ? `· ${sel.reason}` : ""}</div>
          </div>
        )}
      </div>
      {msg && <div className="toast">{msg}</div>}
    </div>
  );
}
