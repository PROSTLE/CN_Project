import { useEffect, useState } from "react";
import { api, fmt, post, ts } from "../api";
import type { DecisionLite, Meta } from "../api";
import { Badge } from "../components/viz";
import { Why } from "../components/Why";

type Any = Record<string, any>;

export function Audit({ meta }: { meta: Meta }) {
  const [att, setAtt] = useState<Any | null>(null);
  const [ver, setVer] = useState<Any | null>(null);
  const [busy, setBusy] = useState(false);
  const [src, setSrc] = useState("");
  const [rows, setRows] = useState<DecisionLite[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const load = () => api<Any>("/api/audit/attestation").then(setAtt).catch(() => {});
  useEffect(() => { load(); }, []);
  const verify = async () => {
    setBusy(true);
    try { setVer(await post<Any>("/api/audit/verify")); } catch (e) { setVer({ error: String(e) }); }
    setBusy(false); load();
  };
  const search = () => api<DecisionLite[]>(`/api/audit/decisions?limit=300${src ? `&cli=${encodeURIComponent(src)}` : ""}`).then(setRows);
  const exportBundle = async () => {
    const r = await fetch("/api/audit/export", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cli: src || null, limit: 500 }) });
    const blob = await r.blob();
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "glasswall_audit.json"; a.click();
  };
  return (
    <div>
      <div className="grid2">
        <div className="panel">
          <h3>Ledger integrity</h3>
          <button className="primary" disabled={busy} onClick={verify}>{busy ? "Verifying…" : "Verify ledger now"}</button>
          {ver && (ver.error ? <p>{ver.error}</p> : (
            <div style={{ marginTop: 10, padding: 10, borderRadius: 6, border: `2px solid var(--${ver.ok ? "allow" : "block"})` }}>
              <b style={{ color: `var(--${ver.ok ? "allow" : "block"})` }}>{ver.ok ? "✓ LEDGER INTACT" : `✗ TAMPERING DETECTED at seq ${ver.first_bad_seq} (${ver.kind})`}</b>
              <div className="muted">{ver.detail}</div>
              <div>{ver.entries} entries · {ver.batches} batches · {ver.quotes_checked} TPM quotes checked · {fmt(ver.seconds, 3)} s</div>
            </div>
          ))}
          {att && <div className="muted" style={{ marginTop: 8 }}>{att.counts.entries} entries, {att.counts.batches} signed batches</div>}
        </div>
        <div className="panel">
          <h3>TPM attestation <span className="chip">{att?.tpm_label}</span></h3>
          {att?.latest_batch ? (
            <div className="mono" style={{ fontSize: 12 }}>
              latest batch {att.latest_batch.id} (seq {att.latest_batch.from_seq}–{att.latest_batch.to_seq}) · {ts(att.latest_batch.created_at)}<br />
              Merkle root {att.latest_batch.root.slice(0, 32)}…<br />
              quote nonce = root ✓ · PCR{att.latest_batch.quote.pcr_index} = {String(att.latest_batch.quote.pcr_value).slice(0, 32)}…<br />
              model set live: {att.latest_batch.model_set_id}<br />ruleset sha: {String(att.latest_batch.ruleset_sha).slice(0, 24)}…
            </div>) : <div className="muted">No signed batch yet.</div>}
          {att?.signing_key && <p className="muted" style={{ fontSize: 12 }}>Key protection: {att.signing_key.protection}</p>}
        </div>
      </div>
      <div className="panel">
        <h3>Measurement log (PCR events)</h3>
        {att?.pcr_events?.length ? <table><thead><tr><th>time</th><th>what</th><th>ref</th><th>digest</th><th>PCR after</th></tr></thead>
          <tbody>{att.pcr_events.map((e: Any) => <tr key={e.id}><td className="mono">{ts(e.created_at)}</td><td>{e.what}</td><td className="mono">{e.ref}</td><td className="mono">{String(e.digest).slice(0, 16)}</td><td className="mono">{String(e.pcr_after).slice(0, 16)}</td></tr>)}</tbody></table>
          : <div className="muted">No measurements.</div>}
      </div>
      <div className="panel">
        <h3>Search decisions</h3>
        <div className="row"><input placeholder="source ip" value={src} onChange={(e) => setSrc(e.target.value)} /><button onClick={search}>Search</button><button onClick={exportBundle}>Export signed bundle (JSON)</button></div>
        {rows.length > 0 && <table style={{ marginTop: 8 }}><thead><tr><th>id</th><th>time</th><th>flow</th><th>decision</th><th>ECS</th><th>ledger seq</th></tr></thead>
          <tbody>{rows.map((r) => <tr key={r.id} className="click" onClick={() => setSel(r.id)}><td>{r.id}</td><td className="mono">{ts(r.created_at)}</td><td className="mono">{r.cli}:{r.cport} → {r.srv}:{r.sport}</td><td><Badge d={r.decision} adv={r.adversarial} /></td><td>{fmt(r.ecs, 2)}</td><td>{r.ledger_seq}</td></tr>)}</tbody></table>}
      </div>
      {sel !== null && <Why id={sel} meta={meta} onClose={() => setSel(null)} />}
    </div>
  );
}
