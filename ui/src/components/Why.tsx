import { useEffect, useState } from "react";
import { api, fmt, post, PROTO, ts } from "../api";
import type { Meta } from "../api";
import { Badge, Gauge, SeqHeatmap, SetChips, Waterfalls } from "./viz";

type Full = Record<string, any>;

export function Why({ id, meta, onClose }: { id: number; meta: Meta; onClose?: () => void }) {
  const [d, setD] = useState<Full | null>(null);
  const [err, setErr] = useState("");
  const [off, setOff] = useState<Full | null>(null);
  const [busy, setBusy] = useState("");
  const [wi, setWi] = useState<Full | null>(null);
  const [changes, setChanges] = useState<Record<string, number>>({});
  useEffect(() => {
    setD(null); setOff(null); setWi(null); setChanges({});
    api<Full>(`/api/decisions/${id}`).then(setD).catch((e) => setErr(String(e)));
  }, [id]);
  if (err) return <div className="drawer"><button className="close" onClick={onClose}>✕</button><p className="bad">{err}</p></div>;
  if (!d) return <div className="drawer"><div className="empty">Loading…</div></div>;
  const k = meta.learned?.k ?? 0;
  const names = meta.classes.map((c) => c.name);
  const channels = meta.features.filter((f) => f.section === "sequence_channels").map((f) => f.name);
  const runOffline = async (method: string) => {
    setBusy(method);
    try { setOff(await post<Full>(`/api/decisions/${id}/offline-explain`, { method })); } catch (e) { setOff({ error: String(e) }); }
    setBusy("");
  };
  const runWhatIf = async () => {
    setBusy("whatif");
    try { setWi(await post<Full>("/api/whatif", { decision_id: id, changes })); } catch (e) { setWi({ error: String(e) }); }
    setBusy("");
  };
  return (
    <div className="drawer" role="dialog" aria-label="Why this decision">
      {onClose && <button className="close" onClick={onClose} aria-label="close">✕</button>}
      <h2 style={{ margin: "4px 0 2px" }}><Badge d={d.decision} adv={d.adversarial} /> <span style={{ fontSize: 16 }}>{names[d.pred_class]}</span></h2>
      <div className="muted mono">
        decision #{d.id} · {d.cli}:{d.cport} → {d.srv}:{d.sport} {PROTO[d.proto] ?? d.proto} · {d.n_pkts} pkts · checkpoint {d.checkpoint} · row {d.row_id} · kernel {d.kernel_action}
      </div>

      <div className="panel" style={{ marginTop: 10 }}>
        <h3>a) Checkpoint timeline</h3>
        <div className="row">
          {d.timeline.map((t: Full) => (
            <span key={t.id} className="chip">{t.checkpoint}: <Badge d={t.decision} adv={t.adversarial} /> ECS {fmt(t.ecs, 2)}</span>
          ))}
        </div>
        <div className="muted" style={{ marginTop: 6 }}>Policy {String(meta.policy.mode)} · enforcement {JSON.stringify(d.enforce)}</div>
      </div>

      <div className="panel">
        <h3>b) Narration <span className="chip">{d.narration.source === "llm" ? "LLM, verified ✓" : "template fallback"}</span></h3>
        <div>{d.narration.text}</div>
        {d.narration.note && <div className="muted" style={{ fontSize: 12 }}>{d.narration.note}</div>}
      </div>

      <div className="panel">
        <h3>c) Group attributions — 3 independent sources (top-{k} bold)</h3>
        <div className="legend"><span><span className="sw" style={{ background: "var(--pos)" }} />toward predicted class</span><span><span className="sw" style={{ background: "var(--neg)" }} />against</span></div>
        <Waterfalls attr={d.attributions} meta={meta} k={k} />
      </div>

      <div className="grid2">
        <div className="panel">
          <h3>d) Explanation Consensus</h3>
          <Gauge v={d.ecs} meta={meta} />
          <table>
            <thead><tr><th>pair</th><th>Jaccard@{k}</th><th>signAgree</th><th>A_ij</th></tr></thead>
            <tbody>
              {Object.entries(d.ecs_pairs as Record<string, Record<string, number>>).map(([p, v]) => (
                <tr key={p}><td className="mono">{p}</td><td>{fmt(v.jaccard)}</td><td>{fmt(v.sign)}</td><td>{fmt(v.A)}</td></tr>
              ))}
            </tbody>
          </table>
          <div className="muted" style={{ fontSize: 12 }}>α = {fmt(meta.learned?.alpha, 2)} (learned, config_version {meta.learned?.config_version})</div>
        </div>
        <div className="panel">
          <h3>e) Conformal set & decision row</h3>
          <SetChips set={d.conf_set} meta={meta} />
          <table style={{ marginTop: 6 }}>
            <thead><tr><th>class</th><th>p_ens</th><th>nonconf.</th><th>threshold</th><th>α_t</th></tr></thead>
            <tbody>
              {Object.keys(d.conformal.nonconformity).map((c) => (
                <tr key={c}><td>{c}</td><td>{fmt(d.probs[c], 4)}</td><td>{fmt(d.conformal.nonconformity[c], 4)}</td>
                  <td>{d.conformal.thresholds[c] === null ? "∞" : fmt(d.conformal.thresholds[c], 4)}</td><td>{fmt(d.conformal.alphas[c], 4)}</td></tr>
              ))}
            </tbody>
          </table>
          <div style={{ marginTop: 6 }}>Fired: <b>{d.row_id}</b> → {d.decision}</div>
        </div>
      </div>

      <div className="panel">
        <h3>f) Which packets mattered (CfC integrated gradients, |attr|)</h3>
        <SeqHeatmap attr={d.seq_attr?.attr} raw={d.seq_attr?.raw} channels={channels} />
      </div>

      <div className="panel">
        <h3>g) Adversarial signals</h3>
        {d.adversarial_signals.length ? (
          <ul>{d.adversarial_signals.map((s: Full, i: number) => <li key={i}>{s.kind}: {fmt(s.value, 4)}</li>)}</ul>
        ) : <div className="muted">No signal raised for this decision.</div>}
      </div>

      <div className="panel">
        <h3>h) Offline detail <span className="chip">offline, sampling-based</span></h3>
        <div className="row">
          <button disabled={!!busy} onClick={() => runOffline("kernelshap")}>{busy === "kernelshap" ? "Running…" : "Run KernelSHAP"}</button>
          <button disabled={!!busy} onClick={() => runOffline("lime")}>{busy === "lime" ? "Running…" : "Run LIME"}</button>
        </div>
        {off && (off.error ? <p>{off.error}</p> : (
          <div style={{ marginTop: 8 }}>
            <div>Agreement with hot path: {Object.entries(off.agreement).map(([s, v]) => `${s} ${fmt(v as number)}`).join(" · ")} — disagreement {fmt(off.disagreement)} {off.flag ? <span className="badge b-ADV">⚠ flagged (agreement &lt; τ_lo)</span> : <span className="chip ok">consistent</span>}</div>
            <Waterfalls attr={{ gbdt: off.groups, ebm: [], cfc: [] }} meta={meta} k={k} />
            <div className="muted">{off.method} took {fmt(off.seconds, 2)} s</div>
          </div>
        ))}
        {d.offline.length > 0 && <div className="muted">Previous runs: {d.offline.map((o: Full) => `${o.method} disagreement ${fmt(o.disagreement)}`).join("; ")}</div>}
      </div>

      <div className="panel">
        <h3>i) What-if <span className="chip">Simulation — not applied to traffic</span></h3>
        <div className="grid3">
          {d.features.filter((f: Full) => f.realizable).map((f: Full) => (
            <label key={f.name} className="mono" style={{ fontSize: 12 }}>{f.name} ({fmt(f.value, 0)})
              <input type="number" style={{ width: "100%" }} placeholder={String(f.value)}
                onChange={(e) => { const v = e.target.value; setChanges((c) => { const n = { ...c }; if (v === "") delete n[f.name]; else n[f.name] = Number(v); return n; }); }} />
            </label>
          ))}
        </div>
        <button style={{ marginTop: 8 }} disabled={!!busy} onClick={runWhatIf}>{busy === "whatif" ? "Evaluating…" : "Evaluate"}</button>
        {wi && (wi.error ? <p>{wi.error}</p> : (
          <div style={{ marginTop: 8 }}>
            <div>Now: <Badge d={wi.base.decision} /> {wi.base.pred} ECS {fmt(wi.base.ecs)} → with changes: <Badge d={wi.changed.decision} adv={wi.changed.adversarial} /> {wi.changed.pred} ECS {fmt(wi.changed.ecs)} set {"{"}{wi.changed.set.join(", ")}{"}"}</div>
            <div style={{ marginTop: 4 }}>Counterfactuals (single realizable feature):{" "}
              {wi.counterfactuals.length ? wi.counterfactuals.map((c: Full) => <div key={c.feature} className="mono">if {c.feature} were {fmt(c.to, 0)} (now {fmt(c.from, 0)}) → {c.decision}</div>) : <span className="muted">none found among validation quantiles</span>}
            </div>
          </div>
        ))}
      </div>

      <div className="panel">
        <h3>j) Provenance</h3>
        {d.ledger ? (
          <div className="mono">
            ledger seq {d.ledger.seq} · entry {d.ledger.entry_hash.slice(0, 16)}…<br />
            {d.ledger.batch ? <>batch {d.ledger.batch.id} · root {d.ledger.batch.root.slice(0, 16)}… · signed {ts(d.ledger.batch.created_at)}</> : "not yet sealed into a signed batch"}<br />
            model set {d.model_set_id} · feature hash {d.feature_hash.slice(0, 16)}…
          </div>
        ) : <div className="muted">No ledger entry.</div>}
      </div>

      <details className="panel">
        <summary>k) Raw features ({d.features.length})</summary>
        <table>
          <thead><tr><th>feature</th><th>group</th><th>value</th><th>kernel</th></tr></thead>
          <tbody>{d.features.map((f: Full) => <tr key={f.name}><td className="mono">{f.name}</td><td>{f.group} {meta.groups[f.group]}</td><td className="mono">{fmt(f.value, 4)}</td><td>{f.realizable ? "✓" : ""}</td></tr>)}</tbody>
        </table>
      </details>
    </div>
  );
}
