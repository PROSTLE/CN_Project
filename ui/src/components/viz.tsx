import type { Meta } from "../api";
import { fmt } from "../api";

const ICON: Record<string, string> = { ALLOW: "✓", ALLOW_SHADOW: "👁", BLOCK: "⛔", QUARANTINE: "⌛" };
const LABEL: Record<string, string> = { ALLOW: "ALLOW", ALLOW_SHADOW: "ALLOW + shadow", BLOCK: "BLOCK", QUARANTINE: "QUARANTINE" };

export function Badge({ d, adv }: { d: string; adv?: number | boolean }) {
  return (
    <span className="row" style={{ gap: 4, display: "inline-flex" }}>
      <span className={`badge b-${d}`}>{ICON[d] ?? ""} {LABEL[d] ?? d}</span>
      {adv ? <span className="badge b-ADV">⚠ ADVERSARIAL</span> : null}
    </span>
  );
}

/** ECS gauge; zones from the ACTIVE learned tau_lo / tau_hi (never constants). */
export function Gauge({ v, meta, size = 120 }: { v: number; meta: Meta; size?: number }) {
  const L = meta.learned;
  const r = size / 2 - 8, cx = size / 2, cy = size / 2;
  const pt = (x: number) => {
    const a = Math.PI * (1 - x);
    return [cx + r * Math.cos(a), cy - r * Math.sin(a)];
  };
  const arc = (a: number, b: number, color: string) => {
    const [x1, y1] = pt(a), [x2, y2] = pt(b);
    return <path d={`M${x1},${y1} A${r},${r} 0 0 1 ${x2},${y2}`} stroke={color} strokeWidth={8} fill="none" />;
  };
  const [nx, ny] = pt(Math.max(0, Math.min(1, v)));
  return (
    <svg width={size} height={size / 2 + 22} role="img" aria-label={`ECS ${fmt(v)}`}>
      {L ? <>{arc(0, L.tau_lo, "var(--adv)")}{arc(L.tau_lo, L.tau_hi, "var(--quar)")}{arc(L.tau_hi, 1, "var(--allow)")}</> : arc(0, 1, "var(--border)")}
      <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="var(--text)" strokeWidth={2} />
      <text x={cx} y={cy + 18} textAnchor="middle" fontSize={14} fill="var(--text)" fontWeight={600}>ECS {fmt(v)}</text>
    </svg>
  );
}

export function MiniEcs({ v, meta }: { v: number; meta: Meta }) {
  const L = meta.learned;
  const color = !L ? "var(--muted)" : v < L.tau_lo ? "var(--adv)" : v < L.tau_hi ? "var(--quar)" : "var(--allow)";
  return (
    <span className="row" style={{ gap: 4, display: "inline-flex" }}>
      <svg width={48} height={8}><rect width={48} height={8} rx={2} fill="var(--panel2)" /><rect width={48 * v} height={8} rx={2} fill={color} /></svg>
      <span className="mono">{fmt(v, 2)}</span>
    </span>
  );
}

/** Group attribution bars for the 3 sources, same group order and scale. */
export function Waterfalls({ attr, meta, k }: { attr: Record<string, number[]>; meta: Meta; k: number }) {
  const gids = Object.keys(meta.groups);
  const srcs: [string, string][] = [["gbdt", "GBDT / TreeSHAP"], ["ebm", "EBM terms"], ["cfc", "CfC / IG"]];
  return (
    <div className="grid3">
      {srcs.map(([s, title]) => {
        const v = attr[s] ?? [];
        const mx = Math.max(1e-12, ...v.map(Math.abs));
        const top = new Set([...v.keys()].filter((i) => v[i] !== 0).sort((a, b) => Math.abs(v[b]) - Math.abs(v[a])).slice(0, k));
        return (
          <div key={s}>
            <div style={{ fontWeight: 600, fontSize: 12, color: `var(--${s})` }}>{title}</div>
            <svg width="100%" viewBox={`0 0 220 ${gids.length * 15}`} role="img" aria-label={`${title} attributions`}>
              {gids.map((g, i) => {
                const val = v[i] ?? 0, w = (Math.abs(val) / mx) * 70;
                return (
                  <g key={g} transform={`translate(0 ${i * 15})`}>
                    <text x={0} y={11} fontSize={9.5} fill={top.has(i) ? "var(--text)" : "var(--muted)"} fontWeight={top.has(i) ? 700 : 400}>
                      {g} {meta.groups[g].slice(0, 16)}
                    </text>
                    <line x1={145} x2={145} y1={0} y2={15} stroke="var(--border)" />
                    <rect x={val >= 0 ? 145 : 145 - w} y={3} width={w} height={9} fill={val >= 0 ? "var(--pos)" : "var(--neg)"} opacity={top.has(i) ? 1 : 0.45} />
                  </g>
                );
              })}
            </svg>
          </div>
        );
      })}
    </div>
  );
}

export function SeqHeatmap({ attr, raw, channels }: { attr: number[][]; raw: number[][]; channels: string[] }) {
  if (!attr?.length) return <div className="muted">No packet sequence.</div>;
  const mx = Math.max(1e-12, ...attr.flat());
  const cw = Math.max(8, Math.min(22, 560 / attr.length));
  return (
    <svg width={70 + attr.length * cw} height={channels.length * 16 + 18} role="img" aria-label="per-packet attribution heatmap">
      {channels.map((c, j) => (
        <text key={c} x={0} y={j * 16 + 12} fontSize={10} fill="var(--muted)">{c}</text>
      ))}
      {attr.map((row, t) =>
        row.map((v, j) => (
          <rect key={`${t}-${j}`} x={70 + t * cw} y={j * 16} width={cw - 1} height={15} fill="var(--pos)" opacity={0.08 + 0.92 * (v / mx)}>
            <title>{`packet ${t}, ${channels[j]}: |attr| ${v.toFixed(4)}, raw ${raw?.[t]?.[j]}`}</title>
          </rect>
        )),
      )}
      {attr.map((_, t) => (t % 4 === 0 ? <text key={t} x={70 + t * cw} y={channels.length * 16 + 13} fontSize={9} fill="var(--muted)">{t}</text> : null))}
    </svg>
  );
}

export function SetChips({ set, meta }: { set: number[]; meta: Meta }) {
  if (!set.length) return <span className="chip bad">∅ empty (OOD)</span>;
  return <span className="row" style={{ gap: 3 }}>{set.map((c) => <span key={c} className="chip">{meta.classes[c]?.name}</span>)}</span>;
}
