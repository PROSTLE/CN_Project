export type Meta = {
  classes: { id: number; name: string; attack: boolean }[];
  classes_modelled: number[];
  groups: Record<string, string>;
  features: { name: string; group_id: string; section: string; kernel_realizable: number }[];
  learned: null | { k: number; alpha: number; tau_lo: number; tau_hi: number; rules_min_agreement: number;
    rules_max_fpr: number; config_version: number; source_run_id: string };
  policy: Record<string, unknown> & { mode: string; fpr_budget: number };
  checkpoints: (number | string)[];
  safety_allowlist: { ports: number[]; ips: string[] };
  env: { label: string; tpm: string };
  enforcement_path: null | { path: string; detail: string; created_at: number };
  model_set: null | { id: string; set_hash: string; created_at: number };
  brain: null | (Record<string, unknown> & { age_s: number });
  last_verification: null | { ok: number; first_bad_seq: number | null; kind: string | null; created_at: number; seconds: number };
  narrator: { endpoint: string | null; model: string | null };
  scenarios: Record<string, { class: string; duration: number; evasion: boolean }>;
};

export type DecisionLite = {
  id: number; flow_id: string; checkpoint: string; created_at: number; decision: string; row_id: string;
  adversarial: number; ecs: number; pred_class: number; conf_set: number[]; probs: Record<string, number>;
  topk: Record<string, [string, number][]>; kernel_action: string; rule_id: number | null; ledger_seq: number | null;
  cli: string; srv: string; cport: number; sport: number; proto: number; n_pkts: number;
};

export async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const r = await fetch(path, {
    credentials: "same-origin",
    headers: opts.body ? { "Content-Type": "application/json" } : undefined,
    ...opts,
  });
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail ?? msg; } catch { /* not json */ }
    throw new Error(`${r.status}: ${msg}`);
  }
  return r.json() as Promise<T>;
}

export const post = <T,>(path: string, body: unknown = {}) => api<T>(path, { method: "POST", body: JSON.stringify(body) });

export const fmt = (v: number | null | undefined, d = 3) => (v === null || v === undefined || Number.isNaN(v) ? "—" : v.toFixed(d));
export const ts = (t: number) => new Date(t * 1000).toLocaleTimeString();
export const PROTO: Record<number, string> = { 6: "TCP", 17: "UDP", 1: "ICMP" };
