'use client';

import { useId, useMemo, useState } from 'react';
import useSWR from 'swr';

import { PLANS, RULE_CATALOG, type RulePack } from '@fortis/shared';

import { Bank, Chevron, Key, Layers, Search, Target } from '@/components/icons';
import { Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { Empty, SeverityPill } from '@/components/ui';
import { fetcher } from '@/lib/api';

type Health = { ruleId: string; total: number; open: number; triaged: number; falsePositive: number; falsePositiveRate: number | null };

/** How your team triaged this rule's findings. */
function HealthLine({ h }: { h?: Health }) {
  if (!h) return <div className="rule-health muted">No findings in your workspace yet</div>;
  const rate = h.falsePositiveRate;
  const tone = rate === null ? '' : rate >= 0.3 ? 'bad' : rate >= 0.1 ? 'warn' : 'good';
  return (
    <div className={`rule-health ${tone}`}>
      <span>{h.total} found · {h.open} open</span>
      <span>{rate === null ? 'none triaged yet' : `${Math.round(rate * 100)}% marked false positive (${h.falsePositive} of ${h.triaged})`}</span>
    </div>
  );
}

type PackId = RulePack | 'zap';

const PACKS: { id: PackId; name: string; short: string; icon: typeof Key; text: string }[] = [
  { id: 'fintech', name: 'Fintech rule pack', short: 'Money-moving code', icon: Bank, text: 'Checks written for money-moving code: transfers, wallets, webhooks, KYC data and OTPs.' },
  { id: 'secrets', name: 'Secrets', short: 'Keys and tokens', icon: Key, text: 'API keys, tokens and private keys committed to the repository, including Paystack, Flutterwave and Monnify secret keys.' },
  { id: 'dependencies', name: 'Dependencies', short: 'Known vulnerabilities', icon: Layers, text: 'Known vulnerabilities in the open-source packages your project uses.' },
  { id: 'zap', name: 'Running-app tests', short: 'OWASP ZAP', icon: Target, text: 'ZAP tests your deployed staging app from the outside. Findings show as ZAP-<id> with ZAP’s own advice.' },
];

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const SEVERITY_GUIDE = [
  { s: 'critical', t: 'Exploitable now. The push is blocked until it is fixed.' },
  { s: 'high', t: 'Serious. Fix it this sprint.' },
  { s: 'medium', t: 'Real but harder to exploit. Plan a fix.' },
  { s: 'low', t: 'Hygiene. Fix when you are nearby.' },
];

/** The ZAP scan modes, shaped like rules so they share one list. */
const ZAP_MODES = [
  { id: 'baseline', severity: 'medium', title: 'Baseline (passive)', flag: '--mode baseline', summary: 'Crawls the app and inspects every response: missing security headers, cookie flags, information leaks, mixed content, CSRF tokens. Sends no attacks, so it is safe on staging.', plan: 'Fortis Core' },
  { id: 'full', severity: 'high', title: 'Full scan (active)', flag: '--mode full', summary: 'Adds attack simulation: SQL injection, cross-site scripting, path traversal, command injection and more. Never allowed against production targets.', plan: 'Fortis Plus' },
  { id: 'api', severity: 'high', title: 'API scan (OpenAPI)', flag: '--mode full --openapi', summary: 'Pass --openapi with your spec and ZAP tests every operation directly, including ones a crawler cannot find. Counts as a full scan.', plan: 'Fortis Plus' },
];

type Item = {
  key: string;
  pack: PackId;
  severity: string;
  title: string;
  /** The rule id, or the CLI flag for a ZAP mode. */
  label: string;
  summary: string;
  extraLabel: 'Fix' | 'Plan';
  extra: string;
  ruleId?: string;
};

const ITEMS: Item[] = [
  ...RULE_CATALOG.map((r) => ({ key: r.id, pack: r.pack as PackId, severity: r.severity, title: r.title, label: r.id, summary: r.summary, extraLabel: 'Fix' as const, extra: r.fix, ruleId: r.id })),
  ...ZAP_MODES.map((m) => ({ key: `zap-${m.id}`, pack: 'zap' as PackId, severity: m.severity, title: m.title, label: m.flag, summary: m.summary, extraLabel: 'Plan' as const, extra: m.plan })),
].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || a.title.localeCompare(b.title));

function RuleRow({ item, open, onToggle, health }: { item: Item; open: boolean; onToggle: () => void; health: Map<string, Health> | null }) {
  const bodyId = useId();
  const h = item.ruleId ? health?.get(item.ruleId) : undefined;
  return (
    <li className={`rule-row${open ? ' open' : ''}`}>
      <button type="button" className="rule-head" aria-expanded={open} aria-controls={bodyId} onClick={onToggle}>
        <SeverityPill severity={item.severity} />
        <span className="t">
          <b>{item.title}</b>
          <span>{item.label}</span>
        </span>
        {h && h.open > 0 ? <span className="seen">{h.open} open</span> : null}
        <Chevron className="chev" aria-hidden="true" />
      </button>
      {open ? (
        <div className="rule-body" id={bodyId}>
          <p>{item.summary}</p>
          <div className="rule-fix"><span>{item.extraLabel}</span>{item.extra}</div>
          {item.ruleId && health ? <HealthLine h={h} /> : null}
        </div>
      ) : null}
    </li>
  );
}

export default function RulesPage() {
  const { org } = useSession();
  const [pack, setPack] = useState<PackId>('fintech');
  const [q, setQ] = useState('');
  const [sev, setSev] = useState<string>('all');
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const [legend, setLegend] = useState(false);
  const plan = PLANS[(org.plan as keyof typeof PLANS) ?? 'free'] ?? PLANS.free;
  const { data: healthData } = useSWR<{ rules: Health[] }>(`/v1/orgs/${org.id}/rules/health`, fetcher);
  const health = useMemo(() => (healthData ? new Map(healthData.rules.map((h) => [h.ruleId, h])) : null), [healthData]);
  const tabsId = useId();

  const needle = q.trim().toLowerCase();
  const searching = needle !== '';
  const matches = (i: Item) => !searching || [i.title, i.label, i.summary].some((s) => s.toLowerCase().includes(needle));
  const included = (id: PackId) => (id === 'zap' ? plan.dast !== 'none' : plan.rulePacks.includes(id));

  // What each tab would show, so its number stays right while you search.
  const countByPack = new Map<PackId, number>();
  for (const i of ITEMS) if (matches(i)) countByPack.set(i.pack, (countByPack.get(i.pack) ?? 0) + 1);

  // A search looks across every pack; otherwise only the chosen pack shows.
  const scope = ITEMS.filter((i) => matches(i) && (searching || i.pack === pack));
  const sevCount = (s: string) => scope.filter((i) => s === 'all' || i.severity === s).length;
  const visible = scope.filter((i) => sev === 'all' || i.severity === sev);
  const current = PACKS.find((p) => p.id === pack)!;
  const allOpen = visible.length > 0 && visible.every((i) => open.has(i.key));

  const toggle = (key: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const toggleAll = () => setOpen(allOpen ? new Set() : new Set(visible.map((i) => i.key)));

  const groups = searching ? PACKS.map((p) => ({ pack: p, items: visible.filter((i) => i.pack === p.id) })).filter((g) => g.items.length) : [{ pack: current, items: visible }];

  return (
    <div className="stack">
      <section className="band reveal">
        <span className="eyebrow">What Fortis checks</span>
        <h1 className="display"><Words>Rules written for <span className="it accent">money-moving code.</span></Words></h1>
        <p className="lead">Every rule explains the risk in plain language and ships with the fix. Rules run on your machine; only masked results are sent here.</p>
      </section>

      <div className="packs stagger" role="tablist" aria-label="Rule packs">
        {PACKS.map((p) => {
          const Icon = p.icon;
          const n = countByPack.get(p.id) ?? 0;
          return (
            <button
              key={p.id}
              type="button"
              role="tab"
              id={`${tabsId}-${p.id}`}
              aria-selected={!searching && pack === p.id}
              aria-controls={`${tabsId}-panel`}
              className="pack"
              onClick={() => { setPack(p.id); setQ(''); setSev('all'); }}
            >
              <span className="pack-ic"><Icon /></span>
              <span className="nm"><b>{p.name}</b><small>{p.short}</small></span>
              <span className="n">{n}</span>
            </button>
          );
        })}
      </div>

      <section className="card reveal" id={`${tabsId}-panel`} role="tabpanel" aria-labelledby={`${tabsId}-${pack}`} style={{ ['--d' as string]: '120ms' }}>
        <div className="rules-head">
          <div>
            <h3>{searching ? `Results for “${q.trim()}”` : current.name}</h3>
            <span className="small">{searching ? `${visible.length} ${visible.length === 1 ? 'rule' : 'rules'} across every pack` : current.text}</span>
          </div>
          {searching ? null : <span className={`pill ${included(pack) ? 'p-ok' : 'p-mute'}`}>{included(pack) ? `Included in ${plan.name}` : 'Fortis Core and above'}</span>}
        </div>

        <div className="rules-tools">
          <label className="search">
            <Search />
            <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search every rule" aria-label="Search rules" />
          </label>
          <div className="seg" role="group" aria-label="Filter by severity">
            <button type="button" className={sev === 'all' ? 'on' : ''} onClick={() => setSev('all')}>All<span className="k">{sevCount('all')}</span></button>
            {SEVERITIES.filter((s) => sevCount(s) > 0 || sev === s).map((s) => (
              <button key={s} type="button" className={sev === s ? 'on' : ''} onClick={() => setSev(s)}>
                {s[0]!.toUpperCase() + s.slice(1)}<span className="k">{sevCount(s)}</span>
              </button>
            ))}
          </div>
          <button type="button" className="linkbtn" aria-expanded={legend} onClick={() => setLegend((v) => !v)}>How severity works</button>
          <button type="button" className="linkbtn" style={{ marginLeft: 'auto' }} onClick={toggleAll} disabled={visible.length === 0}>
            {allOpen ? 'Collapse all' : 'Expand all'}
          </button>
        </div>

        {legend ? (
          <div className="sev-legend">
            {SEVERITY_GUIDE.map((g) => (
              <div key={g.s}><SeverityPill severity={g.s} /><p>{g.t}</p></div>
            ))}
          </div>
        ) : null}

        {visible.length === 0 ? (
          <Empty
            icon={<Search />}
            title="No rules match"
            text="Try a different word, or clear the severity filter."
            action={<button className="btn btn-outline btn-sm" onClick={() => { setQ(''); setSev('all'); }}>Clear filters</button>}
          />
        ) : (
          groups.map((g) => (
            <div key={g.pack.id}>
              {searching ? <div className="rule-group">{g.pack.name} · {g.items.length}</div> : null}
              <ul className="rule-list">
                {g.items.map((item) => (
                  <RuleRow key={item.key} item={item} open={open.has(item.key)} onToggle={() => toggle(item.key)} health={health} />
                ))}
              </ul>
            </div>
          ))
        )}
      </section>
    </div>
  );
}
