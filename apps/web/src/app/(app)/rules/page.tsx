'use client';

import { useState } from 'react';
import useSWR from 'swr';

import { PLANS, RULE_CATALOG, type RulePack } from '@fortis/shared';

import { Bank, Key, Layers, Search, Target } from '@/components/icons';
import { Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { SeverityPill } from '@/components/ui';
import { InfoTip } from '@/components/widgets';
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

const PACKS: { id: RulePack; name: string; icon: typeof Key; text: string }[] = [
  { id: 'fintech', name: 'Fintech rule pack', icon: Bank, text: 'Checks written for money-moving code: transfers, wallets, webhooks, KYC data and OTPs.' },
  { id: 'secrets', name: 'Secrets', icon: Key, text: 'API keys, tokens and private keys committed to the repository, including Paystack, Flutterwave and Monnify secret keys.' },
  { id: 'dependencies', name: 'Dependencies', icon: Layers, text: 'Known vulnerabilities in the open-source packages your project uses.' },
];

const SEVERITY_GUIDE = [
  { s: 'critical', t: 'Exploitable now. The push is blocked until it is fixed.' },
  { s: 'high', t: 'Serious. Fix it this sprint.' },
  { s: 'medium', t: 'Real but harder to exploit. Plan a fix.' },
  { s: 'low', t: 'Hygiene. Fix when you are nearby.' },
];

export default function RulesPage() {
  const { org } = useSession();
  const [q, setQ] = useState('');
  const plan = PLANS[(org.plan as keyof typeof PLANS) ?? 'free'] ?? PLANS.free;
  const match = (s: string) => s.toLowerCase().includes(q.trim().toLowerCase());
  const { data: health } = useSWR<{ rules: Health[] }>(`/v1/orgs/${org.id}/rules/health`, fetcher);
  const byRule = new Map((health?.rules ?? []).map((h) => [h.ruleId, h]));

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <span className="eyebrow reveal">What Fortis checks</span>
          <h1 className="display"><Words>Rules written for <span className="it accent">money-moving code.</span></Words></h1>
          <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>
            Every rule explains the risk in plain language and ships with the fix. Rules run on your machine; only masked results are sent here.
          </p>
        </div>
        <label className="search reveal" style={{ ['--d' as string]: '200ms', minWidth: 260 }}>
          <Search />
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search rules" aria-label="Search rules" />
        </label>
      </div>

      <section className="card card-pad reveal sev-guide" style={{ ['--d' as string]: '220ms' }}>
        <h3 className="h3" style={{ marginBottom: 14 }}>How severity works <InfoTip text="Severity is set by the rule, based on how easy the issue is to exploit and how much money or data is at stake." /></h3>
        <div className="sev-guide-grid">
          {SEVERITY_GUIDE.map((g) => (
            <div key={g.s}><SeverityPill severity={g.s} /><p>{g.t}</p></div>
          ))}
        </div>
      </section>

      {PACKS.map((pack, pi) => {
        const rules = RULE_CATALOG.filter((r) => r.pack === pack.id && (match(r.title) || match(r.id) || match(r.summary)));
        if (!rules.length) return null;
        const included = plan.rulePacks.includes(pack.id);
        const Icon = pack.icon;
        return (
          <section key={pack.id} className="card reveal" style={{ ['--d' as string]: `${260 + pi * 60}ms` }}>
            <div className="card-head">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span className="pack-ic"><Icon /></span>
                <div>
                  <h3>{pack.name}</h3>
                  <span className="small">{pack.text}</span>
                </div>
              </div>
              <span className={`pill ${included ? 'p-ok' : 'p-mute'}`}>{included ? `Included in ${plan.name}` : 'Fortis Core and above'}</span>
            </div>
            <div className="rule-grid">
              {rules.map((r, i) => (
                <article key={r.id} className="rule-card row-in" style={{ ['--i' as string]: i }}>
                  <div className="rule-top"><SeverityPill severity={r.severity} /><span className="mono muted">{r.id}</span></div>
                  <h4>{r.title}</h4>
                  <p>{r.summary}</p>
                  <div className="rule-fix"><span>Fix</span>{r.fix}</div>
                  {health ? <HealthLine h={byRule.get(r.id)} /> : null}
                </article>
              ))}
            </div>
          </section>
        );
      })}

      <section className="card reveal" style={{ ['--d' as string]: '460ms' }}>
        <div className="card-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span className="pack-ic"><Target /></span>
            <div>
              <h3>Running-app tests · OWASP ZAP</h3>
              <span className="small">ZAP tests your deployed staging app from the outside. Findings show as ZAP-&lt;id&gt; with ZAP&apos;s own advice.</span>
            </div>
          </div>
          <span className={`pill ${plan.dast !== 'none' ? 'p-ok' : 'p-mute'}`}>{plan.dast !== 'none' ? `Included in ${plan.name}` : 'Fortis Core and above'}</span>
        </div>
        <div className="rule-grid">
          {[
            { id: 'baseline', sev: 'medium', title: 'Baseline (passive)', text: 'Crawls the app and inspects every response: missing security headers, cookie flags, information leaks, mixed content, CSRF tokens. Sends no attacks, so it is safe on staging.', plan: 'Fortis Core' },
            { id: 'full', sev: 'high', title: 'Full scan (active)', text: 'Adds attack simulation: SQL injection, cross-site scripting, path traversal, command injection and more. Never allowed against production targets.', plan: 'Fortis Plus' },
            { id: 'api', sev: 'high', title: 'API scan (OpenAPI)', text: 'Pass --openapi with your spec and ZAP tests every operation directly, including ones a crawler cannot find. Counts as a full scan.', plan: 'Fortis Plus' },
          ].map((m, i) => (
            <article key={m.id} className="rule-card row-in" style={{ ['--i' as string]: i }}>
              <div className="rule-top"><SeverityPill severity={m.sev} /><span className="mono muted">--mode {m.id === 'api' ? 'full --openapi' : m.id}</span></div>
              <h4>{m.title}</h4>
              <p>{m.text}</p>
              <div className="rule-fix"><span>Plan</span>{m.plan}</div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
