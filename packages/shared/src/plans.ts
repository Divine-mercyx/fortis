/**
 * Plans and what each one unlocks. The API enforces these; the dashboard and
 * marketing site display them. Prices are in kobo (₦1 = 100 kobo).
 */

export const PLAN_IDS = ['free', 'core', 'plus', 'enterprise'] as const;
export type PlanId = (typeof PLAN_IDS)[number];

export const RULE_PACKS = ['secrets', 'dependencies', 'fintech'] as const;
export type RulePack = (typeof RULE_PACKS)[number];

/** Running-app (DAST) testing with OWASP ZAP: none, passive baseline, or full active scan. */
export const DAST_MODES = ['baseline', 'full'] as const;
export type DastMode = (typeof DAST_MODES)[number];

export type PlanLimits = {
  name: string;
  /** Monthly price in kobo; null means priced by agreement. */
  monthlyPriceKobo: number | null;
  /** null means unlimited. */
  maxProjects: number | null;
  maxSeats: number | null;
  rulePacks: readonly RulePack[];
  dashboard: boolean;
  stagingChecks: boolean;
  /** Highest ZAP mode allowed against verified staging targets. */
  dast: 'none' | DastMode;
  maxTargets: number | null;
  releaseGates: boolean;
  evidencePack: 'none' | 'basic' | 'full';
  historyMonths: number | null;
  sso: boolean;
};

export const PLANS: Record<PlanId, PlanLimits> = {
  free: {
    name: 'Fortis Free',
    monthlyPriceKobo: 0,
    maxProjects: 1,
    maxSeats: 1,
    rulePacks: ['secrets', 'dependencies'],
    dashboard: false,
    stagingChecks: false,
    dast: 'none',
    maxTargets: 0,
    releaseGates: false,
    evidencePack: 'none',
    historyMonths: 1,
    sso: false,
  },
  core: {
    name: 'Fortis Core',
    monthlyPriceKobo: 450_000_00,
    maxProjects: 5,
    maxSeats: 10,
    rulePacks: ['secrets', 'dependencies', 'fintech'],
    dashboard: true,
    stagingChecks: false,
    dast: 'baseline',
    maxTargets: 2,
    releaseGates: false,
    evidencePack: 'basic',
    historyMonths: 12,
    sso: false,
  },
  plus: {
    name: 'Fortis Plus',
    monthlyPriceKobo: 750_000_00,
    maxProjects: 20,
    maxSeats: 40,
    rulePacks: ['secrets', 'dependencies', 'fintech'],
    dashboard: true,
    stagingChecks: true,
    dast: 'full',
    maxTargets: 10,
    releaseGates: true,
    evidencePack: 'full',
    historyMonths: 36,
    sso: true,
  },
  enterprise: {
    name: 'Fortis Enterprise',
    monthlyPriceKobo: 1_000_000_00,
    maxProjects: null,
    maxSeats: null,
    rulePacks: ['secrets', 'dependencies', 'fintech'],
    dashboard: true,
    stagingChecks: true,
    dast: 'full',
    maxTargets: null,
    releaseGates: true,
    evidencePack: 'full',
    historyMonths: null,
    sso: true,
  },
};

export function isPlanId(value: string): value is PlanId {
  return (PLAN_IDS as readonly string[]).includes(value);
}

/** Whether a plan may run a ZAP mode (full includes baseline). */
export function planAllowsDast(plan: PlanLimits, mode: DastMode): boolean {
  if (plan.dast === 'none') return false;
  return plan.dast === 'full' || mode === 'baseline';
}
