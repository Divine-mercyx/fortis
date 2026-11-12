/**
 * Which compliance controls each finding is evidence for. Used by the dashboard, the evidence
 * pack and the CLI. The mapping is guidance for auditors and compliance officers, not legal
 * advice: confirm it against your own control set.
 *
 * PCI DSS references are requirement numbers from PCI DSS v4.0.1. The CBN Risk-Based
 * Cybersecurity Framework is referenced by domain, because institutions map its clauses
 * differently. NDPA references are sections of the Nigeria Data Protection Act 2023.
 */

export const FRAMEWORKS = {
  pci: { name: 'PCI DSS v4.0.1', short: 'PCI DSS' },
  cbn: { name: 'CBN Risk-Based Cybersecurity Framework', short: 'CBN RBCF' },
  ndpa: { name: 'Nigeria Data Protection Act 2023', short: 'NDPA' },
} as const;
export type FrameworkId = keyof typeof FRAMEWORKS;

export type Control = { framework: FrameworkId; ref: string; title: string };

const PCI = {
  '1.3.1': 'Inbound traffic to the cardholder data environment is restricted to what is necessary',
  '3.3.1': 'Sensitive authentication data is not retained after authorisation',
  '3.5.1': 'The primary account number is rendered unreadable anywhere it is stored',
  '6.2.3': 'Bespoke software is reviewed before release to find and correct vulnerabilities',
  '6.2.4': 'Software engineering techniques prevent common attacks (injection, access control, business logic, cryptography)',
  '6.3.1': 'Security vulnerabilities are identified and ranked',
  '6.3.3': 'Known vulnerabilities are fixed by installing patches and updates',
  '6.4.1': 'Public-facing web applications are protected against attacks',
  '6.4.3': 'Scripts on payment pages are authorised and their integrity assured',
  '8.3.1': 'All user access is authenticated',
  '8.6.2': 'Passwords and secrets are not hard-coded in scripts, files or source code',
  '11.3.1': 'Internal vulnerability scans are performed and findings resolved',
} as const;
const CBN = {
  appsec: 'Application security and secure software development',
  vuln: 'Vulnerability management',
  vapt: 'Vulnerability assessment and penetration testing',
  access: 'Identity and access management',
  data: 'Data protection and privacy',
  crypto: 'Cryptography and key management',
  logging: 'Security monitoring and logging',
} as const;
const NDPA = {
  's.24': 'Principles of processing, including data minimisation and security',
  's.39': 'Security, integrity and confidentiality of personal data',
  's.40': 'Personal data breach notification',
} as const;

const pci = (ref: keyof typeof PCI): Control => ({ framework: 'pci', ref, title: PCI[ref] });
const cbn = (ref: keyof typeof CBN): Control => ({ framework: 'cbn', ref: CBN[ref], title: CBN[ref] });
const ndpa = (ref: keyof typeof NDPA): Control => ({ framework: 'ndpa', ref, title: NDPA[ref] });

const BY_RULE: Record<string, Control[]> = {
  'FX-SEC-001': [pci('8.6.2'), cbn('crypto'), cbn('appsec')],
  'SEC-GEN-001': [pci('8.6.2'), cbn('crypto'), cbn('appsec')],
  'FX-OWN-001': [pci('6.2.4'), cbn('access'), cbn('appsec'), ndpa('s.39')],
  'FX-MONEY-001': [pci('6.2.4'), cbn('appsec')],
  'FX-PCI-001': [pci('3.3.1'), pci('3.5.1'), cbn('data'), cbn('logging'), ndpa('s.39')],
  'FX-REF-001': [pci('6.2.4'), cbn('appsec'), cbn('crypto')],
  'FX-AMT-001': [pci('6.2.4'), cbn('appsec')],
  'FX-BOLA-001': [pci('6.2.4'), cbn('access'), cbn('vapt'), ndpa('s.39'), ndpa('s.40')],
  'FX-BOLA-002': [pci('6.2.4'), cbn('access'), cbn('vapt'), ndpa('s.39'), ndpa('s.40')],
  'FX-AUTH-001': [pci('6.2.4'), pci('8.3.1'), cbn('access'), cbn('vapt'), ndpa('s.39'), ndpa('s.40')],
  'FX-HOOK-001': [pci('6.2.4'), cbn('appsec')],
  'FX-TXN-001': [pci('6.2.4'), cbn('appsec')],
  'FX-IDEM-001': [pci('6.2.4'), cbn('appsec')],
  'FX-OTP-001': [pci('6.2.4'), cbn('access'), cbn('crypto')],
  'FX-PII-002': [cbn('data'), cbn('logging'), ndpa('s.24'), ndpa('s.39')],
  'DEP-OSV': [pci('6.3.1'), pci('6.3.3'), cbn('vuln')],
  'SUP-IMG-001': [pci('6.3.3'), cbn('vuln')],
  'SUP-IMG-002': [pci('6.3.3'), cbn('vuln')],
  'SUP-IMG-003': [pci('6.3.1'), pci('6.3.3'), cbn('vuln')],
  'SUP-GHA-001': [pci('6.2.3'), cbn('appsec'), cbn('crypto')],
  'SUP-GHA-002': [pci('6.2.4'), cbn('appsec'), cbn('access')],
  'FX-RATE-001': [pci('6.2.4'), pci('8.3.1'), cbn('access'), cbn('appsec')],
  'FX-JWT-001': [pci('6.2.4'), pci('8.3.1'), cbn('access'), cbn('crypto')],
  'FX-RESET-001': [pci('6.2.4'), pci('8.3.1'), cbn('access'), ndpa('s.39')],
  'INF-NET-001': [pci('1.3.1'), cbn('access'), cbn('vapt')],
  'INF-NET-002': [pci('1.3.1'), cbn('access')],
  'INF-STO-001': [pci('1.3.1'), cbn('data'), ndpa('s.39'), ndpa('s.40')],
  'INF-DB-001': [pci('1.3.1'), cbn('access'), cbn('data'), ndpa('s.39')],
  'INF-K8S-001': [pci('1.3.1'), cbn('access')],
};

/** ZAP alerts whose fix protects payment-page scripts (CSP, Subresource Integrity). */
const PAYMENT_PAGE_SCRIPTS = /^ZAP-(10038|90003)\b/;

export function controlsFor(ruleId: string): Control[] {
  if (BY_RULE[ruleId]) return BY_RULE[ruleId]!;
  if (ruleId.startsWith('ZAP-')) {
    const base = [pci('6.4.1'), pci('6.2.4'), pci('11.3.1'), cbn('vapt'), cbn('vuln')];
    return PAYMENT_PAGE_SCRIPTS.test(ruleId) ? [...base, pci('6.4.3')] : base;
  }
  return [cbn('appsec')];
}

/** Controls the Fortis programme itself produces evidence for, whatever was found. */
export const PROGRAMME_CONTROLS: { control: Control; evidence: string }[] = [
  { control: pci('6.2.3'), evidence: 'Every push and CI run is scanned before release; blocked pushes and fixes are recorded.' },
  { control: pci('6.3.1'), evidence: 'Findings are identified and ranked by severity, with dependency advisories from OSV.' },
  { control: pci('11.3.1'), evidence: 'Staging targets are scanned with ZAP on a schedule or after each deploy.' },
  { control: cbn('vapt'), evidence: 'Running-app tests and two-user access checks against verified, authorised staging targets.' },
  { control: cbn('vuln'), evidence: 'Each finding has an owner-visible status, timestamps and a full change history.' },
  { control: ndpa('s.39'), evidence: 'Checks for customer data exposure: BVN/NIN in logs, records readable by other customers.' },
];
