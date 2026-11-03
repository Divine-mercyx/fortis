export type Org = { id: string; name: string; slug: string; plan: string; planName: string; role: string };
export type User = { id: string; email: string; name: string };
export type Me = { user: User; orgs: Org[] };

export type FindingRow = {
  id: string;
  projectId: string;
  projectName: string;
  ruleId: string;
  kind?: 'code' | 'dast';
  targetId?: string | null;
  severity: string;
  title: string;
  file: string;
  line: number | null;
  status: string;
  firstSeenAt: string;
  lastSeenAt: string;
  fixedAt: string | null;
};

export type ScanRow = {
  id: string;
  projectId: string;
  projectName: string;
  trigger: string;
  kind?: 'code' | 'dast';
  dastMode?: 'baseline' | 'full' | null;
  scope: string;
  branch: string | null;
  commit: string | null;
  findingsCount: number;
  newCount: number;
  fixedCount: number;
  reopenedCount: number;
  durationMs: number | null;
  createdAt: string;
};

export type ProjectRow = {
  id: string;
  name: string;
  slug: string;
  repoUrl: string | null;
  createdAt: string;
  openFindings: number;
  openCritical: number;
  lastScanAt: string | null;
};
