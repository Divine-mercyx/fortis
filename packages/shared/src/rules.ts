import type { RulePack } from './plans';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export type RuleMeta = {
  id: string;
  pack: RulePack;
  title: string;
  severity: Severity;
  summary: string;
  fix: string;
  /** The fix in Python's terms, where `fix` is written for JavaScript. */
  fixPython?: string;
  /** The fix in Go's terms. */
  fixGo?: string;
  /** The fix in C#'s terms. */
  fixCsharp?: string;
  /** The fix in PHP's terms. */
  fixPhp?: string;
  /** The fix in Java's and Kotlin's terms. */
  fixJvm?: string;
};

/**
 * Catalogue of rule metadata shown in the dashboard and sent to the CLI with
 * each rule pack. Detection logic lives in the CLI's rules package.
 */
export const RULE_CATALOG: readonly RuleMeta[] = [
  {
    id: 'FX-SEC-001',
    // Free: a leaked payment key is a secret, and the free plan promises secret scanning.
    pack: 'secrets',
    title: 'Payment-provider secret key in code',
    severity: 'critical',
    summary: 'A Paystack, Stripe, Korapay, BudPay, Flutterwave, Monnify, SeerBit, OPay or Squad secret key (or a Stripe restricted key or webhook secret) is committed to the repository or config.',
    fix: 'Move the key to an environment variable or secret manager, then rotate it with the provider: Paystack (Settings → API Keys & Webhooks → generate a new secret key), Stripe (Developers → API keys → roll the key), Korapay or BudPay (regenerate the secret key in that dashboard\'s API keys settings), Flutterwave (Settings → API Keys → generate new keys), Monnify (Developers → API Keys → regenerate), SeerBit (Account settings → API keys → regenerate), OPay (merchant dashboard → API keys → reset the private key), Squad (Merchant Settings → API & Webhook → regenerate).',
  },
  {
    id: 'FX-OWN-001',
    pack: 'fintech',
    title: 'Money record read without an ownership check',
    severity: 'critical',
    summary: 'A transfer, wallet or account is loaded by ID without scoping it to the signed-in user.',
    fix: 'Filter the query by the signed-in user, for example { _id: id, ownerId: req.user.id }, and return 404 otherwise.',
    fixPython: 'Filter by the signed-in user, for example get_object_or_404(Wallet, pk=pk, user=request.user), or override get_queryset in Django REST.',
    fixGo: 'Filter by the signed-in user in the query, for example db.Where("id = ? AND user_id = ?", id, userID).First(&wallet), and return 404 when nothing matches.',
    fixCsharp: 'Filter by the signed-in user, for example FirstOrDefaultAsync(w => w.Id == id && w.UserId == userId), or use resource-based authorization with IAuthorizationService. [Authorize] alone only checks that someone is logged in.',
    fixPhp: "Check a policy with $this->authorize('view', $wallet), or scope the query to the signed-in user: $request->user()->wallets()->findOrFail($id).",
    fixJvm: "Add @PreAuthorize or @PostAuthorize with an ownership check, or query by the signed-in user: walletRepository.findByIdAndOwnerId(id, userId). Return 404 when nothing matches.",
  },
  {
    id: 'FX-HOOK-001',
    pack: 'fintech',
    title: 'Payment webhook without a signature check',
    severity: 'critical',
    summary: 'A webhook credits value without verifying the provider signature header.',
    fix: "Verify the provider's HMAC signature (for example x-paystack-signature) against the raw body before acting.",
    fixPython: "Compute the HMAC of the raw body and compare it to the provider's signature header with hmac.compare_digest before acting.",
    fixGo: "Compute the HMAC of the raw body with crypto/hmac, and compare it to the provider's signature header with hmac.Equal before acting.",
    fixCsharp: "Compute the HMAC of the raw body with HMACSHA512, and compare it to the provider's signature header with CryptographicOperations.FixedTimeEquals before acting.",
    fixPhp: "Compute hash_hmac('sha512', $request->getContent(), $secret), and compare it to the provider's signature header with hash_equals before acting.",
    fixJvm: "Compute the HMAC of the raw body with Mac.getInstance(\"HmacSHA512\"), and compare it to the provider's signature header with MessageDigest.isEqual before acting.",
  },
  {
    id: 'FX-TXN-001',
    pack: 'fintech',
    title: 'Balance update outside a transaction',
    severity: 'high',
    summary: 'A debit or credit reads and writes a balance in separate steps, open to race conditions.',
    fix: 'Use a single atomic update or a database transaction with a row lock.',
    fixPython: 'Use update(balance=F("balance") - amount), or lock the row first with select_for_update() (with_for_update() in SQLAlchemy). transaction.atomic alone is not enough.',
    fixGo: 'Do the update in one statement, such as db.Model(&wallet).Update("balance", gorm.Expr("balance - ?", amount)), or lock the row inside db.Transaction with clause.Locking.',
    fixCsharp: 'Do the update in one statement with ExecuteUpdateAsync and SetProperty, or use BeginTransaction with a row lock, or a concurrency token.',
    fixPhp: "Use $wallet->decrement('balance', $amount), or lock the row with lockForUpdate() inside DB::transaction().",
    fixJvm: "Make the method @Transactional and load the row with @Lock(LockModeType.PESSIMISTIC_WRITE), or update it in one statement with @Modifying @Query.",
  },
  {
    id: 'FX-PII-002',
    pack: 'fintech',
    title: 'BVN or NIN exposed',
    severity: 'high',
    summary: 'A BVN or NIN is written to logs, errors or API responses.',
    fix: 'Remove it from the output or mask all but the last four digits.',
  },
  {
    id: 'FX-IDEM-001',
    pack: 'fintech',
    title: 'Transfer without an idempotency key',
    severity: 'high',
    summary: 'A money-out endpoint can be replayed and pay out twice on a retry.',
    fix: 'Require an idempotency key and store it with the transfer, rejecting repeats.',
  },
  {
    id: 'FX-OTP-001',
    pack: 'fintech',
    title: 'Weak or leaked one-time passcode',
    severity: 'high',
    summary: 'An OTP is logged, returned in a response, generated with a predictable random function or has no attempt limit.',
    fix: 'Generate with crypto.randomInt, never log or return it, and limit attempts.',
    fixPython: 'Generate with secrets.randbelow, never log or return it, and limit attempts.',
    fixGo: 'Generate with crypto/rand, never math/rand. Never log or return it, and limit attempts.',
    fixCsharp: 'Generate with RandomNumberGenerator.GetInt32, never System.Random. Never log or return it, and limit attempts.',
    fixPhp: "Generate with random_int(), never rand() or mt_rand(). Never log or return it, and limit attempts.",
    fixJvm: "Generate with SecureRandom, never java.util.Random or Math.random(). Never log or return it, and limit attempts.",
  },
  {
    id: 'SEC-GEN-001',
    pack: 'secrets',
    title: 'Generic secret in code',
    severity: 'high',
    summary: 'An API key, token, private key or database password (in a connection URL or connection string) is committed to the repository. Named keys include Mono and Dojah secret keys and Africa\'s Talking API keys.',
    fix: 'Move it to an environment variable or secret manager and rotate it.',
  },
  {
    id: 'DEP-OSV',
    pack: 'dependencies',
    title: 'Vulnerable dependency',
    severity: 'medium',
    summary: 'A package has a known vulnerability in public advisory data.',
    fix: 'Upgrade to the fixed version. Each finding names the version that clears every advisory on the package and the command for your package manager; for an indirect dependency, it names the direct dependency that pulls it in.',
  },
  {
    id: 'SUP-IMG-001',
    pack: 'dependencies',
    title: 'Docker base image with no tag or latest',
    severity: 'low',
    summary: 'A Dockerfile builds FROM an image with no tag, or the latest tag, so each build can get a different image: new vulnerabilities, or a compromised upload, arrive without anyone choosing them.',
    fix: 'Pin the image to a release, such as node:22.11-alpine, and better still to its digest: FROM node:22.11-alpine@sha256:<digest>.',
  },
  {
    id: 'SUP-IMG-002',
    pack: 'dependencies',
    title: 'Docker base image not pinned by digest',
    severity: 'info',
    summary: "A production Dockerfile names its base image by tag only. A tag can be moved to point at a different image, by the publisher or by anyone who takes over their account. Dev, test and example Dockerfiles aren't checked.",
    fix: "Add the digest of the image you've tested: FROM node:22.11-alpine@sha256:<digest>. docker buildx imagetools inspect <image> shows it, and Dependabot or Renovate can keep it current.",
  },
  {
    id: 'SUP-IMG-003',
    pack: 'dependencies',
    title: 'Docker base image is end-of-life',
    severity: 'medium',
    summary: 'A Dockerfile builds on an OS or runtime release that no longer gets security fixes, such as debian:buster, node:16 or python:3.7. Dates come from endoflife.date and are refreshed with each Fortis release.',
    fix: 'Move to a supported release of the same image, test, and rebuild. https://endoflife.date lists each release and its end date.',
  },
  {
    id: 'SUP-GHA-001',
    pack: 'dependencies',
    title: 'Third-party GitHub Action not pinned to a commit',
    severity: 'medium',
    summary: "A workflow uses another publisher's action by tag or branch, such as @v4. Whoever controls that repository can move the tag, and the next run executes their code with your workflow's secrets and token. Actions from GitHub itself (actions/* and github/*) aren't flagged.",
    fix: "Pin the action to the full commit SHA of the release you've reviewed, keeping the tag as a comment so Dependabot can update it: uses: owner/action@<40-character SHA> # v4.2.0.",
  },
  {
    id: 'SUP-GHA-002',
    pack: 'dependencies',
    title: "pull_request_target workflow runs the pull request's code",
    severity: 'high',
    summary: "A workflow triggered by pull_request_target checks out or fetches the pull request's own code. That trigger runs with the repository's secrets and a write token, so anyone who opens a pull request from a fork can run code with them.",
    fix: "Use the pull_request trigger for anything that builds or tests the contributor's code. If you need pull_request_target (to label or comment), don't check out the pull request's head, or move the privileged step to a separate workflow_run workflow that never runs that code.",
  },
  {
    id: 'INF-NET-001',
    pack: 'infrastructure',
    title: 'Firewall open to the internet on an admin or database port',
    severity: 'high',
    summary: 'A Terraform security group, firewall or network security rule lets any address on the internet (0.0.0.0/0) reach SSH, Remote Desktop, a database, a cache or a cluster API. Exposed admin and database ports are scanned within minutes of going live and are a common first step in breaches.',
    fix: 'Allow only the addresses that need access (your VPN or office range, a bastion host, another security group), or keep the service on a private network. For admin access, use a bastion, SSM Session Manager, IAP or a VPN instead of an open port.',
  },
  {
    id: 'INF-NET-002',
    pack: 'infrastructure',
    title: 'Docker Compose publishes a database or cache port',
    severity: 'medium',
    summary: "A production Compose file publishes a database, cache or queue port (Postgres, MySQL, Redis, MongoDB and others) on every network interface. On a server that makes it reachable from the internet, and Docker's own firewall rules bypass ufw. Dev, test and override Compose files aren't checked.",
    fix: 'Remove the ports entry so only other services on the Compose network can reach it, or bind it to the machine itself: "127.0.0.1:5432:5432".',
  },
  {
    id: 'INF-STO-001',
    pack: 'infrastructure',
    title: 'Public storage bucket',
    severity: 'high',
    summary: 'A Terraform file makes an S3 bucket, Cloud Storage bucket or Azure storage container readable by anyone: a public ACL, a public access block turned off, or allUsers access. Public buckets holding KYC documents, statements and backups are a leading cause of fintech data leaks.',
    fix: 'Keep buckets private (on AWS, set all four public access block settings to true) and share individual files with presigned or signed URLs, or through a CDN with origin access control.',
  },
  {
    id: 'INF-DB-001',
    pack: 'infrastructure',
    title: 'Database reachable from the internet',
    severity: 'high',
    summary: 'A managed database is given a public address: RDS or Redshift with publicly_accessible = true, Cloud SQL with 0.0.0.0/0 as an authorised network, or an Azure database firewall rule that allows every address. Its password is then the only thing between the internet and your customer records.',
    fix: 'Turn off the public address and keep the database in private subnets. Connect from your app servers, a bastion or a VPN, or through the Cloud SQL Auth Proxy or a private endpoint.',
  },
  {
    id: 'INF-K8S-001',
    pack: 'infrastructure',
    title: 'Kubernetes service exposes a database or cache',
    severity: 'high',
    summary: 'A Kubernetes Service of type LoadBalancer or NodePort puts a database, cache or queue port on an address outside the cluster, with no loadBalancerSourceRanges to limit who can connect. Internal load balancers are not flagged.',
    fix: 'Use type: ClusterIP so only pods in the cluster can reach it. If something outside the cluster needs it, use an internal load balancer and set loadBalancerSourceRanges.',
  },
  {
    id: 'FX-MONEY-001',
    pack: 'fintech',
    title: 'Money stored or computed as floating point',
    severity: 'high',
    summary: 'Floating point can\'t hold most decimal amounts exactly: 0.1 + 0.2 is 0.30000000000000004. On money, these errors add up into ledgers that don\'t balance and customers charged the wrong amount.',
    fix: 'Keep money as an integer in kobo (or the smallest unit), or use a decimal type: BigInt, a decimal library, and NUMERIC or DECIMAL columns.',
    fixPython: 'Use decimal.Decimal, or an integer in kobo, with models.DecimalField or Numeric columns. Parse with Decimal(value), not float(value).',
  },
  {
    id: 'FX-PCI-001',
    pack: 'fintech',
    title: 'Card data logged, stored in plain text or sent to analytics',
    severity: 'critical',
    summary: 'A card number or CVV is written to logs, sent to an analytics tool, or kept in a plain text column. PCI DSS forbids keeping a CVV after authorisation at all, and logs spread to places with far weaker access controls.',
    fix: 'Keep only the provider\'s token and the last 4 digits. Never store or log a CVV. If you must store a card number, encrypt it, and bring that system into PCI DSS scope.',
  },
  {
    id: 'FX-REF-001',
    pack: 'fintech',
    title: 'Transaction reference built from a timestamp or weak random',
    severity: 'high',
    summary: 'A reference from Math.random() or the time can be guessed, and two requests in the same moment can collide. Providers use the reference to tell payments apart, so this leads to rejected payments, or to one being mistaken for another.',
    fix: 'Generate it with crypto.randomUUID(), or crypto.randomBytes(16).toString(\'hex\').',
    fixPython: 'Generate it with uuid.uuid4() or secrets.token_hex(16).',
  },
  {
    id: 'FX-AMT-001',
    pack: 'fintech',
    title: 'Charge amount taken from the request',
    severity: 'critical',
    summary: 'The amount sent to the payment provider comes from the client, so anyone can change it and pay ₦1 for a ₦100,000 order. Fortis skips top-ups and donations, where the customer chooses the amount.',
    fix: 'Read the price from your own database, using the order or plan ID, and charge that. Then check the amount again when the provider confirms the payment.',
  },
  {
    id: 'FX-BOLA-001',
    pack: 'fintech',
    title: "One customer can read another customer's records",
    severity: 'critical',
    summary: "Found by `fortis access` on staging: test user B asked for test user A's loan, wallet or transfer by ID and got it. This is broken object-level authorisation (BOLA/IDOR), the most common way fintech data leaks.",
    fix: "Scope every lookup to the signed-in customer (WHERE id = $1 AND customer_id = $2) and return 404 when the record isn't theirs.",
  },
  {
    id: 'FX-BOLA-002',
    pack: 'fintech',
    title: "One customer can change or delete another customer's records",
    severity: 'critical',
    summary: "Found by `fortis access --writes` on staging: test user B sent an update or delete for a throwaway record owned by test user A, and A's record changed. This is broken object-level authorisation (BOLA/IDOR) on a write.",
    fix: "Check that the record belongs to the signed-in customer before writing (UPDATE … WHERE id = $1 AND customer_id = $2) and return 404 when it isn't theirs.",
  },
  {
    id: 'FX-AUTH-001',
    pack: 'fintech',
    title: 'Customer records readable without logging in',
    severity: 'critical',
    summary: 'Found by `fortis access` on staging: a request with no login at all returned a customer record.',
    fix: 'Put the route behind your authentication middleware and add a test that an anonymous request gets 401.',
  },
];

/** The fix for a finding, in the language of the file it's in. */
export function fixFor(rule: Pick<RuleMeta, 'fix' | 'fixPython' | 'fixGo' | 'fixCsharp' | 'fixPhp' | 'fixJvm'>, file: string): string {
  if (/\.py$/i.test(file) && rule.fixPython) return rule.fixPython;
  if (/\.go$/i.test(file) && rule.fixGo) return rule.fixGo;
  if (/\.cs$/i.test(file) && rule.fixCsharp) return rule.fixCsharp;
  if (/\.php$/i.test(file) && rule.fixPhp) return rule.fixPhp;
  if (/\.(java|kt)$/i.test(file) && rule.fixJvm) return rule.fixJvm;
  return rule.fix;
}

export function findRule(id: string): RuleMeta | undefined {
  return RULE_CATALOG.find((r) => r.id === id);
}
