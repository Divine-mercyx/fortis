import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { cvssSeverity, scanDependencies } from '../src/rules/dependencies';
import { findLockfiles, parseLockfile } from '../src/rules/lockfiles';
import { isRequestHandler, pyClasses, pyCodeOnly, pyFunctions, pyStatementAt } from '../src/rules/python';
import { TEST_PATH, type SourceFile } from '../src/rules/types';
import { buildContext } from '../src/scan';

const source = (text: string, path = 'app/views.py'): SourceFile => ({ path, text, lines: text.split('\n') });

describe('reading Python', () => {
  it('blanks strings and comments but keeps f-string values', () => {
    expect(pyCodeOnly('logger.info("BVN must be 11 digits")')).not.toMatch(/BVN/);
    expect(pyCodeOnly('logger.info(f"BVN {user.bvn}")')).toContain('user.bvn');
    expect(pyCodeOnly('x = 1  # user.bvn')).not.toContain('bvn');
    expect(pyCodeOnly('rf"{a}" + f"{{literal}}"')).toContain('a');
    expect(pyCodeOnly('f"{{literal}}"')).not.toContain('literal');
    expect(pyCodeOnly('"""bvn\nnin"""\nreal')).toContain('real');
    expect(pyCodeOnly('"""bvn\nnin"""\nreal')).not.toContain('bvn');
    expect(pyCodeOnly("'it\\'s bvn' + x")).not.toContain('bvn');
    // A word ending in f before a quote isn't an f-string prefix.
    expect(pyCodeOnly('self"{bvn}"')).not.toContain('bvn');
  });

  it('follows a statement across lines', () => {
    const file = source('logger.info(\n    "x",\n    user.bvn,\n)\nother()');
    expect(pyStatementAt(file, 1)).toContain('user.bvn');
    expect(pyStatementAt(file, 1)).not.toContain('other');
  });

  it('finds functions with their decorators, parameters, class and body', () => {
    const file = source(`@login_required
@app.route(
    "/wallets/<id>",
    methods=["POST"],
)
def wallet(id, db=Depends(get_db)):
    # a comment
    lookup(id)

    return 1

class TransferView(APIView):
    permission_classes = []

    async def post(self, request, pk: int = 0):
        return pk

def after():
    pass
`);
    const [wallet, post, after] = pyFunctions(file);
    expect(wallet).toMatchObject({ name: 'wallet', params: ['id', 'db'], line: 6, bodyLine: 7, endLine: 10 });
    expect(wallet!.decorators.map((d) => d.line)).toEqual([1, 2]);
    expect(wallet!.body).toContain('lookup(id)');
    expect(post).toMatchObject({ name: 'post', className: 'TransferView', classBases: 'APIView', params: ['request', 'pk'] });
    expect(after!.className).toBeUndefined();
    expect(after!.decorators).toEqual([]);
    expect(pyClasses(file).map((c) => c.name)).toEqual(['TransferView']);
  });

  it('tells request handlers from other functions', () => {
    const fns = pyFunctions(source(`def django_view(request, pk):
    pass

def helper(wallet_id):
    pass

@router.get("/x")
def fastapi_route(id: int):
    pass

class Detail(APIView):
    def get(self, request):
        pass
    def _load(self, request):
        pass
`));
    expect(fns.map((f) => [f.name, isRequestHandler(f)])).toEqual([
      ['django_view', true], ['helper', false], ['fastapi_route', true], ['get', true], ['_load', false],
    ]);
  });

  it('treats Python test files and migrations as test code', () => {
    for (const p of ['app/test_views.py', 'test_views.py', 'app/views_test.py', 'conftest.py', 'app/migrations/0001_initial.py', 'tests/x.py']) {
      expect(TEST_PATH.test(p), p).toBe(true);
    }
    for (const p of ['app/views.py', 'app/latest_rates.py', 'app/contest.py']) expect(TEST_PATH.test(p), p).toBe(false);
  });

  it('collects idempotency helpers, module-level functions only', () => {
    const ctx = buildContext([source('# idempotency\ndef with_guard(fn):\n    return fn\n\nclass X:\n    def post(self):\n        pass\n', 'app/guards.py')]);
    expect(ctx.idempotencyHelpers.has('with_guard')).toBe(true);
    expect(ctx.idempotencyHelpers.has('post')).toBe(false);
  });
});

const devMap = (file: string, text: string, manifest?: string) => Object.fromEntries(parseLockfile(file, text, manifest).packages.map((p) => [p.name, p.dev]));

describe('Python lockfiles', () => {
  it('uv.lock: walks from the project, and leaves the project itself out', () => {
    const text = `version = 1

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "flask" },
]

[package.optional-dependencies]
pg = [
    { name = "psycopg" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[[package]]
name = "flask"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "Werkzeug", extra = ["watchdog"] },
]
wheels = [
    { url = "https://x/flask.whl", hash = "sha256:abc" },
]

[[package]]
name = "werkzeug"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "psycopg"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "pluggy" },
]

[[package]]
name = "pluggy"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
`;
    expect(devMap('uv.lock', text)).toEqual({ flask: false, werkzeug: false, psycopg: false, pytest: true, pluggy: true });
  });

  it("uv.lock: follows extras, such as fastapi[standard]", () => {
    const text = `[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "fastapi", extra = ["standard"] },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[[package]]
name = "fastapi"
version = "0.100.0"
source = { registry = "https://pypi.org/simple" }

[package.optional-dependencies]
standard = [
    { name = "uvicorn" },
]

[[package]]
name = "uvicorn"
version = "0.30.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
`;
    expect(devMap('uv.lock', text)).toEqual({ fastapi: false, uvicorn: false, pytest: true });
  });

  it('uv.lock: counts everything as production when the project lists no dependencies', () => {
    const text = '[[package]]\nname = "app"\nversion = "1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "x"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\n';
    expect(devMap('uv.lock', text)).toEqual({ x: false });
  });

  it("poetry.lock v2: reads each package's groups", () => {
    const text = '[[package]]\nname = "django"\nversion = "4.2"\ngroups = ["main"]\n\n[[package]]\nname = "shared"\nversion = "1.0"\ngroups = ["main", "dev"]\n\n[[package]]\nname = "pytest"\nversion = "7.0"\ngroups = ["dev"]\n\n[metadata]\nlock-version = "2.1"\n';
    expect(devMap('poetry.lock', text)).toEqual({ django: false, shared: false, pytest: true });
  });

  it('poetry.lock before 2.0: walks the graph from pyproject.toml', () => {
    const lock = `[[package]]
name = "django"
version = "4.2"

[package.dependencies]
asgiref = ">=3.6"
sqlparse = { version = ">=0.3" }

[package.extras]
argon2 = ["argon2-cffi"]

[[package]]
name = "asgiref"
version = "3.7"

[[package]]
name = "sqlparse"
version = "0.4"

[[package]]
name = "pytest"
version = "7.0"

[metadata]
lock-version = "2.0"
`;
    const pyproject = '[tool.poetry.dependencies]\npython = "^3.11"\nDjango = "^4.2"\n\n[tool.poetry.group.dev.dependencies]\npytest = "^7"\n';
    expect(devMap('poetry.lock', lock, pyproject)).toEqual({ django: false, asgiref: false, sqlparse: false, pytest: true });
    expect(devMap('poetry.lock', lock)).toEqual({ django: false, asgiref: false, sqlparse: false, pytest: false }); // no pyproject: can't tell
    expect(devMap('poetry.lock', lock, '[tool.poetry.dependencies]\npython = "^3.11"\nother = "1"\n')).toEqual({ django: false, asgiref: false, sqlparse: false, pytest: false }); // roots not found
  });

  it('poetry.lock: reads [project] dependencies too', () => {
    const lock = '[[package]]\nname = "flask"\nversion = "2.0"\n\n[[package]]\nname = "pytest"\nversion = "7.0"\n';
    expect(devMap('poetry.lock', lock, '[project]\nname = "x"\ndependencies = [\n  "flask>=2",\n]\n')).toEqual({ flask: false, pytest: true });
  });

  it('pdm.lock: uses groups', () => {
    expect(devMap('pdm.lock', '[metadata]\ngroups = ["default", "dev"]\n\n[[package]]\nname = "flask"\nversion = "2.0"\ngroups = ["default"]\n\n[[package]]\nname = "pytest"\nversion = "7.0"\ngroups = ["dev"]\n')).toEqual({ flask: false, pytest: true });
  });

  it('pylock.toml: reads [[packages]], counting those with no version', () => {
    const text = 'lock-version = "1.0"\n\n[[packages]]\nname = "Flask"\nversion = "2.0.0"\n\n[[packages.wheels]]\nname = "flask.whl"\n\n[[packages]]\nname = "private"\n[packages.vcs]\ntype = "git"\n';
    const parsed = parseLockfile('pylock.toml', text);
    expect(parsed.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['flask@2.0.0']);
    expect(parsed.skipped).toBe(1);
    expect(findLockfiles(['pylock.toml', 'pylock.prod.toml'])).toHaveLength(2);
  });

  it('requirements: a wildcard pin has no exact version to check', () => {
    const parsed = parseLockfile('requirements.txt', 'django==3.2.*\nflask==2.0.0\n');
    expect(parsed.packages.map((p) => p.name)).toEqual(['flask']);
    expect(parsed.skipped).toBe(1);
  });

  it('requirements: knows a hand-written file from a compiled one', () => {
    expect(parseLockfile('requirements.txt', 'flask==2.0.0\n').directOnly).toBe(true);
    expect(parseLockfile('requirements.txt', 'flask==2.0.0\n    # via -r requirements.in\n').directOnly).toBe(false);
    expect(parseLockfile('requirements.txt', 'flask==2.0.0 \\\n    --hash=sha256:abc\n').directOnly).toBe(false);
    expect(parseLockfile('requirements.txt', '# This file is autogenerated by pip-compile\nflask==2.0.0\n').directOnly).toBe(false);
    expect(parseLockfile('constraints.txt', 'flask==2.0.0\n').directOnly).toBe(false);
  });

  it('requirements: finds the usual file names, and prefers a real lock beside them', () => {
    expect(findLockfiles(['dev-requirements.txt', 'requirements_test.txt', 'requirements/base.txt', 'constraints.txt', 'readme.txt'])).toHaveLength(4);
    expect(findLockfiles(['api/pdm.lock', 'api/requirements.txt'])).toEqual(['api/pdm.lock']);
  });
});

describe('advisory severity', () => {
  it('scores a CVSS 3 vector', () => {
    expect(cvssSeverity('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe('critical'); // 9.8
    expect(cvssSeverity('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe('critical'); // 10
    expect(cvssSeverity('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')).toBe('high'); // 7.5
    expect(cvssSeverity('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe('medium'); // 6.1
    expect(cvssSeverity('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')).toBe('low'); // 1.8
    expect(cvssSeverity('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
  });

  const advisories = (vulns: Record<string, object>): typeof fetch => async (url) => {
    const u = String(url);
    if (u.endsWith('/v1/querybatch')) return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'PYSEC-1' }] }] }));
    return new Response(JSON.stringify(vulns[decodeURIComponent(u.slice(u.lastIndexOf('/') + 1))] ?? {}), { status: 200 });
  };
  const severityFor = async (vulns: Record<string, object>) => {
    const root = mkdtempSync(join(tmpdir(), 'fortis-sev-'));
    writeFileSync(join(root, 'requirements.txt'), 'pillow==8.0.0\n');
    const r = await scanDependencies(root, ['requirements.txt'], { fetchImpl: advisories(vulns) });
    rmSync(root, { recursive: true, force: true });
    return r.detections[0]!.severity;
  };

  it('uses the GitHub alias when an advisory has no severity of its own', async () => {
    expect(await severityFor({ 'PYSEC-1': { id: 'PYSEC-1', aliases: ['GHSA-a'] }, 'GHSA-a': { id: 'GHSA-a', database_specific: { severity: 'CRITICAL' } } })).toBe('critical');
  });

  it('falls back on the CVSS vector, then medium', async () => {
    expect(await severityFor({ 'PYSEC-1': { id: 'PYSEC-1', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }] } })).toBe('high');
    expect(await severityFor({ 'PYSEC-1': { id: 'PYSEC-1' } })).toBe('medium');
  });
});
