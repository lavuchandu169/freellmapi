import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EventEmitter } from 'node:events';

// Security audit finding (localagent fork patch, VULN-03:
// freellmapi-server:auth-setup-loopback-trust-bypass). The real vulnerable
// surface — POST /api/auth/setup accepting any loopback caller with no
// code while userCount() === 0 — lives in server/src/routes/auth.ts and
// isn't exercised here (this suite mocks the HTTP app entirely, same as
// server-host-boot.test.ts). What this proves instead is the fix's actual
// mechanism: that server-host.ts's own account-claim happens BEFORE
// listen() is ever called (so no HTTP request — attacker or legitimate —
// can reach the server while the account is still unclaimed), and that
// ensureSessionToken() never blindly adopts whichever account happens to
// exist.
//
// Unlike server-host-boot.test.ts's auth.js mock (which stubs
// userCount/createUser/createSession as inert no-ops to isolate the
// startup ORDER test from account logic), this suite backs auth.js with a
// real in-memory user store shared with the mocked getDb(), so the actual
// claim-then-lookup behavior runs for real.

const calls: string[] = [];
let users: { id: number; email: string }[] = [];
let nextId = 1;

function normalizeEmailReal(email: string): string {
  return email.trim().toLowerCase();
}

vi.mock('../../../server/src/env.js', () => ({}));

vi.mock('../../../server/src/db/index.js', () => ({
  initDb: vi.fn(() => {
    calls.push('initDb');
  }),
  getDb: vi.fn(() => ({
    prepare: (sql: string) => ({
      get: (param: string) => {
        if (sql.includes('WHERE email')) {
          return users.find((u) => u.email === param);
        }
        if (sql.includes('ORDER BY id ASC LIMIT 1')) {
          return users[0];
        }
        throw new Error(`unexpected query in test fake: ${sql}`);
      },
    }),
  })),
  getUnifiedApiKey: vi.fn(),
}));

vi.mock('../../../server/src/lib/proxy.js', () => ({
  restoreProxySettings: vi.fn(),
  flushProxyCache: vi.fn(),
}));

vi.mock('../../../server/src/lib/log-redaction.js', () => ({
  installLogRedaction: vi.fn(() => () => undefined),
}));

vi.mock('../../../server/src/lib/process-safety-net.js', () => ({
  installProcessSafetyNet: vi.fn(),
}));

vi.mock('../../../server/src/services/ratelimit.js', () => ({
  cleanupExpiredCooldowns: vi.fn(() => 0),
}));

vi.mock('../../../server/src/services/cache.js', () => ({
  loadCacheFromDb: vi.fn(),
}));

vi.mock('../../../server/src/services/cooldown-probe.js', () => ({
  startCooldownProbe: vi.fn(),
}));

vi.mock('../../../server/src/services/backups.js', () => ({
  startBackupScheduler: vi.fn(() => () => undefined),
}));

vi.mock('../../../server/src/services/custom-model-sync.js', () => ({
  startCustomModelSync: vi.fn(() => null),
}));

vi.mock('../../../server/src/lib/wake-detect.js', () => ({
  startWakeDetect: vi.fn(),
}));

vi.mock('../../../server/src/app.js', () => ({
  createApp: vi.fn(() => ({
    listen: (_port: number, _host: string) => {
      calls.push('listen');
      const server = new EventEmitter();
      setImmediate(() => server.emit('listening'));
      return server;
    },
  })),
}));

vi.mock('../../../server/src/services/health.js', () => ({
  startHealthChecker: vi.fn(),
  checkAllKeys: vi.fn(async () => ({})),
}));

vi.mock('../../../server/src/services/catalog-sync.js', () => ({
  startCatalogSync: vi.fn(),
}));

vi.mock('../../../server/src/services/auth.js', () => ({
  userCount: vi.fn(() => users.length),
  createUser: vi.fn((email: string, _password: string) => {
    calls.push('createUser');
    const user = { id: nextId++, email: normalizeEmailReal(email) };
    users.push(user);
    return { userId: user.id, email: user.email };
  }),
  createSession: vi.fn((userId: number) => `session-for-${userId}`),
  normalizeEmail: normalizeEmailReal,
}));

vi.mock('../../../server/src/lib/scheduler.js', () => ({
  NodeScheduler: class {},
}));

async function boot(): Promise<void> {
  const { startServer } = await import('../server-host.js');
  await startServer({
    dbPath: ':memory:',
    clientDist: '/tmp/client-dist',
    host: '127.0.0.1',
    preferredPort: 45998,
  });
}

beforeEach(() => {
  calls.length = 0;
  users = [];
  nextId = 1;
  vi.resetModules();
});

describe('server-host admin-claim race fix (VULN-03)', () => {
  it('claims the machine user before the server starts listening, not after', async () => {
    await boot();
    const claimedAt = calls.indexOf('createUser');
    const listenAt = calls.indexOf('listen');
    expect(claimedAt).toBeGreaterThanOrEqual(0);
    expect(listenAt).toBeGreaterThanOrEqual(0);
    expect(claimedAt).toBeLessThan(listenAt);
  });

  it('a fresh boot results in exactly one user, the machine user', async () => {
    await boot();
    expect(users.length).toBe(1);
    expect(users[0]!.email).toBe('desktop@localhost');
  });

  it('ensureSessionToken mints a session for the machine user it just claimed', async () => {
    await boot();
    const { ensureSessionToken } = await import('../server-host.js');
    const token = ensureSessionToken();
    expect(token).toBe(`session-for-${users[0]!.id}`);
  });

  it('booting twice (simulating an app restart) does not create a second account', async () => {
    await boot();
    const firstCount = users.length;
    calls.length = 0;
    await boot();
    expect(users.length).toBe(firstCount);
  });

  it(
    'ensureSessionToken refuses to adopt a foreign account if the machine user is somehow missing ' +
      '(defense in depth: the pre-listen claim above is what actually prevents this in practice)',
    async () => {
      const { ensureSessionToken } = await import('../server-host.js');
      // Simulate a foreign account existing with no machine-user row at
      // all — the exact shape of "someone else won the race" that the old
      // blind ORDER BY id ASC LIMIT 1 query would have silently adopted.
      users.push({ id: 999, email: 'attacker@example.com' });
      expect(() => ensureSessionToken()).toThrow(/refusing to adopt/i);
    },
  );
});
