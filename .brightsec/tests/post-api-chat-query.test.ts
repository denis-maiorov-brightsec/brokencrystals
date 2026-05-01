import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSize = process.env.SECTESTER_SCAN_POOL_SIZE ? +process.env.SECTESTER_SCAN_POOL_SIZE || undefined : undefined;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /api/chat/query', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'prompt_injection',
        'server_side_js_injection',
        'html_injection',
        'xss',
        'csrf',
        'secret_tokens',
        'full_path_disclosure',
        'ssrf',
        'open_database'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL', 'MikroORM'],
        user_roles: ['admin', 'user']
      },
      poolSize
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/chat/query`,
      body: [
        { role: 'user', content: 'Hello, can you help me with my account?' },
        { role: 'assistant', content: 'Of course — what would you like to know?' }
      ],
      headers: { 'Content-Type': 'application/json' }
    });
});