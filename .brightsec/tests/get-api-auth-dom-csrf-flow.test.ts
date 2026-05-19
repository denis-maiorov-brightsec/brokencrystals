import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /api/auth/dom-csrf-flow', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'full_path_disclosure'],
      attackParamLocations: [AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL'],
        user_roles: ['admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/auth/dom-csrf-flow`,
      headers: {
        fingerprint: '9f3a2b1c4d5e6f708192a3b4c5d6e7f8'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});