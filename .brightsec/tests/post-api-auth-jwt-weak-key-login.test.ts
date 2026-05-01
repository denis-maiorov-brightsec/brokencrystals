import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSize = process.env.SECTESTER_SCAN_POOL_SIZE ? Number(process.env.SECTESTER_SCAN_POOL_SIZE) || undefined : undefined;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /api/auth/jwt/weak-key/login', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['jwt', 'secret_tokens', 'csrf', 'http_method_fuzzing', 'full_path_disclosure', 'improper_asset_management'],
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
      url: `${baseUrl}/api/auth/jwt/weak-key/login`,
      body: {
        user: 'john.doe@example.com',
        password: 'Pa55w0rd!',
        op: 'basic'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});