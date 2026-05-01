import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSize = (() => {
  const value = Number(process.env.SECTESTER_SCAN_POOL_SIZE);
  return value ? value : undefined;
})();

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /api/auth/login', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'jwt', 'ldapi', 'sqli', 'nosql', 'secret_tokens', 'full_path_disclosure', 'open_database', 'http_method_fuzzing', 'improper_asset_management'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
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
      url: `${baseUrl}/api/auth/login`,
      body: {
        user: 'john.doe@example.com',
        password: 'Pa55w0rd!',
        op: 'basic',
        csrf: 'csrf-token-1234567890abcdef'
      },
      headers: {
        'Content-Type': 'application/json',
        Cookie: '_csrf=csrf-token-1234567890abcdef',
        authorization: 'Bearer existing-access-token'
      }
    });
});