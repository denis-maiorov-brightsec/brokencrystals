import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSizeValue = Number(process.env.SECTESTER_SCAN_POOL_SIZE);
const poolSize = poolSizeValue ? poolSizeValue : undefined;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('OPTIONS /api/users', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'http_method_fuzzing',
        'csrf',
        'improper_asset_management',
        'full_path_disclosure',
        'xss'
      ],
      attackParamLocations: [AttackParamLocation.HEADER],
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
      method: HttpMethod.OPTIONS,
      url: `${baseUrl}/api/users`,
      headers: { 'Access-Control-Request-Headers': 'OPTIONS, GET, POST, DELETE' }
    });
});