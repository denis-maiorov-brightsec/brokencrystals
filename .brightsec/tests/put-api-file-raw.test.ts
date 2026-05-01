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

test('PUT /api/file/raw?path=some%2Fpath%2Fto%2Ffile.png', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['http_method_fuzzing', 'file_upload', 'lfi', 'full_path_disclosure', 'csrf', 'html_injection', 'xss', 'osi'],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.BODY],
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
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/file/raw?path=some%2Fpath%2Fto%2Ffile.png`,
      body: 'Hello, world!',
      headers: { 'Content-Type': 'text/plain', 'Accept': '*/*' }
    });
});