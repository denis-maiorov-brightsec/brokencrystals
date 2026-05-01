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

test('GET /api/users/ldap', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'ldapi',
        'full_path_disclosure',
        'id_enumeration',
        'business_constraint_bypass',
        'html_injection',
        'xss'
      ],
      attackParamLocations: [AttackParamLocation.QUERY],
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
      method: HttpMethod.GET,
      url: `${baseUrl}/api/users/ldap?query=%28%26%28objectClass%3Dperson%29%28objectClass%3Duser%29%28email%3Djohn.doe%40example.com%29%29`
    });
});