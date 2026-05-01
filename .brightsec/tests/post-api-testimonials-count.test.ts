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

test('POST /api/testimonials/count?query=select count(*) as count from testimonial', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['sqli', 'full_path_disclosure', 'open_database', 'business_constraint_bypass'],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/api/testimonials/count?query=select%20count(*)%20as%20count%20from%20testimonial`,
      body: {
        query: 'select count(*) as count from testimonial'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});