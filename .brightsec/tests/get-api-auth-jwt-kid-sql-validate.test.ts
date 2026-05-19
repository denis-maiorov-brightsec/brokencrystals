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

test('GET /api/auth/jwt/kid-sql/validate', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['sqli', 'jwt'],
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
      url: `${baseUrl}/api/auth/jwt/kid-sql/validate`,
      headers: {
        authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZDEifQ.eyJ1c2VyIjoiam9obkBleGFtcGxlLmNvbSIsImV4cCI6MTg5MzQ1NjAwMH0.YWJjMTIzc2lnbmF0dXJl'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});