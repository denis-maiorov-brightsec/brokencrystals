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

test(
  'GET /api/email/sendSupportEmail?content=:content&name=:name&subject=:subject&to=:to',
  { signal: AbortSignal.timeout(timeout) },
  async () => {
    await runner
      .createScan({
        tests: [
          'email_injection',
          'proto_pollution',
          'csrf',
          {
            name: 'broken_access_control',
            options: {
              auth: process.env.BRIGHT_AUTH_ID
            }
          },
          'html_injection'
        ],
        attackParamLocations: [AttackParamLocation.QUERY],
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
        url: `${baseUrl}/api/email/sendSupportEmail?content=I%20would%20like%20to%20request%20help%20regarding%20my%20recent%20order.&name=Bob%20Dylan&subject=Help%20Request&to=username%40email.com`,
        auth: process.env.BRIGHT_AUTH_ID
      });
  }
);