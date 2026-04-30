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

test('POST /api/testimonials', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'xss',
        'jwt',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'csrf',
        'server_side_js_injection',
        'open_database',
        'sqli',
        'html_injection'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: [
          'PostgreSQL (via @mikro-orm/postgresql and pg)'
        ],
        user_roles: ['admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/testimonials`,
      body: {
        name: 'Jane Doe',
        title: 'Great Service',
        message: 'I loved the product — it exceeded my expectations. The team was responsive and helpful.'
      },
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: process.env.BRIGHT_AUTH_ID ? `Bearer ${process.env.BRIGHT_AUTH_ID}` : 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.example.signature'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});