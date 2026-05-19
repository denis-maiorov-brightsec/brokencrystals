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

test('POST /api/chat/query', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'prompt_injection',
        'proto_pollution',
        'full_path_disclosure',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        }
      ],
      attackParamLocations: [AttackParamLocation.BODY],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/api/chat/query`,
      body: [
        {
          role: 'user',
          content: 'What is the refund policy for annual plans?'
        },
        {
          role: 'assistant',
          content: 'Annual plans can be refunded within 14 days of purchase.'
        },
        {
          role: 'user',
          content: 'Does that also apply to discounted plans?'
        }
      ],
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});