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

test('POST /api/safe-files', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'ssrf',
        'amazon_s3_takeover',
        'open_cloud_storage',
        'html_injection',
        'xss',
        'iframe_injection',
        'css_injection',
        'csrf',
        'proto_pollution',
        'file_upload'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
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
      url: `${baseUrl}/api/safe-files`,
      body: {
        name: 'example.txt',
        url: 'https://trusted.example.com/files/example.txt'
      },
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});