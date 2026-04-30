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

test('GET /api/nestedJson?depth=3', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'business_constraint_bypass',
        'date_manipulation',
        'proto_pollution',
        'ssrI',
        'server_side_js_injection',
        'ssti',
        'xxe',
        'osi',
        'secret_tokens',
        'open_database',
        'full_path_disclosure',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'improper_asset_management',
        'xss'
      ],
      attackParamLocations: [AttackParamLocation.QUERY],
      // ensure the date_manipulation test does not skip static params
      skipStaticParams: false,
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: [
          'PostgreSQL (via @mikro-orm/postgresql and pg)'
        ],
        user_roles: [
          'admin'
        ]
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/nestedJson?depth=3`,
      headers: {
        Accept: 'application/json',
        Host: 'example.com',
        'User-Agent': 'Mozilla/5.0 (compatible; ExampleClient/1.0)'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});