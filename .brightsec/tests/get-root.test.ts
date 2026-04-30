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

test('GET /', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'version_control_systems',
        'full_path_disclosure',
        'secret_tokens',
        'html_injection',
        'xss',
        'iframe_injection',
        'css_injection',
        'proto_pollution',
        'improper_asset_management',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        }
      ],
      attackParamLocations: [AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL (via @mikro-orm/postgresql and pg)'],
        user_roles: ['admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/`,
      headers: {
        Accept: 'application/json',
        Deprecation: 'true',
        Host: 'example.com',
        Sunset: 'Wed, 31 Dec 2026 23:59:59 GMT',
        'User-Agent': 'curl/8.0'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});