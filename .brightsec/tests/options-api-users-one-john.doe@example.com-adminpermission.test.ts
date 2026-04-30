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

test('OPTIONS /api/users/one/john.doe@example.com/adminpermission?email=john.doe%40example.com', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'id_enumeration',
        'xxe',
        'ldapi',
        'full_path_disclosure',
        'csrf',
        'open_database',
        'ldap (alternative mapping)'
      ],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.QUERY, AttackParamLocation.HEADER],
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
      method: HttpMethod.OPTIONS,
      url: `${baseUrl}/api/users/one/john.doe@example.com/adminpermission?email=john.doe%40example.com`,
      headers: {
        Accept: '*/*',
        'Access-Control-Request-Headers': 'Authorization, Content-Type',
        'Access-Control-Request-Method': 'GET',
        Host: 'example.com',
        Origin: 'https://example.com',
        'User-Agent': 'curl/7.88.1'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});