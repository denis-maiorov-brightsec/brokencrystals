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

test('OPTIONS /api/users/fullinfo/john.doe@example.com', { signal: AbortSignal.timeout(timeout) }, async () => {
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
        'file_upload',
        'xxe',
        'jwt',
        'full_path_disclosure',
        'http_method_fuzzing',
        'ldapi',
        'sqli',
        'nosql'
      ],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.HEADER],
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
      method: HttpMethod.OPTIONS,
      url: `${baseUrl}/api/users/fullinfo/john.doe%40example.com`,
      headers: {
        Accept: '*/*',
        'Access-Control-Request-Headers': 'OPTIONS, GET, POST, DELETE',
        'Access-Control-Request-Method': 'GET',
        Host: 'example.com',
        Origin: 'https://example-client.example.com',
        'User-Agent': 'curl/7.85.0'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});