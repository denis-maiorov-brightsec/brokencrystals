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

test('OPTIONS /api/users/one/john.doe%40example.com/photo', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'jwt',
        'file_upload',
        'xxe',
        'xss',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'http_method_fuzzing'
      ],
      attackParamLocations: [
        AttackParamLocation.HEADER,
        AttackParamLocation.PATH,
        AttackParamLocation.QUERY
      ],
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
      method: HttpMethod.OPTIONS,
      url: `${baseUrl}/api/users/one/john.doe%40example.com/photo?email=john.doe%40example.com`,
      headers: {
        Accept: '*/*',
        Authorization: 'Bearer eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiam9obi5kb2VAZXhhbXBsZS5jb20ifQ==.signature',
        Origin: 'https://app.example.com',
        'Access-Control-Request-Method': 'PUT',
        'Access-Control-Request-Headers': 'authorization, content-type',
        'User-Agent': 'BrokenCrystalsClient/1.0',
        Host: 'example.com'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});