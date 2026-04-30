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

test('PUT /api/users/one/john.doe@example.com/photo', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'file_upload',
        'xxe',
        'ssrf',
        'jwt',
        'full_path_disclosure',
        'csrf',
        'open_database',
        'improper_asset_management'
      ],
      attackParamLocations: [
        AttackParamLocation.PATH,
        AttackParamLocation.QUERY,
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER
      ],
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
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/users/one/john.doe@example.com/photo?email=john.doe%40example.com`,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW',
        Authorization: process.env.BRIGHT_AUTH_ID ? `Bearer ${process.env.BRIGHT_AUTH_ID}` : ''
      },
      // Representing multipart upload in a simple form for the scan runner
      body: {
        file: 'avatar.png'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});