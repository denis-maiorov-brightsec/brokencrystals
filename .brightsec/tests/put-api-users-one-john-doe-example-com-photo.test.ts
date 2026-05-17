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
      tests: ['file_upload', 'xxe', 'osi'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL'],
        user_roles: ['admin', 'user', 'basic', 'oidc']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/users/one/john.doe@example.com/photo`,
      body: `--boundary\r\nContent-Disposition: form-data; name="file"; filename="profile.svg"\r\nContent-Type: image/svg+xml\r\n\r\n<svg>...</svg>\r\n--boundary--\r\n`,
      headers: { Authorization: 'Bearer <JWT_TOKEN>' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});