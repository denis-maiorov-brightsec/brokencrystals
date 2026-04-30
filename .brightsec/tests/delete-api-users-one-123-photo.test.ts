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

test('DELETE /api/users/one/123/photo?isAdmin=true', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'bopla',
        'jwt',
        'id_enumeration',
        'csrf',
        'file_upload',
        'xxe'
      ],
      attackParamLocations: [
        AttackParamLocation.PATH,
        AttackParamLocation.QUERY,
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
      method: HttpMethod.DELETE,
      url: `${baseUrl}/api/users/one/123/photo?isAdmin=true`,
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer xxx.eyJ1c2VyIjoiYWRtaW5AZXhhbXBsZS5jb20ifQ.yyy'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});