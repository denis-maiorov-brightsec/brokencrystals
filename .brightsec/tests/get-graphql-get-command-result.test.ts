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

test('GET /graphql getCommandResult', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'osi',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'graphql_introspection',
        'full_path_disclosure'
      ],
      attackParamLocations: [AttackParamLocation.QUERY],
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
      method: HttpMethod.GET,
      url: `${baseUrl}/graphql?operationName=getCommandResult&query=query+getCommandResult%28%24command%3A+String%21%29+%7B+getCommandResult%28command%3A+%24command%29+%7D&variables=%7B%22command%22%3A%22uname+-a%22%7D%7D`,
      headers: { Accept: 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});