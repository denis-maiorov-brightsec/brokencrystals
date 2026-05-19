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

test('POST /api/mcp', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'sqli',
        'ssti',
        'server_side_js_injection',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'open_database',
        'secret_tokens',
        'full_path_disclosure'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/api/mcp`,
      body: {
        jsonrpc: '2.0',
        method: 'initialize',
        params: {},
        id: 1
      },
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});