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

test('POST /graphql latestProducts', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'sqli',
        'graphql_introspection',
        'full_path_disclosure',
        'xss',
        'html_injection',
        'business_constraint_bypass',
        'csrf',
        'proto_pollution'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/graphql`,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Host: 'example.com',
        'User-Agent': 'BrokenCrystalsClient/1.0'
      },
      body: {
        query: "query latestProducts {\n  latestProducts {\n    name\n    category\n    photoUrl\n    description\n    viewsCount\n  }\n}\n",
        operationName: 'latestProducts',
        variables: {}
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});