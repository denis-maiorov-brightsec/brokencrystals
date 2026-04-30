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

test('POST /graphql AllProducts', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'graphql_introspection',
        'sqli',
        'business_constraint_bypass',
        'csrf',
        'xss',
        'html_injection',
        'ssrf',
        'server_side_js_injection',
        'proto_pollution',
        'open_database',
        'jwt'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/graphql`,
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNjA5MDAwMDAsImV4cCI6MTYwOTAwMzYwMH0.signature',
        'Content-Type': 'application/json',
        Host: 'example.com'
      },
      body: {
        query: "query AllProducts { allProducts { name category photoUrl description viewsCount } }",
        operationName: 'AllProducts',
        variables: {}
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});