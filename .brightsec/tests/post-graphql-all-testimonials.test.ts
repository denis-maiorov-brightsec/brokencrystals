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

test('POST /graphql allTestimonials', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'graphql_introspection',
        'sqli',
        'xss',
        'html_injection',
        'csrf',
        'business_constraint_bypass',
        'id_enumeration'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL', 'MikroORM'],
        user_roles: ['admin', 'user']
      },
      poolSize: Number(process.env.SECTESTER_SCAN_POOL_SIZE) || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/graphql`,
      body: {
        query: 'query allTestimonials { allTestimonials { name title message } }',
        variables: {}
      },
      headers: { 'Content-Type': 'application/json' }
    });
});