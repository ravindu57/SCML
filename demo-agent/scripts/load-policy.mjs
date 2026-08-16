#!/usr/bin/env node
/**
 * Push this agent's policy into a running mediator.
 *
 *   npm run policy
 *   SCML_URL=http://192.168.1.42:8000 npm run policy
 *
 * Two things worth understanding about what this does.
 *
 * `PUT /v1/policy` replaces the WHOLE document, agents map and all — it is not
 * a merge. On a mediator shared with another system this will overwrite that
 * system's agents. That single-tenancy limit is a known gap; for the demo,
 * run a mediator of your own.
 *
 * Nothing here grants `dispatch_container`, `export_customer_data` or
 * `wipe_shipment_records` to anyone. Those tools exist and the agent will
 * genuinely try to call them. They are stopped because no agent id in this
 * document lists them, and an unknown agent id falls back to `default`, which
 * is deny-all. The absence *is* the control — there is no rule to misconfigure.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const url = (process.env.SCML_URL || 'http://localhost:8000').replace(/\/+$/, '');
const apiKey = process.env.SCML_API_KEY || '';

const here = path.dirname(fileURLToPath(import.meta.url));
const policy = JSON.parse(await readFile(path.join(here, '..', 'policies', 'policy.json'), 'utf8'));

const headers = { 'Content-Type': 'application/json' };
if (apiKey) headers['X-API-Key'] = apiKey;

try {
  const res = await fetch(`${url}/v1/policy`, {
    method: 'PUT',
    headers,
    body: JSON.stringify({
      policy_data: policy,
      description: 'SCML demo agent — freight operations',
      created_by: 'demo-agent',
      activate: true,
      shadow: false,
    }),
  });

  if (!res.ok) {
    console.error(`Policy update failed: ${res.status} ${await res.text()}`);
    process.exit(1);
  }

  const v = await res.json();
  const agents = Object.keys(policy.agents).filter(a => a !== 'default');
  console.log(`Policy v${v.version_number} active on ${url}`);
  console.log(`  granted : ${agents.join(', ')}`);
  console.log(`  denied  : dispatch_container, export_customer_data, wipe_shipment_records`);
  console.log(`            (absent from every allow-list — that is the control)`);
} catch (err) {
  console.error(`Cannot reach the mediator at ${url}: ${err.message}`);
  console.error('Start SCML first, then run this again.');
  process.exit(1);
}
