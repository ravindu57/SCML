/**
 * HTTP server for the demo agent.
 *
 * Node's built-in http and fs only — no framework. The whole point of this
 * package is that it installs and runs on a second laptop with no database,
 * no Docker and, once packed, no network.
 */

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { handleMessage, llmConfig } from './agent.js';
import { SCENARIOS } from './scenarios.js';
import { TOOLS } from './tools.js';
import * as scml from './scml.js';

const PORT = Number(process.env.PORT || 4000);
/* Where the dashboard is served. Defaults to the mediator's host on 3100,
   which is what run-demo.sh starts; override when it lives elsewhere. */
const DASHBOARD_URL = (process.env.DASHBOARD_URL || '').replace(/\/+$/, '');
const SESSION = process.env.SCML_SESSION || 'agent-live';
const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

const json = (res: http.ServerResponse, code: number, body: unknown) => {
  const payload = JSON.stringify(body);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'Access-Control-Allow-Origin': '*',
  });
  res.end(payload);
};

const readBody = (req: http.IncomingMessage): Promise<string> =>
  new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => {
      data += c;
      // A chat message has no business being megabytes.
      if (data.length > 1_000_000) reject(new Error('body too large'));
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host}`);

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      });
      return res.end();
    }

    if (url.pathname === '/api/config') {
      const h = await scml.health();
      return json(res, 200, {
        session: SESSION,
        mediator: scml.mediatorUrl,
        mediatorHealthy: h.ok,
        mediatorDetail: h.detail,
        mode: llmConfig() ? 'llm' : 'deterministic',
        dashboard: DASHBOARD_URL || scml.mediatorUrl.replace(/:\d+$/, ':3100'),
        scenarios: SCENARIOS,
        tools: TOOLS.map(t => ({ name: t.name, tier: t.tier, agentId: t.agentId, description: t.description })),
      });
    }

    if (url.pathname === '/api/chat' && req.method === 'POST') {
      const { message } = JSON.parse((await readBody(req)) || '{}');
      if (typeof message !== 'string' || !message.trim()) {
        return json(res, 400, { error: 'message required' });
      }
      const session = url.searchParams.get('session') || SESSION;
      return json(res, 200, await handleMessage(message, session));
    }

    // Static files. Only ever serves from public/, and the resolved path is
    // checked against it so a crafted URL cannot escape the directory.
    const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const file = path.resolve(PUBLIC, rel);
    if (!file.startsWith(path.resolve(PUBLIC))) {
      return json(res, 403, { error: 'forbidden' });
    }
    const types: Record<string, string> = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css',
      '.js': 'text/javascript',
      '.svg': 'image/svg+xml',
    };
    try {
      const body = await readFile(file);
      res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' });
      return res.end(body);
    } catch {
      return json(res, 404, { error: 'not found' });
    }
  } catch (err) {
    return json(res, 500, { error: err instanceof Error ? err.message : 'server error' });
  }
});

server.listen(PORT, '0.0.0.0', async () => {
  const h = await scml.health();
  const line = '─'.repeat(64);
  console.log(`\n${line}`);
  console.log('  SCML Demo Agent — freight operations');
  console.log(line);
  console.log(`  Chat        http://localhost:${PORT}`);
  console.log(`  Mediator    ${scml.mediatorUrl}  ${h.ok ? '✔ ' + h.detail : '✖ ' + h.detail}`);
  console.log(`  Session     ${SESSION}`);
  const cfg = llmConfig();
  console.log(`  Intent      ${cfg ? `LLM — ${cfg.provider} ${cfg.model} @ ${cfg.baseUrl}` : 'deterministic (no API key needed)'}`);
  if (!h.ok) {
    console.log(`\n  The mediator is not reachable. Actions will fail CLOSED, which is`);
    console.log(`  correct but makes for a dull demo. Start SCML, then reload.`);
  }
  console.log(`${line}\n`);
});
