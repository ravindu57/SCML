/**
 * HTTP + SSE server for the orchestration.
 *
 * Events stream as the run happens rather than arriving as one blob at the
 * end, because the point of the exhibit is watching the label degrade and the
 * policy checks land in order.
 */

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { run } from './orchestrator.js';
import { corpusIndex, TOOLS, AGENT_ID, TOOLLESS_ROLES } from './agents.js';
import * as scml from './scml.js';

const PORT = Number(process.env.PORT || 4100);
const SESSION = process.env.SCML_SESSION || 'orchestration-live';
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
    let d = '';
    req.on('data', c => {
      d += c;
      if (d.length > 1_000_000) reject(new Error('body too large'));
    });
    req.on('end', () => resolve(d));
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

      // Read the policy so the UI can distinguish what an agent may *reach
      // for* from what policy actually *grants* it. Listing the forbidden
      // tools under the executor without that distinction reads as "the
      // executor has these", which is the opposite of what the demo shows.
      let granted: Record<string, string[]> = {};
      try {
        const raw = await readFile(path.join(PUBLIC, '..', 'policies', 'policy.json'), 'utf8');
        const doc = JSON.parse(raw);
        granted = Object.fromEntries(
          Object.entries(doc.agents ?? {}).map(([id, a]) => [
            id,
            (a as { allowed_tools?: string[] }).allowed_tools ?? [],
          ]),
        );
      } catch {
        granted = {};
      }

      return json(res, 200, {
        session: SESSION,
        mediator: scml.mediatorUrl,
        mediatorHealthy: h.ok,
        mediatorDetail: h.detail,
        mode: process.env.ANTHROPIC_API_KEY ? 'llm' : 'deterministic',
        corpus: corpusIndex(),
        agents: Object.entries(AGENT_ID).map(([role, id]) => {
          const reachable = TOOLS.filter(t => t.role === role).map(t => t.name);
          const allow = granted[id] ?? [];
          return {
            role,
            agentId: id,
            granted: reachable.filter(t => allow.includes(t)),
            denied: reachable.filter(t => !allow.includes(t)),
            toolless: TOOLLESS_ROLES.includes(role as never),
          };
        }),
      });
    }

    // Streamed run. SSE so the UI can render each hop as it happens.
    if (url.pathname === '/api/run' && req.method === 'POST') {
      const { task } = JSON.parse((await readBody(req)) || '{}');
      if (typeof task !== 'string' || !task.trim()) {
        return json(res, 400, { error: 'task required' });
      }
      const session = url.searchParams.get('session') || SESSION;

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'Access-Control-Allow-Origin': '*',
      });

      const send = (event: string, data: unknown) =>
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

      try {
        const result = await run(task, session, e => send('step', e));
        send('result', { reply: result.reply, stopped: result.stopped, mode: result.mode });
      } catch (err) {
        send('error', { message: err instanceof Error ? err.message : String(err) });
      }
      return res.end();
    }

    const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const file = path.resolve(PUBLIC, rel);
    if (!file.startsWith(path.resolve(PUBLIC))) return json(res, 403, { error: 'forbidden' });
    const types: Record<string, string> = {
      '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
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
  const line = '─'.repeat(66);
  console.log(`\n${line}`);
  console.log('  SCML Orchestration — researcher → planner → executor → reporter');
  console.log(line);
  console.log(`  Console     http://localhost:${PORT}`);
  console.log(`  Mediator    ${scml.mediatorUrl}  ${h.ok ? '✔ ' + h.detail : '✖ ' + h.detail}`);
  console.log(`  Session     ${SESSION}`);
  console.log(`  Planner     ${process.env.ANTHROPIC_API_KEY ? 'LLM' : 'deterministic (no API key needed)'}`);
  if (!h.ok) console.log(`\n  Mediator unreachable — every action will fail CLOSED.`);
  console.log(`${line}\n`);
});
