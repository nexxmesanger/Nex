#!/usr/bin/env node
/**
 * Nex keepalive — pings Render so free tier doesn't sleep.
 *
 * Loop:   RENDER_URL=https://xxx.onrender.com node nex-keepalive.js
 * Once:   RENDER_URL=https://xxx.onrender.com KEEPALIVE_ONCE=1 node nex-keepalive.js
 *
 * Better for free: cron-job.org every 10 min → GET https://xxx.onrender.com/health
 */
const URL_BASE = process.env.RENDER_URL || process.env.KEEPALIVE_URL || '';
const PATH = process.env.KEEPALIVE_PATH || '/health';
const INTERVAL = Number(process.env.KEEPALIVE_INTERVAL_MS || 10 * 60 * 1000);
const ONCE = process.env.KEEPALIVE_ONCE === '1' || process.argv.includes('--once');

if (!URL_BASE) {
  console.error('Set RENDER_URL, e.g. RENDER_URL=https://nex-api.onrender.com');
  process.exit(1);
}

const target = URL_BASE.replace(/\/$/, '') + PATH;

async function ping() {
  const t0 = Date.now();
  try {
    const res = await fetch(target, {
      method: 'GET',
      headers: { 'user-agent': 'nex-keepalive/1.0' },
      signal: AbortSignal.timeout(15000),
    });
    const ms = Date.now() - t0;
    const body = await res.text().catch(() => '');
    console.log(`[keepalive] ${new Date().toISOString()} ${res.status} ${ms}ms ${body.slice(0, 80)}`);
    return res.ok;
  } catch (e) {
    console.error(`[keepalive] ${new Date().toISOString()} FAIL ${e.message}`);
    return false;
  }
}

(async () => {
  if (ONCE) {
    process.exit((await ping()) ? 0 : 1);
  }
  console.log(`[keepalive] every ${INTERVAL / 60000} min → ${target}`);
  await ping();
  setInterval(ping, INTERVAL);
})();
