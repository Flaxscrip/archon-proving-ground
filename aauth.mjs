/**
 * GenitriX through the Agent Lab proving ground's aauth door (AAuth Protocol -11,
 * dickhardt/AAuth@178e9e6), PS authorization access, three-party.
 *
 *   node aauth.mjs [--archon <name>] [--local <agent local part>] [--port <n>] [--public-url <https origin>] [--no-open] [--dry]
 *
 * The agent is its own agent provider:
 *   - The provider key, which signs agent tokens, is the Archon identity's Ed25519
 *     assertion key: the same key its did:cid document publishes as #key-assertion-1.
 *     It is published in the provider's JWKS with that DID URL as its `kid`.
 *   - The agent's request-signing key is a separate Ed25519 key in .state/aauth-agent.json,
 *     bound by the agent token's cnf.jwk. The Archon key never signs HTTP requests.
 *
 * The provider's two documents must be on public HTTPS with no port. They are
 * static (a public key), so any static host will do: write them with
 *   node aauth.mjs --public-url https://<host> --write-provider <dir>
 * publish <dir> at that origin, then run with --public-url alone. Without
 * --public-url, a Cloudflare quick tunnel to --port is started for the run.
 *
 * The Lab test person server needs a person twice: once for the person token and
 * once to consent to scope `receipt`. Each time this prints a URL (and opens it,
 * unless --no-open); pick a test account and Allow.
 */
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { bareItemToString, fetch as signedFetch, parseDictionary } from '@hellocoop/httpsig';
import { SignJWT, calculateJwkThumbprint, createLocalJWKSet, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose';
import { archonHolder } from './archon-holder.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : d; };
const BASE = process.env.PG_BASE ?? 'https://agentlab.choosemission.com/proving-ground';
const STATE = new URL('./.state/', import.meta.url);
const load = (name) => (existsSync(new URL(name, STATE)) ? JSON.parse(readFileSync(new URL(name, STATE), 'utf8')) : null);
const save = (name, value) => writeFileSync(new URL(name, STATE), JSON.stringify(value, null, 2), { mode: 0o600 });
const now = () => Math.floor(Date.now() / 1000);
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));
const getJson = async (url) => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}: ${await res.text()}`);
  return res.json();
};
/** Metadata at {issuer}/.well-known/{dwk}, whose issuer must be the one asked for (11.2). */
const metadata = async (issuer, dwk) => {
  const doc = await getJson(`${issuer}/.well-known/${dwk}`);
  if (doc.issuer !== issuer) throw new Error(`${issuer}/.well-known/${dwk} says issuer ${doc.issuer}`);
  return doc;
};

const run = load('run.json');
if (!run?.doors?.aauth) throw new Error('No run in .state/run.json: run x401.mjs first.');
const door = run.doors.aauth;
const resource = new URL(door).origin;

// --- The agent provider: the Archon identity ---------------------------------------------
const archon = await archonHolder(opt('archon', 'GenitriX'));
if (!archon.published) console.log(`note: ${archon.kid} is not published in the DID document; the JWKS will still carry the key.`);
const providerKey = archon.key;
const providerJwk = { ...archon.jwk, kid: archon.kid, alg: 'Ed25519', use: 'sig' };

// --- The agent's own request-signing key -------------------------------------------------
let signingKey = load('aauth-agent.json');
if (!signingKey) {
  const { privateKey } = await generateKeyPair('Ed25519', { extractable: true });
  signingKey = { ...(await exportJWK(privateKey)), alg: 'Ed25519' };
  save('aauth-agent.json', signingKey);
}
const { d: _d, ...publicJwk } = signingKey;
const thumbprint = await calculateJwkThumbprint(publicJwk);

// --- Serve the provider's documents, on public HTTPS -------------------------------------
const port = Number(opt('port', 8403));
let provider = opt('public-url')?.replace(/\/$/, '');
const documents = () => ({
  '/.well-known/aauth-agent.json': { issuer: provider, jwks_uri: `${provider}/jwks.json`, name: `${opt('archon', 'GenitriX')} (Archon)`, description: `A self-hosted agent whose provider key is ${archon.kid}` },
  '/jwks.json': { keys: [providerJwk] },
});
// --write-provider <dir>: write the two documents for a static host at --public-url, and stop.
if (opt('write-provider')) {
  if (!provider) throw new Error('--write-provider needs --public-url <https origin>');
  const { mkdirSync } = await import('node:fs');
  const dir = opt('write-provider').replace(/\/$/, '');
  mkdirSync(`${dir}/.well-known`, { recursive: true });
  for (const [path, doc] of Object.entries(documents())) writeFileSync(`${dir}${path}`, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`wrote ${dir}/.well-known/aauth-agent.json and ${dir}/jwks.json for ${provider}`);
  process.exit(0);
}
const server = createServer((req, res) => {
  const body = provider && documents()[new URL(req.url ?? '/', 'http://x').pathname];
  if (!body) return res.writeHead(404).end();
  res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(body));
});
await new Promise((r) => server.listen(port, '127.0.0.1', r));

let tunnel;
if (provider) server.close(); // a static host serves the documents
if (!provider) {
  tunnel = spawn('cloudflared', ['tunnel', '--no-autoupdate', '--url', `http://127.0.0.1:${port}`], { stdio: ['ignore', 'ignore', 'pipe'] });
  provider = await new Promise((resolve, reject) => {
    let log = '';
    const t = setTimeout(() => reject(new Error(`no tunnel URL after 40 s:\n${log}`)), 40_000);
    tunnel.stderr.on('data', (c) => {
      log += c;
      const m = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/.exec(log);
      if (m) { clearTimeout(t); resolve(m[0]); }
    });
    tunnel.on('exit', (code) => reject(new Error(`cloudflared exited ${code}:\n${log}`)));
  });
}
const cleanup = () => { server.close(); tunnel?.kill(); };
process.on('SIGINT', () => { cleanup(); process.exit(130); });

try {
  // The door fetches the provider from the internet, so wait until it answers there.
  for (let i = 0; ; i++) {
    const ok = await fetch(`${provider}/.well-known/aauth-agent.json`).then((r) => r.ok, () => false);
    if (ok) break;
    if (i > 30) throw new Error(`${provider} is not reachable`);
    await sleep(2);
  }
  const id = `aauth:${opt('local', run.handle)}@${new URL(provider).hostname}`;
  const ps = await metadata(opt('ps', resource), 'aauth-person.json');
  const meta = await metadata(resource, 'aauth-resource.json');
  console.log(`agent ${id}\nagent provider ${provider}, key ${archon.kid}\nPS ${ps.issuer}`);

  /** An agent token (5.3.1), signed by the provider key. */
  const agentToken = () => new SignJWT({ iss: provider, dwk: 'aauth-agent.json', sub: id, cnf: { jwk: publicJwk }, ps: ps.issuer, iat: now(), exp: now() + 3600, jti: randomBytes(8).toString('hex') })
    .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-agent+jwt', kid: archon.kid })
    .sign(providerKey);

  /** One signed request (11.3.3), presenting `jwt` in Signature-Key. */
  const call = async (url, jwt, body) => {
    const res = await signedFetch(url, {
      method: body === undefined ? 'GET' : 'POST',
      ...(body !== undefined && { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
      signingKey, signatureKey: { type: 'jwt', jwt },
    });
    const text = await res.text();
    let parsed; try { parsed = JSON.parse(text); } catch { parsed = { text }; }
    return { status: res.status, headers: res.headers, body: parsed };
  };
  /** The AAuth-Requirement header (11.6.1), as {requirement, ...params}. */
  const requirement = (h) => {
    const v = h.get('aauth-requirement');
    if (!v) return null;
    const [value, params] = parseDictionary(v).get('requirement');
    return { requirement: bareItemToString(value), ...Object.fromEntries([...params].map(([k, x]) => [k, bareItemToString(x)])) };
  };
  const show = (label, r) => console.log(`${label}: <- ${r.status} ${r.headers.get('aauth-requirement')?.replace(/resource-token="[^"]+"/, 'resource-token=…') ?? ''}${r.status >= 400 && !r.headers.get('aauth-requirement') ? ` ${JSON.stringify(r.body)}` : ''}`);
  const fail = (label, r) => { throw new Error(`${label}: ${r.status} ${r.headers.get('signature-error') ?? ''} ${JSON.stringify(r.body)}`); };

  /** A PS request that may be deferred (11.8): the person goes to the URL while the agent polls Location. */
  const deferred = async (endpoint, body, what) => {
    let r = await call(endpoint, await agentToken(), body);
    let told = false;
    const deadline = Date.now() + 15 * 60_000;
    while (r.status === 202) {
      const req = requirement(r.headers);
      if (req?.requirement === 'interaction' && !told) {
        told = true;
        const url = `${req.url}?code=${encodeURIComponent(req.code)}`;
        console.log(`\nPERSON NEEDED (${what}): open this, check the code is ${req.code}, pick a test account and Allow:\n${url}\n`);
        if (!args.includes('--no-open')) spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
      }
      const location = r.headers.get('location');
      if (!location) throw new Error('202 without Location');
      if (Date.now() > deadline) throw new Error(`gave up waiting for the person (${what})`);
      await sleep(Number(r.headers.get('retry-after') ?? 5));
      r = await call(new URL(location, endpoint).toString(), await agentToken());
    }
    return r;
  };

  // 1. The agent token: 401 requirement=person-token (6.4).
  const first = await call(door, await agentToken());
  show('agent token', first);
  if (requirement(first.headers)?.requirement !== 'person-token') fail('agent token', first);
  if (args.includes('--dry')) { console.log('--dry: stopping before the person server.'); cleanup(); process.exit(0); }

  // 2. A person token for the resource, from the PS (7.1).
  const p = await deferred(ps.person_token_endpoint, { resource: meta.issuer, capabilities: ['interaction'] }, 'person token');
  if (p.status !== 200) fail('person token', p);
  const person = p.body.person_token;
  const pc = decodeJwt(person);
  if (pc.aud !== resource || pc.cnf?.jwk?.x !== publicJwk.x) throw new Error('the person token is not for this resource, or not bound to this key');

  // 3. The person token: 401 requirement=auth-token and a resource token (6.5), checked as 6.7.3 says.
  const second = await call(door, person);
  show('person token', second);
  const req = requirement(second.headers);
  if (req?.requirement !== 'auth-token') fail('person token', second);
  const resourceToken = req['resource-token'];
  const { payload: rt } = await jwtVerify(resourceToken, createLocalJWKSet(await getJson(meta.jwks_uri)), { typ: 'aa-resource+jwt', issuer: resource });
  if (rt.agent_jkt !== thumbprint) throw new Error("the resource token's agent_jkt is not this agent's key");
  if (rt.ps !== ps.issuer || rt.sub !== pc.sub || rt.presented_jti !== pc.jti) throw new Error('the resource token does not name this PS, person and presented token');

  // 4. Trade it at the PS for an auth token (7.2), checked as 9.4.4 says.
  const a = await deferred(ps.auth_token_endpoint, { resource_token: resourceToken, presented_token: person, capabilities: ['interaction'], justification: 'Collect my proving-ground receipt.' }, `consent to scope ${rt.scope}`);
  if (a.status !== 200) fail('auth token', a);
  const auth = a.body.auth_token;
  const ac = decodeJwt(auth);
  if (ac.iss !== rt.aud || ac.aud !== rt.iss || ac.cnf?.jwk?.x !== publicJwk.x || ac.sub !== pc.sub) throw new Error('the auth token does not match the resource token');

  // 5. The auth token: 200 and a receipt.
  const third = await call(door, auth);
  show('auth token', third);
  if (third.status !== 200 || !third.body.receipt) fail('auth token', third);
  const { keys } = await getJson(`${BASE}/pg/jwks.json`);
  const kid = decodeProtectedHeader(third.body.receipt).kid;
  const { payload } = await jwtVerify(third.body.receipt, await importJWK(keys.find((k) => k.kid === kid) ?? keys[0], 'ES256'), { typ: 'pg-receipt+jwt' });
  save('receipt-aauth.json', { receipt: third.body.receipt, payload, agent: id, provider_key: archon.kid });
  console.log('receipt verified:', payload);
} finally {
  cleanup();
}
process.exit(0);
