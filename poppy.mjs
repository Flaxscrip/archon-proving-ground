/**
 * GenitriX through the Agent Lab proving ground's poppy door: a Personal Agent under
 * Personal Agent Protocol 1.0 (personal-agent-protocol@8c02b42).
 *
 *   node poppy.mjs [--archon <name>] [--public-url <https base>] [--handle <h>] [--port <n>] [--no-open]
 *   node poppy.mjs --public-url <https base> --write-client <dir>
 *
 * Keys. Poppy fixes the Personal Agent's algorithms: the client key in its JWKS signs
 * with ES256 or PS384, and Session JWTs with ES256. An Archon identity has secp256k1,
 * X25519 and Ed25519 keys, so none of them can be the client key. Instead:
 *   - The client key is a P-256 key in .state/poppy-agent.json.
 *   - The Archon identity vouches for it: did-binding.jwt, beside the JWKS, is a JWT
 *     signed by the identity's Ed25519 assertion key (kid <did>#key-assertion-1) with
 *     sub = the client_id and cnf.jkt = the client key's RFC 7638 thumbprint. The door
 *     does not read it; anyone who resolves the DID can check it.
 *
 * The client metadata document and the JWKS must be on public HTTPS. They are static,
 * so write them once with --write-client and publish <dir> at --public-url; then
 * client_id is <public-url>/agent.json. The sign-in redirect is a loopback URI
 * (RFC 8252 7.3), so nothing but those files is public. Without --public-url the
 * documents are served on http://localhost:<port>, which only a local proving ground
 * (PG_BASE=http://localhost:8401) accepts.
 *
 * The door links a Personal Agent to a run by client_id, given when the run is made,
 * so this door has a run of its own in .state/run-poppy.json.
 *
 * Sign-in needs a person once: this prints the authorization URL (and opens it,
 * unless --no-open); pick a test account and Allow.
 */
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { SignJWT, calculateJwkThumbprint, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose';
import { archonHolder } from './archon-holder.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : d; };
const BASE = (process.env.PG_BASE ?? 'https://agentlab.choosemission.com/proving-ground').replace(/\/$/, '');
const STATE = process.env.PG_STATE_DIR ? pathToFileURL(`${process.env.PG_STATE_DIR.replace(/\/$/, '')}/`) : new URL('./.state/', import.meta.url);
const VERSION = '1.0';
const load = (name) => (existsSync(new URL(name, STATE)) ? JSON.parse(readFileSync(new URL(name, STATE), 'utf8')) : null);
const save = (name, value) => writeFileSync(new URL(name, STATE), JSON.stringify(value, null, 2), { mode: 0o600 });
const rand = (n = 16) => randomBytes(n).toString('base64url');
const sha256 = (s) => createHash('sha256').update(s).digest('base64url');
const getJson = async (url, init) => {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${url} returned ${res.status}: ${await res.text()}`);
  return res.json();
};

// --- The Personal Agent's identity (4.1) -------------------------------------------------
let agentState = load('poppy-agent.json');
if (!agentState) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  // sub: this agent's opaque ID for its one User, the same at every Company.
  agentState = { jwk: await exportJWK(privateKey), sub: `usr_${rand(9)}` };
  save('poppy-agent.json', agentState);
}
const { d: _d, ...publicJwk } = agentState.jwk;
const kid = await calculateJwkThumbprint(publicJwk);
const clientKey = await importJWK(agentState.jwk, 'ES256');
const jwks = { keys: [{ ...publicJwk, kid, alg: 'ES256', use: 'sig' }] };

const port = Number(opt('port', 8402));
const publicUrl = opt('public-url')?.replace(/\/$/, '');
const base = publicUrl ?? `http://localhost:${port}`;
const clientId = `${base}/agent.json`;
const name = opt('archon', 'GenitriX');
const metadata = {
  client_id: clientId,
  client_name: `${name} (Archon)`,
  client_uri: `${base}/`,
  jwks_uri: `${base}/jwks.json`,
  // Static hosting can't take a callback, so the redirect is loopback; the port is chosen at sign-in.
  redirect_uris: [publicUrl ? 'http://127.0.0.1/callback' : `${base}/callback`],
  token_endpoint_auth_method: 'private_key_jwt',
};

// --write-client <dir>: the two documents, and the DID's signature over the client key.
if (opt('write-client')) {
  if (!publicUrl) throw new Error('--write-client needs --public-url <https base>');
  const archon = await archonHolder(name);
  if (!archon.published) console.log(`note: ${archon.kid} is not published in the DID document, so nobody can check the binding by resolving the DID.`);
  const binding = await new SignJWT({ cnf: { jkt: kid } })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: archon.kid })
    .setIssuer(archon.did).setSubject(clientId).setIssuedAt().sign(archon.key);
  const dir = opt('write-client').replace(/\/$/, '');
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/agent.json`, `${JSON.stringify(metadata, null, 2)}\n`);
  writeFileSync(`${dir}/jwks.json`, `${JSON.stringify(jwks, null, 2)}\n`);
  writeFileSync(`${dir}/did-binding.jwt`, `${binding}\n`);
  console.log(`wrote agent.json, jwks.json and did-binding.jwt to ${dir} for ${clientId}\nbinding: ${archon.kid} vouches for client key ${kid}`);
  process.exit(0);
}

// --- Discovery (3, 3.1, 3.2), with the checks a Personal Agent MUST make -----------------
async function discover(origin) {
  const doc = await getJson(`${origin}/.well-known/poppy.json`);
  const host = new URL(origin).host.toLowerCase();
  if (!/^1\.\d+$/.test(doc.protocol_version)) throw new Error(`unsupported protocol_version ${doc.protocol_version}`);
  if (String(doc.organization?.domain).toLowerCase() !== host) throw new Error(`organization.domain ${doc.organization?.domain} isn't ${host}`);
  const resource = `${new URL(origin).protocol}//${host}`;
  const prm = await getJson(`${origin}/.well-known/oauth-protected-resource`);
  if (prm.resource !== resource) throw new Error(`protected resource metadata names ${prm.resource}, not ${resource}`);
  const issuer = doc.auth?.issuer ?? prm.authorization_servers?.[0];
  if (!prm.authorization_servers?.includes(issuer)) throw new Error(`issuer ${issuer} isn't in authorization_servers`);
  const iss = new URL(issuer);
  const as = await getJson(`${iss.origin}/.well-known/oauth-authorization-server${iss.pathname.replace(/\/$/, '')}`);
  if (as.issuer !== issuer) throw new Error(`the issuer's metadata names ${as.issuer}`);
  if (!as.protected_resources?.map((r) => r.toLowerCase()).includes(resource)) throw new Error(`the issuer doesn't vouch for ${resource}`);
  const endpoint = doc.agent?.protocols?.find((p) => p.type === 'poppy')?.endpoint;
  if (!endpoint) throw new Error('poppy.json lists no poppy conversation endpoint');
  return { issuer, as, endpoint };
}

// --- A Session (5.2): a delegated key, vouched for by the client key ----------------------
async function newSession(company) {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const cnf = await exportJWK(publicKey);
  const delegation = await new SignJWT({ cnf: { jwk: cnf } })
    .setProtectedHeader({ alg: 'ES256', typ: 'poppy-delegation+jwt', kid })
    .setIssuer(clientId).setIssuedAt().setExpirationTime('1h').setJti(rand()).sign(clientKey);
  return { company, sid: rand(), sub: agentState.sub, key: privateKey, kid: await calculateJwkThumbprint(cnf), delegation, token: undefined };
}

async function call(s, method, url, body) {
  const u = new URL(url);
  const session = await new SignJWT({ sid: s.sid, sub: s.sub, htm: method, htu: `${u.origin}${u.pathname}`, ...(s.token && { ath: sha256(s.token) }) })
    .setProtectedHeader({ typ: 'poppy-session+jwt', alg: 'ES256', kid: s.kid, poppy_dlg: s.delegation })
    .setIssuer(clientId).setAudience(s.company.issuer).setIssuedAt().setJti(rand()).sign(s.key);
  const res = await fetch(url, {
    method,
    headers: { 'Poppy-Session': session, 'Poppy-Version': VERSION, ...(s.token && { Authorization: `Bearer ${s.token}` }), ...(body !== undefined && { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const out = { status: res.status, body: await res.json().catch(() => ({})) };
  if (res.status >= 400) throw new Error(`${method} ${u.pathname} → ${res.status} ${JSON.stringify(out.body)}`);
  return out;
}
const message = (text) => ({ id: `req_${rand(12)}`, message: { author: { type: 'agent' }, text } });
const companySaid = (read) => (read.events ?? []).filter((e) => e.type === 'message' && e.message?.role === 'company').map((e) => e.message.text);

// --- Direct Sign-In (4.2): authorization code + PKCE, then private_key_jwt at the issuer ---
const assertion = (issuer) => new SignJWT({}).setProtectedHeader({ alg: 'ES256', kid })
  .setIssuer(clientId).setSubject(clientId).setAudience(issuer).setIssuedAt().setExpirationTime('2m').setJti(rand()).sign(clientKey);

async function signIn(company, scope, redirectUri, browser) {
  const verifier = rand(32);
  const state = rand();
  const auth = new URL(company.as.authorization_endpoint);
  auth.search = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, scope, state, code_challenge: sha256(verifier), code_challenge_method: 'S256', prompt: 'consent' }).toString();
  const back = new URL(await browser(auth.toString())).searchParams;
  if (back.get('iss') !== company.issuer) throw new Error(`sign-in came back with iss ${back.get('iss')}, not ${company.issuer}`);
  if (back.get('state') !== state) throw new Error('sign-in came back with the wrong state');
  if (!back.get('code')) throw new Error(`sign-in declined: ${back.get('error')}`);
  const tokens = await getJson(company.as.token_endpoint, {
    method: 'POST',
    body: new URLSearchParams({ grant_type: 'authorization_code', code: back.get('code'), redirect_uri: redirectUri, code_verifier: verifier, client_id: clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await assertion(company.issuer) }),
  });
  if (!String(tokens.scope ?? scope).split(' ').includes(scope)) throw new Error(`the User didn't grant ${scope}`);
  return tokens;
}

// --- Go ------------------------------------------------------------------------------------
// The local server takes the sign-in callback; without --public-url it also serves the documents.
let callback = () => {};
const server = createServer((req, res) => {
  const u = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
  if (!publicUrl && u.pathname === '/agent.json') return res.end(JSON.stringify(metadata));
  if (!publicUrl && u.pathname === '/jwks.json') return res.end(JSON.stringify(jwks));
  if (u.pathname === '/callback') { callback(u.toString()); return res.end('Signed in. You can close this tab.'); }
  res.writeHead(404).end();
}).listen(port, publicUrl ? '127.0.0.1' : undefined);
const redirectUri = publicUrl ? `http://127.0.0.1:${port}/callback` : metadata.redirect_uris[0];

try {
  console.log(`client_id ${clientId}`);
  if (publicUrl) {
    // What the door will fetch must be what this run signs with.
    const [m, j] = [await getJson(clientId), await getJson(metadata.jwks_uri)];
    if (m.client_id !== clientId || !j.keys?.some((k) => k.kid === kid)) throw new Error(`${base} doesn't serve this agent's documents: run --write-client and publish them first.`);
  }
  const company = await discover(new URL(BASE).origin);
  console.log(`discovered: issuer ${company.issuer}, endpoint ${company.endpoint}`);

  let run = load('run-poppy.json');
  if (!run || run.client_id !== clientId) {
    const handle = opt('handle', process.env.PG_HANDLE ?? 'genitrix');
    const res = await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle, client_id: clientId }) });
    if (!res.ok) throw new Error(`starting a run as ${handle} → ${res.status} ${await res.text()}\nA run takes its client_id only when it is made, and a handle belongs to one run: pass --handle <another>.`);
    run = await res.json();
    save('run-poppy.json', run);
  }
  console.log(`run: ${run.handle}`, run.poppy);

  const s = await newSession(company);
  const started = await call(s, 'POST', `${company.endpoint}?wait=5`, message(`Hello from ${name}, a Personal Agent with an Archon identity.`));
  console.log(`conversation started: <- ${started.status}`, companySaid(started.body));
  const ask = started.body.events?.find((e) => e.type === 'authorization');
  if (!ask) throw new Error(`no authorization event: ${JSON.stringify(started.body)}`);

  const tokens = await signIn(company, ask.scope, redirectUri, (url) => {
    console.log(`\nPERSON NEEDED (sign in, scope ${ask.scope}): open this, pick a test account and Allow:\n${url}\n`);
    if (!args.includes('--no-open')) spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
    return new Promise((resolve) => (callback = resolve));
  });
  s.token = tokens.access_token;
  console.log(`signed in: ${tokens.token_type} token, scope ${tokens.scope}`);

  const signedIn = await call(s, 'POST', `${company.endpoint}/${started.body.conversation_id}/messages?wait=5&cursor=${started.body.cursor}`, message('Signed in now.'));
  console.log(`authorized call: <- ${signedIn.status}`, companySaid(signedIn.body));
  const receipt = signedIn.body.events?.find((e) => e.message?.data?.receipt)?.message.data.receipt;
  if (!receipt) throw new Error(`no receipt: ${JSON.stringify(signedIn.body)}`);
  const { keys } = await getJson(`${BASE}/pg/jwks.json`);
  const rkid = decodeProtectedHeader(receipt).kid;
  const { payload } = await jwtVerify(receipt, await importJWK(keys.find((k) => k.kid === rkid) ?? keys[0], 'ES256'), { typ: 'pg-receipt+jwt' });
  save('receipt-poppy.json', { receipt, payload, client_id: clientId });
  console.log('receipt verified:', payload);

  // Sign out (4.6): revoke the refresh token, which ends the access tokens made from it.
  if (tokens.refresh_token) {
    await fetch(company.as.revocation_endpoint, { method: 'POST', body: new URLSearchParams({ token: tokens.refresh_token, token_type_hint: 'refresh_token', client_id: clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await assertion(company.issuer) }) });
    console.log('signed out: refresh token revoked');
  }
} finally {
  server.close();
}
