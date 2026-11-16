/**
 * GenitriX through the Agent Lab proving ground's x401 door.
 *
 *   node x401.mjs [--unsigned] [--archon [name]] [--proof jwk|kid]
 *
 *   --archon [name]  hold the credential with an Archon identity's Ed25519
 *                    assertion key (default GenitriX) instead of the standalone key
 *   --proof jwk|kid  how the OpenID4VCI proof names the key: a header `jwk`, or a
 *                    `kid` (did:key for the standalone key, did:cid for Archon)
 *
 * Follows x401 0.2.0 (proof/x401@7e864af) as the door pins it:
 *   1. start a run (once; kept in .state/run.json, the run ID is not public)
 *   2. GET the door, decode PROOF-REQUEST, verify the signed request against the
 *      verifier's did:webvh log
 *   3. redeem the run's OpenID4VCI credential offer for the Lab handle credential,
 *      bound to our holder key (Ed25519, presented as a did:key `kid`)
 *   4. present it (SD-JWT + KB-JWT) in PROOF-RESPONSE
 *
 * The holder key is a standalone Ed25519 key in .state/holder.json.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { SignJWT, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose';
import { defaultVerifier, multibaseEncode, resolveDIDFromLog } from 'didwebvh-ts';

const BASE = process.env.PG_BASE ?? 'https://agentlab.choosemission.com/proving-ground';
const HANDLE = process.env.PG_HANDLE ?? 'genitrix';
const STATE = process.env.PG_STATE_DIR ? pathToFileURL(`${process.env.PG_STATE_DIR.replace(/\/$/, '')}/`) : new URL('./.state/', import.meta.url);
const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const decode = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
const encode = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const load = (name) => (existsSync(new URL(name, STATE)) ? JSON.parse(readFileSync(new URL(name, STATE), 'utf8')) : null);
const save = (name, value) => writeFileSync(new URL(name, STATE), JSON.stringify(value, null, 2), { mode: 0o600 });
const json = async (res) => {
  if (!res.ok) throw new Error(`${res.url} said ${res.status}: ${await res.text()}`);
  return res.json();
};

/** An Ed25519 holder key, kept across runs, with its did:key verification method ID. */
async function holder() {
  let jwk = load('holder.json');
  if (!jwk) {
    const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    jwk = await exportJWK(privateKey);
    save('holder.json', jwk);
  }
  const { d, ...pub } = jwk;
  // did:key: multibase(base58btc, 0xed01 || raw public key)
  const mb = multibaseEncode(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(pub.x, 'base64url')]), 'z');
  return { key: await importJWK(jwk, 'EdDSA'), jwk: pub, kid: `did:key:${mb}#${mb}` };
}

async function run() {
  let r = load('run.json');
  if (!r) {
    r = await json(await fetch(`${BASE}/pg/runs`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: HANDLE }),
    }));
    save('run.json', r);
    console.log(`started run for handle ${r.handle}`);
  }
  return r;
}

/** OpenID4VCI 1.0 pre-authorized code flow, from the offer alone. */
async function getCredential(offer, h) {
  const id = new URL(offer.credential_issuer);
  const wellKnown = (name) => `${id.origin}/.well-known/${name}${id.pathname.replace(/\/$/, '')}`;
  const md = await json(await fetch(wellKnown('openid-credential-issuer')));
  if (md.credential_issuer !== offer.credential_issuer) throw new Error('issuer metadata mismatch');
  const as = await json(await fetch(wellKnown('oauth-authorization-server')));
  const { access_token } = await json(await fetch(as.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: PRE_AUTH, 'pre-authorized_code': offer.grants[PRE_AUTH]['pre-authorized_code'] }),
  }));
  const { c_nonce } = await json(await fetch(md.nonce_endpoint, { method: 'POST' }));
  const proof = await new SignJWT({ aud: md.credential_issuer, nonce: c_nonce })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'openid4vci-proof+jwt', ...(proofBy === 'kid' ? { kid: h.kid } : { jwk: h.jwk }) })
    .setIssuedAt()
    .sign(h.key);
  const { credentials } = await json(await fetch(md.credential_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${access_token}` },
    body: JSON.stringify({ credential_configuration_id: offer.credential_configuration_ids[0], proofs: { jwt: [proof] } }),
  }));
  return credentials[0].credential;
}

/** GET the door; verify the signed request against the verifier's did:webvh log. */
async function challenge(doorUrl) {
  const res = await fetch(doorUrl);
  const header = res.headers.get('proof-request');
  if (!header) throw new Error(`expected PROOF-REQUEST, got ${res.status}: ${await res.text()}`);
  const payload = decode(header);
  const entry = (p) => payload.credential_requirements.digital.requests.find((r) => r.protocol === p);
  const jar = entry('openid4vp-v1-signed').data.request;
  const did = String(decodeJwt(jar).client_id).replace(/^decentralized_identifier:/, '');
  const [method, , host] = did.split(':').slice(1);
  if (method !== 'webvh' || !host) throw new Error(`expected a did:webvh client_id, got ${did}`);
  const scheme = /(^|\.)localhost(:|$)/.test(decodeURIComponent(host)) ? 'http' : 'https';
  const logUrl = `${scheme}://${decodeURIComponent(host)}/.well-known/did.jsonl`;
  const log = (await (await fetch(logUrl)).text()).trim().split('\n').map((l) => JSON.parse(l));
  const { didDocument } = await resolveDIDFromLog(log, { verifier: defaultVerifier });
  if (didDocument?.id !== did) throw new Error(`${logUrl} does not resolve to ${did}`);
  const { kid } = decodeProtectedHeader(jar);
  const vm = didDocument.verificationMethod?.find((v) => v.id === kid);
  if (!vm?.publicKeyJwk) throw new Error(`${did} has no key ${kid}`);
  const { payload: signed } = await jwtVerify(jar, await importJWK(vm.publicKeyJwk, 'ES256'), { typ: 'oauth-authz-req+jwt' });
  return { signed, unsigned: entry('openid4vp-v1-unsigned').data, verifier: did };
}

async function present(credential, h, { nonce, aud, disclose }) {
  const [issuerJwt, ...disclosures] = credential.split('~').filter(Boolean);
  const kept = disclosures.filter((d) => disclose.includes(decode(d)[1]));
  const body = `${[issuerJwt, ...kept].join('~')}~`;
  const kb = await new SignJWT({ nonce, aud, sd_hash: createHash('sha256').update(body).digest('base64url') })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'kb+jwt' })
    .setIssuedAt()
    .sign(h.key);
  return body + kb;
}

const args = process.argv.slice(2);
const unsigned = args.includes('--unsigned');
const archonAt = args.indexOf('--archon');
const archonName = archonAt < 0 ? null : (args[archonAt + 1] && !args[archonAt + 1].startsWith('--') ? args[archonAt + 1] : 'GenitriX');
const proofBy = args.includes('--proof') ? args[args.indexOf('--proof') + 1] : (archonName ? 'jwk' : 'kid');
const r = await run();
const doorUrl = r.doors.x401;
const h = archonName ? await (await import('./archon-holder.mjs')).archonHolder(archonName) : await holder();
console.log(`holder ${h.kid}${archonName ? ` (assertion key ${h.published ? 'published' : 'not published'} in the DID document)` : ''}; proof by ${proofBy}`);

const c = await challenge(doorUrl);
const request = unsigned ? c.unsigned : c.signed;
const query = request.dcql_query.credentials[0];
console.log(`<- 401 PROOF-REQUEST from ${c.verifier} (signed request verified); using the ${unsigned ? 'unsigned' : 'signed'} entry`);

const { credential_offer } = await json(await fetch(`${BASE}/pg/runs/${r.run}/offer`));
const credential = await getCredential(credential_offer, h);
const vc = decodeJwt(credential.split('~')[0]);
console.log(`<- handle credential: vct ${vc.vct}, iss ${vc.iss}, bound to cnf.jwk ${vc.cnf?.jwk?.crv}`);

const disclose = query.claims.map((cl) => cl.path[0]);
const presentation = await present(credential, h, {
  nonce: request.nonce, aud: unsigned ? `origin:${new URL(doorUrl).origin}` : request.client_id, disclose,
});
const res = await fetch(doorUrl, {
  headers: { 'PROOF-RESPONSE': encode({ request_id: 'pg-x401-v1', credential_result: { protocol: `openid4vp-v1-${unsigned ? 'unsigned' : 'signed'}`, data: { vp_token: { [query.id]: [presentation] } } } }) },
});
const result = res.headers.get('proof-result');
console.log(`<- ${res.status} PROOF-RESULT`, result && decode(result));
const body = await res.json();
if (body.receipt) {
  // Verify the receipt against the proving ground's published keys before believing it.
  const { keys } = await json(await fetch(`${BASE}/pg/jwks.json`));
  const kid = decodeProtectedHeader(body.receipt).kid;
  const key = keys.find((k) => k.kid === kid) ?? keys[0];
  const { payload } = await jwtVerify(body.receipt, await importJWK(key, 'ES256'), { typ: 'pg-receipt+jwt' });
  save(`receipt-x401-${archonName ? 'archon' : 'key'}-${unsigned ? 'unsigned' : 'signed'}.json`, { receipt: body.receipt, payload });
  console.log('receipt verified:', payload);
} else {
  console.log(JSON.stringify(body, null, 2));
}
