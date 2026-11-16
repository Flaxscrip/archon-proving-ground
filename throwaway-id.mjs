/**
 * A throwaway Archon identity with a published assertion key, in a fresh wallet,
 * for testing did:cid holder binding without touching a real identity.
 *
 *   node throwaway-id.mjs <wallet dir> <node URL> [registry]
 *
 * Writes <wallet dir>/wallet.json and .env (a random passphrase), creates the
 * identity "pg-holder", and publishes its Ed25519 assertion key
 * (<did>#key-assertion-1) so a resolver can find it.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import CipherNode from '@didcid/cipher/node';
import DrawbridgeClient from '@didcid/clients/drawbridge';
import Keymaster from '@didcid/keymaster';
import { openWalletStore } from '@didcid/keymaster/wallet/open';

const [dir, url, registry = 'local'] = process.argv.slice(2);
if (!dir || !url) throw new Error('usage: node throwaway-id.mjs <wallet dir> <node URL> [registry]');
mkdirSync(dir, { recursive: true, mode: 0o700 });
const passphrase = randomBytes(24).toString('base64url');
writeFileSync(path.join(dir, '.env'), `ARCHON_PASSPHRASE=${passphrase}\nARCHON_GATEKEEPER_URL=${url}\n`, { mode: 0o600 });

const gatekeeper = new DrawbridgeClient();
await gatekeeper.connect({ url });
const wallet = await openWalletStore('json', path.join(dir, 'wallet.json'));
const keymaster = new Keymaster({ gatekeeper, wallet, cipher: new CipherNode(), passphrase, defaultRegistry: registry });
await keymaster.newWallet();
const did = await keymaster.createId('pg-holder', { registry });
await keymaster.publishAssertionKey('pg-holder');
const doc = await keymaster.resolveDID(did);
console.log(did);
console.log(JSON.stringify(doc.didDocument.verificationMethod.map((v) => ({ id: v.id, type: v.type })), null, 1));
console.log('assertionMethod', doc.didDocument.assertionMethod, 'authentication', doc.didDocument.authentication);
