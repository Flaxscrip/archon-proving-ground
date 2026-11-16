/**
 * An Archon identity as an SD-JWT holder.
 *
 * Opens a keymaster wallet read-only (nothing here writes to the wallet or the
 * DID) and returns the identity's Ed25519 assertion key: the key keymaster
 * publishes as `<did>#key-assertion-1` with `publishAssertionKey`. It is
 * derived from the wallet seed, so it exists whether or not it is published.
 *
 * Env, as for @didcid/mcp-server (read from ARCHON_WALLET_DIR/.env if present):
 *   ARCHON_PASSPHRASE, ARCHON_GATEKEEPER_URL
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import CipherNode from '@didcid/cipher/node';
import DrawbridgeClient from '@didcid/clients/drawbridge';
import Keymaster from '@didcid/keymaster';
import { openWalletStore } from '@didcid/keymaster/wallet/open';
import { importJWK } from 'jose';

export async function archonHolder(name) {
  const dir = process.env.ARCHON_WALLET_DIR ?? path.join(process.env.HOME, 'wallets/genitrix');
  const envFile = path.join(dir, '.env');
  const env = {};
  if (existsSync(envFile)) {
    for (const line of readFileSync(envFile, 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z_]+)=(.*)$/);
      if (m) env[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
    }
  }
  const passphrase = env.ARCHON_PASSPHRASE ?? process.env.ARCHON_PASSPHRASE;
  const url = env.ARCHON_GATEKEEPER_URL ?? process.env.ARCHON_GATEKEEPER_URL;
  if (!passphrase || !url) throw new Error('ARCHON_PASSPHRASE and ARCHON_GATEKEEPER_URL are required');

  const gatekeeper = new DrawbridgeClient();
  await gatekeeper.connect({ url });
  const wallet = await openWalletStore('json', path.join(dir, 'wallet.json'));
  const keymaster = new Keymaster({ gatekeeper, wallet, cipher: new CipherNode(), passphrase });

  const { did } = await keymaster.fetchIdInfo(name);
  const { publicJwk, privateJwk } = await keymaster.fetchAssertionKeyPair(name);
  const doc = await keymaster.resolveDID(did);
  const kid = `${did}#key-assertion-1`;
  const published = (doc.didDocument?.verificationMethod ?? []).some((vm) => vm.id === kid || vm.id === '#key-assertion-1');
  const { kty, crv, x } = publicJwk;
  return { did, kid, published, jwk: { kty, crv, x }, key: await importJWK({ kty, crv, x, d: privateJwk.d }, 'EdDSA') };
}
