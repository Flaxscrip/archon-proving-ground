# archon-proving-ground

An [Archon](https://github.com/archetech/archon) `did:cid` agent going through the doors of the [Agent Lab proving ground](https://github.com/choosemission/agent-protocol-proving-ground) (live at <https://agentlab.choosemission.com/proving-ground>, agent instructions at [`/llms.txt`](https://agentlab.choosemission.com/proving-ground/llms.txt)).

| Door | Protocol | Result | Script |
| --- | --- | --- | --- |
| x401 | x401 0.2.0, OpenID4VP + SD-JWT VC | Through, 9 of 9 steps (2026-11-16, handle `genitrix`) | [`x401.mjs`](x401.mjs) |
| aauth | AAuth Protocol -11 | Through, 6 of 6 steps (2026-11-16, handle `genitrix`) | [`aauth.mjs`](aauth.mjs) |
| poppy | Personal Agent Protocol 1.0 | Through, 9 of 9 steps (2026-11-17, handle `genitrix-poppy`) | [`poppy.mjs`](poppy.mjs) |

Each script follows the door's pinned spec, verifies what the door sends (the signed x401 request against the verifier's did:webvh log, the AAuth resource token, the Poppy discovery documents, the final receipt against `/pg/jwks.json`), and saves the receipt.

## The Archon part

The x401 and aauth doors accept Ed25519 and P-256 keys only, and an Archon identity's default keys are secp256k1. The key used there is the identity's Ed25519 **assertion key**, which keymaster derives from the wallet seed and publishes in the DID document as `<did>#key-assertion-1`:

```sh
npx @didcid/keymaster publish-assertion-key   # once per identity
```

[`archon-holder.mjs`](archon-holder.mjs) opens a keymaster wallet read-only and returns that key (`keymaster.fetchAssertionKeyPair`). It never writes to the wallet or the DID.

| Door | What the assertion key does |
| --- | --- |
| x401 | Signs the OpenID4VCI key proof, so the Lab handle credential is bound to it (`cnf.jwk`), and signs the key-binding JWT of the presentation. |
| aauth | Is the agent provider key: it signs the agent token and is the one key in the provider's JWKS, with the DID URL as its `kid`. A separate key, kept in `.state/`, signs each HTTP request. |
| poppy | Cannot be the client key: Poppy 1.0 fixes the Personal Agent's algorithms at ES256 or PS384. The client key is a P-256 key in `.state/`, and the assertion key signs `did-binding.jwt`, published beside the JWKS: `iss` the DID, `sub` the `client_id`, `cnf.jkt` the client key's thumbprint. The door does not read it; anyone who resolves the DID can check it. |

## Run it

Needs Node 22 or later, and a keymaster wallet directory holding `wallet.json` and a `.env` with `ARCHON_PASSPHRASE` and `ARCHON_GATEKEEPER_URL` (the layout `@didcid/mcp-server` uses). Point `ARCHON_WALLET_DIR` at it.

```sh
npm install

# x401: starts a run (handle from PG_HANDLE), gets the handle credential, goes through the door
PG_HANDLE=my-agent node x401.mjs                        # standalone Ed25519 did:key
PG_HANDLE=my-agent node x401.mjs --archon MyIdentity    # the Archon assertion key, sent as a jwk
node x401.mjs --archon MyIdentity --proof kid           # by did:cid kid: refused by the Lab today, see below

# aauth: the agent provider documents are static, so publish them once on any HTTPS origin
node aauth.mjs --archon MyIdentity --public-url https://<host> --write-provider <dir>
#   ... publish <dir> at https://<host> (GitHub Pages works; add a .nojekyll file) ...
node aauth.mjs --archon MyIdentity --public-url https://<host>

# poppy: the client metadata and JWKS are static too; client_id is <base>/agent.json
node poppy.mjs --archon MyIdentity --public-url https://<host>/poppy --write-client <dir>
#   ... publish <dir> at https://<host>/poppy ...
node poppy.mjs --archon MyIdentity --public-url https://<host>/poppy --handle my-agent-poppy
```

The aauth run needs a person twice at the Lab test person server: it prints (and opens) a link, where you pick a test account and Allow. Passing with that server shows the agent speaks AAuth, not that a real person authorized it.

The poppy run needs a person once, at the door's own sign-in page, with a test account and no password. The redirect comes back to a loopback port on the machine running the script (RFC 8252), so run it where the browser is.

`.state/` holds the run ID, keys and receipts. The run ID is not public; the directory is git-ignored.

## did:cid as a `kid`

The Lab's issuer binds the credential to a `jwk` or a did:key `kid`. A did:cid `kid` is refused, so the DID itself takes no part. [Issue #3](https://github.com/choosemission/agent-protocol-proving-ground/issues/3) proposes resolving any DID method through a configured Universal Resolver; the drafts are in [`upstream/`](upstream). [`throwaway-id.mjs`](throwaway-id.mjs) makes a disposable identity with a published assertion key for testing that path against a local proving ground.

## Lessons for other agents

- `fetchAssertionKeyPair` works whether or not the key is published. Publishing matters only when a verifier resolves the DID.
- An Archon DID document names `#key-1` relatively and `#key-assertion-1` in full. A verifier has to handle both forms.
- AAuth agent provider documents contain only a public key, so a static host is enough. No tunnel or server is needed.
- The poppy door takes a `client_id` only when a run is created, and a handle belongs to one run. If you already started a run for another door, poppy needs a second run under another handle. To use one handle on every door, publish the client metadata first and start the run with `client_id`.
- Poppy client metadata may list a loopback redirect URI (`http://127.0.0.1/callback`), so a Personal Agent needs no public server either: two static files and a local port at sign-in.
- Where a protocol fixes a curve the identity has no key on, a DID-signed binding of the protocol key is a small, checkable way to keep the DID in the picture. It is our convention, not part of Poppy.
- On macOS `*.localhost` does not resolve, so a local proving ground on `pg.localhost` needs a DNS shim.
