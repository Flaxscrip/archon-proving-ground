# Holder binding by any DID method a configured resolver knows

Closes #<issue>.

The Lab test issuer took a proof's `kid` only as a did:key (D-003). This PR lets an operator name other DID methods and a resolver for them, so an agent can bind its handle credential to a key in its own DID document. With nothing configured, the issuer behaves exactly as before.

The plan is `docs/features/04-did-resolver-holder-binding.md`, and the decision is D-010 in `DECISIONS.md`.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `DID_RESOLVER_URL` | unset | A resolver that speaks the Universal Resolver's HTTP API, such as `https://dev.uniresolver.io/1.0/identifiers/`. The issuer `GET`s `<DID_RESOLVER_URL><did>` |
| `DID_METHODS` | unset | The methods sent there, such as `cid,web,webvh`. did:key is always decoded locally |

Setting `DID_METHODS` without a resolver, or a non-https resolver outside the dev switch, stops the server at start.

## What changed

- **`src/did.ts`** (new): `kidToJwk(kid)`. did:key decoding moved here from `oid4vci.ts`, unchanged. For a listed method it fetches the document through `fetchPublic` (no redirects, 10 seconds, 256 KB) and takes a resolution result or a bare document.
- **Checks, the same for every method:**
  - The `kid` is a DID URL of a listed method, at most 1024 characters. Otherwise the resolver is never asked.
  - The document's `id` is the DID, and it is not deactivated.
  - The `kid` names a verification method, written in full or relatively (`#key-1`), that `authentication` or `assertionMethod` lists, by reference or embedded.
  - The key is Ed25519 or P-256, as `publicKeyMultibase` or `publicKeyJwk` with no `d`.
- **`src/oid4vci.ts`**: `checkProof` calls `kidToJwk`. `cryptographic_binding_methods_supported` is `did:key`, each `did:<method>`, then `jwk`. Refusal texts name the methods a deployment takes.
- **`src/server.ts`**: `/llms.txt` step 2 names them too.
- **README**: the two variables, and the handle credential section.

Every refusal is `invalid_proof` with its reason, and does not spend the nonce, so a holder can retry after a resolver timeout. The credential still carries `cnf.jwk`; no door changes.

## Trust

The issuer believes the resolver. This credential attests a run's handle to whoever holds the run, and that caller can already name any key with `jwk`, so a lying resolver gains nothing. D-010 records this.

## Testing

- `npm test`: 118 pass, up from 112. The six new tests are in `test/did-resolver.test.ts`: the real server against a stub resolver, covering three document shapes, did:key staying local, and twelve refusals.
- `npm run typecheck`: clean.
- Live, locally, resolver = an Archon node's `/1.0/identifiers/`: a did:cid identity with a published Ed25519 assertion key got the credential by `kid` (`did:cid:…#key-assertion-1`) and went through the x401 door, signed request, receipt verified.
- Live, locally, resolver = `dev.uniresolver.io`: the public identity `did:cid:bagaaieraxdxq4fm2kjh6yqjxjor3t2idczkmxd4v7in4u353fa6m6sms2pnq` got the credential by `kid` (`#key-assertion-1`, an Ed25519 Multikey) and went through the x401 door. Its secp256k1 `#key-1` was refused for its curve; an unresolvable did:web got the resolver's 404; an unlisted method was refused without a fetch.

## Known

- **did:jwk through the Universal Resolver is refused.** That driver's document lists no verification relationships, so the key is "not listed under authentication or assertionMethod". The check is deliberate; say if you'd rather relax it.
- **No cache.** Each proof is one fetch, marked `ponytail:` beside the rate limiting it belongs with.
- **Numbering.** PR #2 adds feature 03 and D-007 to D-009, so this takes 04 and D-010. It doesn't touch the poppy door, and should rebase cleanly either way.

## Not in this PR

- **Deploy (task 4):** choosing the Lab's resolver and methods in affinidi-lab's compose file.
- Showing the binding method on the wall.
