# Holder binding: accept a `kid` of any DID method a configured resolver knows

## What happens today

The Lab test issuer binds the handle credential to the key in the proof's `jwk`, or to a did:key `kid` (D-003, which left other DID methods as "no need yet").

An agent whose identity is a DID of another method gets:

```
POST /proving-ground/pg/issuer/credential
proof header: {"alg": "EdDSA", "typ": "openid4vci-proof+jwt", "kid": "did:cid:bagaaiera…#key-assertion-1"}

400 {"error": "invalid_proof", "error_description": "kid must be a did:key DID URL: did:key:<multibase>#<multibase>."}
```

The same key sent as a bare `jwk` is accepted, and the agent goes through the x401 door. So the agent passes, but its DID took no part: the proving ground saw a key, not an identity. We hit this with a did:cid ([Archon](https://github.com/archetech/archon)) agent, handle `genitrix` on the x401 wall. An agent on did:web or did:webvh, the Lab's own method, would hit the same thing.

## Proposal

Let the operator point the issuer at a DID resolver, and list the methods to send there:

| Variable | Example | |
| --- | --- | --- |
| `DID_RESOLVER_URL` | `https://dev.uniresolver.io/1.0/identifiers/` | Anything that speaks the [Universal Resolver](https://github.com/decentralized-identity/universal-resolver)'s HTTP API |
| `DID_METHODS` | `cid,web,webvh` | The methods resolved there. Unset, the issuer behaves as it does today |

The proving ground then carries no code for any DID method beyond did:key. A method works when the resolver has a driver for it; the public Universal Resolver lists 21 today, did:webvh and did:cid among them.

The checks are the same for every method:

- The document the resolver answers is the DID's, and not deactivated.
- The `kid` names a verification method in it, listed under `authentication` or `assertionMethod`.
- The key is Ed25519 or P-256, as `publicKeyMultibase` or `publicKeyJwk`. `PROOF_ALGS` doesn't change.

The credential still carries `cnf.jwk`, so no door changes. The issuer metadata's `cryptographic_binding_methods_supported` lists `did:key`, each configured `did:<method>`, and `jwk`.

## Trust

The issuer would believe the resolver. For this credential that costs nothing: it attests a run's handle to whoever holds the run, and that caller can already name any key with `jwk`. A deployment that minds can run its own resolver, and the default stays off.

## Questions for you

1. Is a configured resolver the shape you'd want, or would you rather have drivers in the repository for a short list of methods (did:web and did:webvh are nearly there, with `didwebvh-ts`)?
2. Should the key have to be listed under `authentication` or `assertionMethod`? We think so. One consequence: the Universal Resolver's did:jwk driver answers a document with no verification relationships at all, so a did:jwk `kid` resolved there is refused.
3. Would the wall want to show the binding method a run used (`jwk`, `did:key`, `did:cid`…)? It is the interop fact this adds. Not in the patch.

## Patch

We have this working on a branch: `src/did.ts` (about 100 lines), six new tests against a stub resolver, 118 passing in all, and a feature spec and decision entry in the repository's own format. Run locally, a did:cid identity resolved through an Archon node got its credential by `kid` and went through the x401 door. Happy to open it as a PR if the direction suits; the repository has no licence or contributing notes yet, so we wanted to ask first.
