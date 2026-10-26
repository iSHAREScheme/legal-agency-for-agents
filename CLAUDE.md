# Agents with Legal Agency — hackathon repo

W3C TPAC 2026 hackathon, Dublin. 90 minutes. Ship a working demo, not a product.

## What this is
An agent gets non-public data from a custodian that does not own it. The rights holder (principal) issues a **Data Rights Credential (DRC)** — W3C VC 2.0, iSHARE profile — to the agent. The custodian verifies + validates it against the iSHARE scheme (trusted list, participant credential, conditions, licence), releases data, and sends a **receipt** VC back to the rights holder. One DRC, several custodians. Revocation at the rights holder → every door says 403.

Parties: `blue` (rights holder, DRC issuer) · `red` (agent / data user) · `green`, `yellow` (custodians) · `scheme` (iSHARE scheme owner, issues participant credentials, publishes trusted list).

## Stack — keep it this small
- Node 20+, plain `express`. One process, `server.js`, port 3000.
- Signing/verifying with Digital Bazaar libs (they're sponsoring tonight):
  `@digitalbazaar/vc`, `@digitalbazaar/data-integrity`, `@digitalbazaar/eddsa-rdfc-2022-cryptosuite`, `@digitalbazaar/ed25519-multikey`, `@digitalbazaar/vc-bitstring-status-list`, `jsonld-document-loader`.
- Keys: generate one Ed25519 multikey per party at boot, DIDs `did:web:<party>.example`, DID documents served from memory via the document loader. No network DID resolution.
- Status list: in-memory bitstring, published at `GET /status/drc` as a `BitstringStatusListCredential`.
- Trusted list: in-memory JSON, `GET /trusted-list`.
- Frontend: `public/index.html` is already there (`agents-with-legal-agency.html`, rename it). Set its `API` const to `""` (same origin). Do not redesign it.

## Endpoints (the frontend's adapter expects exactly these shapes)
- `POST /issue` — body optional `{ holder, resource:{type,identifiers,attributes}, actions, purpose, licenses, conditions, hours }`; defaults = the mock DRC in `public/index.html`. Signs with blue's key, allocates a status-list index, returns the signed DRC. **This is the general-purpose DRC issuer; it must work with any body, not just the demo defaults.**
- `POST /visit/:custodian` (`green` | `yellow`) — red's agent builds a VP (participant credential + latest DRC, with challenge+domain from the custodian), the custodian verifies and validates, returns `{ checks:[[label, bool]...], ok, data|null, receipt }`. Receipt is a signed VC by the custodian, also POSTed to `/receipts` (blue's inbox).
- `POST /revoke` — flip the DRC's status bit. `DELETE /trusted-list/:party` — remove from trusted list.
- `GET /receipts`, `GET /drc` (latest), `GET /participant/:party`, `GET /.well-known/did/:party.json` for inspection.

## Custodian check order (mirror the frontend labels, same order)
1. DRC signature verifies (eddsa-rdfc-2022)
2. DRC issuer on trusted list with role `DataRightsIssuer`
3. DRC not revoked (status list)
4. VP holder == DRC `credentialSubject.id`, VP challenge/domain match
5. Participant credential: issued by scheme, not revoked, role includes `DataConsumer`, status `active`
6. Conditions: `dataspaces` ∩ participant dataspaces ≠ ∅; `ishareCompliant`; `serviceProviders` empty or contains this custodian
7. Resource identifier held here; requested attributes ⊆ granted attributes
8. Licence from DRC echoed on the response
Stop at first failure; return 403 with that label; still issue a `denied` receipt.

## DRC profile (schemas.ishare.eu/#data-rights)
`@context`: `https://www.w3.org/ns/credentials/v2`, `https://schemas.ishare.eu/data-rights/v1` (serve a local context file with the terms used, no network fetch). `credentialSubject`: `id` (holder), `rightsHolder`, `resource{type,identifiers,attributes}`, `actions`, `purpose`, `licenses`, `conditions{ishareCompliant,dataspaces,serviceProviders,maxDelegationDepth}`, `receipt{required,to}`. `credentialStatus`: BitstringStatusListEntry, purpose `revocation`.

## Rules
- Run it after every change: `node server.js` then `curl -X POST localhost:3000/issue`. If it 500s, fix before adding anything.
- Real signatures, real verification. Do not stub `verify` to `true`.
- No TypeScript, no build step, no database, no auth beyond the credentials themselves.
- Licence: Apache-2.0 (`LICENSE` file). README: one paragraph + the five-step demo script + "known shortcuts".
- Commit after each working endpoint.
