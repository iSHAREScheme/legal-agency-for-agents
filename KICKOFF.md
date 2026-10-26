# Paste this as the first message in `claude` (run it in this folder)

Read CLAUDE.md and build the backend exactly as specified. Order:

1. `npm init -y`, install the Digital Bazaar packages listed in CLAUDE.md plus express. Add `"type":"module"`.
2. `server.js`: boot generates Ed25519 multikeys + DID documents for scheme, blauw, rood, groen, geel. Document loader resolves those DIDs, the VC v2 context, the Bitstring Status List context, and a local `contexts/ishare-data-rights-v1.jsonld` + `contexts/ishare-participant-v3.jsonld` — no network.
3. At boot the scheme issues a signed iSHARE participant credential to each party (rood: role DataConsumer, dataspaces [dvu], status active) and publishes the trusted list.
4. `POST /issue` — general-purpose DRC issuer (any body; defaults from public/index.html). Signed by blauw, status-list index allocated. Test: `curl -X POST localhost:3000/issue` and `curl -X POST localhost:3000/issue -H 'content-type: application/json' -d '{"holder":"did:web:rood.example","resource":{"type":"Contact","identifiers":["crm:acct/8812"],"attributes":["email","phone"]},"purpose":"support","hours":1}'`.
5. `POST /visit/:custodian` — rood builds a VP (participant credential + DRC, challenge+domain from custodian), custodian runs the 8 checks from CLAUDE.md with REAL verification (`@digitalbazaar/vc` verify), returns `{checks, ok, data, receipt}`; receipt signed by custodian and stored in blauw's inbox (`GET /receipts`).
6. `POST /revoke`, `DELETE /trusted-list/:party`, `GET /status/drc`, `GET /trusted-list`, `GET /drc`, `GET /participant/:party`, `GET /.well-known/did/:party.json`. Serve `public/`.
7. Run the full demo via curl: issue → visit groen → visit geel → revoke → visit both (403) → delete issuer → visit both (403). Fix until it passes.
8. LICENSE (Apache-2.0), README.md (one paragraph, 5-step demo script, known shortcuts), git init + commit.

Stop and tell me when step 4 works, then continue. Don't ask questions you can answer from CLAUDE.md.
