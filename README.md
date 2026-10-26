# Agents with Legal Agency

W3C TPAC 2026 hackathon, Dublin — Gerard van der Hoeven, iSHARE Foundation.

An AI agent needs data that isn't public. It sits behind an API at a party that doesn't own it — a terminal, a carrier, a CRM. The owner of the data (the principal) is a different legal entity than the one hosting it. So we give the agent *legal* agency: the principal issues it a **Data Rights Credential** (W3C VC 2.0, iSHARE profile) stating what it may read, for which purpose, under which licence, for how long. At the door the agent presents two credentials — its **iSHARE participant credential** (the legal prerequisite: it signed the scheme's accession agreement) and the DRC. The custodian verifies the signatures, checks the issuer against the **iSHARE trusted list**, validates the conditions, releases the data under the licence, and sends a **Verification Receipt** credential back to the principal. One mandate, any door in the scheme. The principal stays in control after issuance; the custodian never decides; trust comes from the scheme, not the key.

**For coders, in one line:** every agent stack assumes the parties behind the roles are real, accountable and bound by something, and none of them says by what. Here they are bound by a trust framework: every participant signed the same accession agreement, so a licence in a credential is a contractual obligation with a dispute procedure and sanctions behind it, and the receipt is the rights holder's proof. That is AI with legal guard rails — governance, not protocol.

## Run

```bash
npm install
node server.js          # http://localhost:3000
```

One process, no network at runtime: five parties (`scheme`, `blauw`, `rood`, `groen`, `geel`) get an Ed25519 Multikey and a `did:web` DID document at boot, resolved from memory. Everything is signed and verified with the Digital Bazaar libraries (`@digitalbazaar/vc`, Data Integrity `eddsa-rdfc-2022`, Bitstring Status List). Nothing is stubbed: a tampered credential, a replayed presentation or a forged receipt fails verification.

## The five-step demo

Open <http://localhost:3000> and press the buttons, or:

```bash
curl -s -X POST localhost:3000/issue                 # 1. Blauw issues DRC #17 to did:web:rood.example
curl -s -X POST localhost:3000/visit/groen           # 2. the agent presents (participant credential + DRC) → 200, data, receipt
curl -s -X POST localhost:3000/visit/geel            #    same credential, second door → 200
curl -s -X POST localhost:3000/revoke                # 3. Blauw flips the status bit; no call to any custodian
curl -s -X POST localhost:3000/visit/groen           #    → 403 "DRC not revoked", denied receipt still delivered
curl -s -X DELETE localhost:3000/trusted-list/blauw  # 4. the scheme drops the issuer
curl -s -X POST localhost:3000/issue                 #    a fresh, validly signed DRC
curl -s -X POST localhost:3000/visit/geel            #    → 403 "Issuer on iSHARE trusted list": trust ≠ signature
curl -s localhost:3000/receipts                      # 5. Blauw's inbox: every visit, granted or denied, as a signed receipt
```

The issuer is general-purpose. Any body works, defaults are the demo's:

```bash
curl -s -X POST localhost:3000/issue -H 'content-type: application/json' \
  -d '{"holder":"did:web:rood.example","resource":{"type":"Contact","identifiers":["crm:acct/8812"],"attributes":["email","phone"]},"purpose":"support","hours":1}'
curl -s -X POST 'localhost:3000/visit/geel?attributes=email,phone'          # 200: Geel also runs a small CRM
curl -s -X POST 'localhost:3000/visit/geel?attributes=email,creditLimitEur' # 403: outside the grant
```

Inspection: `GET /drc`, `GET /participant/:party`, `GET /trusted-list`, `GET /status/drc`, `GET /status/participants`, `GET /.well-known/did/:party.json`, `GET /receipts`. `POST /reset` restores the trusted list and empties the inbox.

## The custodian's eight checks, in order

1. DRC signature verifies (eddsa-rdfc-2022)
2. DRC issuer on the trusted list with role `DataRightsIssuer`
3. DRC not revoked — Blauw's own signed Bitstring Status List, issuer match enforced
4. VP holder == DRC `credentialSubject.id`; the presentation is signed for this door (`domain`) and this `challenge`
5. Participant credential: issued by the scheme, not revoked, role `DataConsumer`, status `active`, subject == holder
6. Conditions from the DRC: `dataspaces` ∩ participant dataspaces ≠ ∅, `ishareCompliant`, `serviceProviders` empty or contains this door
7. The resource is held here; requested attributes ⊆ granted attributes; action `read`
8. The licence from the DRC travels with the response (`Link: rel="license"` and in the body)

First failure stops the walk, answers 403 with that label, and still produces a `denied` receipt.

**9. The verifier's own requirement.** After the decision the custodian honours the DRC's `VerificationReceiptObligation`: it issues the receipt to the named recipient, within the delivery window, and the UI shows the delivery result as a ninth line. It is not part of the access decision — it is what the rights holder is owed either way.

## The receipt — our proposal to the VC WG

The DRC carries, as issuer-placed `termsOfUse`, a `VerificationReceiptObligation`: who must receive the receipt (`receiptRecipient`), within which window (`deliveryWindow`, PT24H), what it must attest (`attestationScope`) and how minimised (`contentMinimisation: digest`). The custodian reads that obligation and acts on it: every visit ends with a `VerificationReceiptCredential`, issued and signed by the custodian, delivered to the recipient the DRC names. It attests, by digest, what was presented, what was verified (proof, status, trusted list), what was validated (the conditions, each with its result), what was released under which licence — or why not. Blauw's inbox accepts a receipt only from a trusted `DataProvider`, addressed to Blauw, about a credential Blauw actually issued (digest match against its own ledger). That is non-repudiation for the rights holder without a shared ledger and without a verifier-to-issuer call at verification time. Draft schema and context: [schemas.ishare.eu](https://schemas.ishare.eu/#data-rights) (verification-receipt, v3.1 draft).

## Built from W3C blocks

VCDM 2.0 · DIDs (`did:web`, Multikey, CID) · Verifiable Credential Data Integrity with `eddsa-rdfc-2022` · Bitstring Status List · Verifiable Presentations with `challenge`/`domain`. iSHARE adds the profile (`https://schemas.ishare.eu/data-rights/v1`, `…/participant/v3`, the verification-receipt context) and the scheme (who may issue what, published as the trusted list).

## Known shortcuts

- Static trusted list, in memory; the real one is governed (`trust.ishare.eu`).
- Legal binding asserted, not enacted: no accession agreement is signed in the demo.
- Status lists are in memory, re-signed on every change; a deployment publishes them at a stable URL.
- All five parties run in one process; the agent and the custodians share a document loader, so DIDs resolve without the network. Receipts are nevertheless delivered over HTTP (`POST /receipts`).
- The DRC shape here is the hackathon profile from `CLAUDE.md` (flat `credentialSubject`); the published v3 schema expresses the same grant as `datarightsEvidence.policySets`. Purpose is stated in the DRC and echoed in the receipt, not yet validated at the door.
- Terms a custom `/issue` body brings that the iSHARE contexts do not define are issued under the VC WG `undefined-terms/v2` context, so they stay visible rather than failing silently.

Licence: Apache-2.0.
