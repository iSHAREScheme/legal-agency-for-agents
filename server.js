// Agents with Legal Agency: the backend of the demo in public/index.html.
// One process, no network at runtime: every DID, context and status list is served from memory.
import express from 'express';
import {createHash, randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import * as vc from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as eddsaRdfc2022} from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  BitstringStatusList, checkStatus, createCredential as createStatusCredential
} from '@digitalbazaar/vc-bitstring-status-list';
import {contexts as credentialsContexts} from '@digitalbazaar/credentials-context';
import {contexts as statusContexts} from '@digitalbazaar/vc-bitstring-status-list-context';
import {contexts as multikeyContexts} from '@digitalbazaar/multikey-context';
import {contexts as didContexts} from 'did-context';
import {JsonLdDocumentLoader} from 'jsonld-document-loader';

const PORT = Number(process.env.PORT ?? 3000);
const V2 = 'https://www.w3.org/ns/credentials/v2';
const CTX = {
  drc: 'https://schemas.ishare.eu/data-rights/v1',
  participant: 'https://schemas.ishare.eu/participant/v3',
  receipt: 'https://schemas.ishare.eu/v3/verification-receipt/context.jsonld'
};
const SCHEME = 'did:web:scheme.ishare.eu';
const DRC_STATUS_URL = 'https://blauw.example/status/drc';
const PARTICIPANT_STATUS_URL = 'https://scheme.ishare.eu/status/participants';
const TRUSTED_LIST_URL = 'https://scheme.ishare.eu/trusted-list';
const FIRST_DRC_INDEX = 17;

const now = () => new Date().toISOString();
const plusHours = h => new Date(Date.now() + h * 3600e3).toISOString();
const sha256 = data => `sha256-${createHash('sha256').update(data).digest('base64')}`;

// ---------------------------------------------------------------- parties
export const didOf = party => party === 'scheme' ? SCHEME : `did:web:${party}.example`;
const PARTIES = {
  scheme: {name: 'iSHARE scheme owner'},
  blauw: {name: 'Blauw Shipping B.V.', eori: 'NL987654321', roles: ['DataRightsIssuer', 'DataRightsHolder']},
  rood: {name: 'Rood Forwarding B.V.', eori: 'NL123456789', roles: ['DataConsumer']},
  groen: {name: 'Groen Terminal B.V.', eori: 'NL555000111', roles: ['DataProvider']},
  geel: {name: 'Geel Carrier B.V.', eori: 'NL555000222', roles: ['DataProvider']}
};
const CUSTODIANS = ['groen', 'geel'];
const partyOfDid = d => Object.keys(PARTIES).find(p => didOf(p) === d);

// What the custodians hold. Same container at both doors, different content; geel is also a small CRM.
const HOLDINGS = {
  groen: {
    'CONS-2026-104455': {
      container: 'CONS-2026-104455', eta: '2026-10-27T06:40Z', location: 'Groen Terminal · yard B3',
      status: 'discharged', customsValueEur: 184250
    }
  },
  geel: {
    'CONS-2026-104455': {
      container: 'CONS-2026-104455', eta: '2026-10-27T06:10Z', location: 'vessel MV Geel 7 · berth',
      status: 'arrived', customsValueEur: 184250
    },
    'crm:acct/8812': {
      account: 'crm:acct/8812', email: 'ops@rood.example', phone: '+31 10 555 0100', creditLimitEur: 25000
    }
  }
};

// ---------------------------------------------------------------- the one place that knows how to resolve things
const loader = new JsonLdDocumentLoader();
const addContexts = map => { for(const [url, doc] of map) { loader.addStatic(url, doc); } };
addContexts(credentialsContexts);
addContexts(statusContexts);
addContexts(multikeyContexts);
addContexts(didContexts);
const localContext = async file =>
  JSON.parse(await readFile(new URL(`./contexts/${file}`, import.meta.url), 'utf8'));
loader.addStatic(CTX.drc, await localContext('ishare-data-rights-v1.jsonld'));
loader.addStatic(CTX.participant, await localContext('ishare-participant-v3.jsonld'));
loader.addStatic(CTX.receipt, await localContext('ishare-verification-receipt-v3.jsonld'));
export const documentLoader = loader.build();

// ---------------------------------------------------------------- keys, DID documents
const keys = {};
for(const party of Object.keys(PARTIES)) {
  const controller = didOf(party);
  const key = await Ed25519Multikey.generate({id: `${controller}#key-1`, controller});
  const vm = await key.export({publicKey: true, includeContext: true});
  const {'@context': _vmContext, ...method} = vm;
  const didDocument = {
    '@context': [...didContexts.keys(), ...multikeyContexts.keys()],
    id: controller,
    verificationMethod: [method],
    authentication: [key.id],
    assertionMethod: [key.id]
  };
  loader.addStatic(controller, didDocument);
  loader.addStatic(key.id, vm);
  keys[party] = {key, didDocument, suite: new DataIntegrityProof({signer: key.signer(), cryptosuite: eddsaRdfc2022})};
}
const verifySuite = new DataIntegrityProof({cryptosuite: eddsaRdfc2022});

// ---------------------------------------------------------------- Bitstring Status Lists (in memory, signed on every change)
class StatusRegistry {
  constructor({url, issuerParty}) {
    this.url = url;
    this.issuerParty = issuerParty;
    this.list = new BitstringStatusList({length: 131072});
    this.next = 0;
  }
  allocate(start = this.next) {
    const index = Math.max(start, this.next);
    this.next = index + 1;
    return index;
  }
  async publish() {
    const credential = await createStatusCredential({id: this.url, list: this.list, statusPurpose: 'revocation'});
    credential.issuer = didOf(this.issuerParty);
    credential.validFrom = now();
    this.credential = await vc.issue({credential, suite: keys[this.issuerParty].suite, documentLoader});
    loader.addStatic(this.url, this.credential);
    return this.credential;
  }
  async set(index, revoked) {
    this.list.setStatus(index, revoked);
    return this.publish();
  }
  entry(index) {
    return {
      id: `${this.url}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation',
      statusListIndex: String(index), statusListCredential: this.url
    };
  }
}
const drcStatus = new StatusRegistry({url: DRC_STATUS_URL, issuerParty: 'blauw'});
drcStatus.next = FIRST_DRC_INDEX;
const participantStatus = new StatusRegistry({url: PARTICIPANT_STATUS_URL, issuerParty: 'scheme'});
await drcStatus.publish();
await participantStatus.publish();

// ---------------------------------------------------------------- participant credentials, trusted list
const participantCredentials = {};
for(const party of ['rood', 'blauw', 'groen', 'geel']) {
  const index = party === 'rood' ? participantStatus.allocate(4471) : participantStatus.allocate();
  participantCredentials[party] = await vc.issue({
    suite: keys.scheme.suite, documentLoader,
    credential: {
      '@context': [V2, CTX.participant],
      id: `urn:uuid:${randomUUID()}`,
      type: ['VerifiableCredential', 'iSHAREParticipantCredential'],
      issuer: SCHEME,
      validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z',
      credentialSubject: {
        id: didOf(party), legalName: PARTIES[party].name, eori: PARTIES[party].eori,
        role: PARTIES[party].roles, dataspaces: ['dvu'], accessionAgreement: 'iSHARE-TF-v3', status: 'active'
      },
      credentialStatus: participantStatus.entry(index)
    }
  });
}

const trustedList = {
  scheme: 'iSHARE (hackathon stand-in)', publishedAt: now(), id: TRUSTED_LIST_URL, issuers: []
};
const resetTrustedList = () => {
  trustedList.issuers = [
    {party: 'scheme', did: SCHEME, roles: ['ParticipantCredentialIssuer'], status: 'active'},
    {party: 'blauw', did: didOf('blauw'), roles: ['DataRightsIssuer'], status: 'active'},
    ...CUSTODIANS.map(p => ({party: p, did: didOf(p), roles: ['DataProvider'], status: 'active'}))
  ];
};
resetTrustedList();
export const trustedAs = (did, role) =>
  trustedList.issuers.some(i => i.did === did && i.roles.includes(role) && i.status === 'active');

// ---------------------------------------------------------------- the mandate: Data Rights Credential
const state = {drc: null, issued: [], receipts: []};

const DEFAULTS = {
  holder: didOf('rood'),
  resource: {type: 'Container', identifiers: ['CONS-2026-104455'], attributes: ['eta', 'location', 'status']},
  actions: ['read'],
  purpose: 'arrival-planning',
  licenses: ['0001'],
  conditions: {ishareCompliant: true, dataspaces: ['dvu'], serviceProviders: [], maxDelegationDepth: 0},
  hours: 4
};

class BadRequest extends Error {}
const list = (value, what) => {
  if(!Array.isArray(value) || !value.length || value.some(v => typeof v !== 'string' || !v)) {
    throw new BadRequest(`${what} must be a non-empty array of strings`);
  }
  return value;
};

const UNDEFINED_TERMS = 'https://www.w3.org/ns/credentials/undefined-terms/v2';

/**
 * Signs with every term defined (JSON-LD safe mode). A body that brings terms the iSHARE contexts do not define
 * (a resource type of its own, extra conditions) is still issued, but the credential then says so: the VC WG's
 * undefined-terms context is added to its @context, which makes those terms legal and visible.
 */
async function issueStrictThenLoose({credential, suite}) {
  try {
    return await vc.issue({credential, suite, documentLoader});
  } catch(error) {
    if(!/safe mode/i.test(error.message)) { throw error; }
    return vc.issue({
      credential: {...credential, '@context': [...credential['@context'], UNDEFINED_TERMS]}, suite, documentLoader
    });
  }
}

/** General-purpose issuer: any body is accepted, anything missing falls back to the demo defaults. */
export async function issueDrc(body = {}) {
  const holder = body.holder ?? DEFAULTS.holder;
  if(typeof holder !== 'string' || !holder.startsWith('did:')) {
    throw new BadRequest('holder must be a DID');
  }
  const resource = {...DEFAULTS.resource, ...(body.resource ?? {})};
  if(typeof resource.type !== 'string' || !resource.type) {
    throw new BadRequest('resource.type must be a string');
  }
  list(resource.identifiers, 'resource.identifiers');
  list(resource.attributes, 'resource.attributes');
  const hours = body.hours === undefined ? DEFAULTS.hours : Number(body.hours);
  if(!(hours > 0 && hours <= 24 * 366)) {
    throw new BadRequest('hours must be a positive number');
  }
  const issuer = didOf('blauw');
  const receipt = {required: true, to: issuer, ...(body.receipt ?? {})};
  const id = `urn:uuid:${randomUUID()}`;
  const index = drcStatus.allocate();
  const credential = {
    '@context': [V2, CTX.drc],
    id,
    type: ['VerifiableCredential', 'DataRightsCredential'],
    issuer,
    validFrom: now(),
    validUntil: plusHours(hours),
    credentialSubject: {
      id: holder,
      rightsHolder: issuer,
      resource,
      actions: list(body.actions ?? DEFAULTS.actions, 'actions'),
      purpose: body.purpose ?? DEFAULTS.purpose,
      licenses: list(body.licenses ?? DEFAULTS.licenses, 'licenses'),
      conditions: {...DEFAULTS.conditions, ...(body.conditions ?? {})},
      receipt
    },
    credentialStatus: drcStatus.entry(index)
  };
  if(receipt.required) {
    // the proposal for the VC WG: the rights holder obliges the verifier to answer with a receipt credential
    credential.termsOfUse = [{
      type: 'VerificationReceiptObligation', id: `${id}#receipt`, receiptRecipient: receipt.to,
      deliveryWindow: 'PT24H', attestationScope: ['verification', 'validation', 'access'],
      contentMinimisation: 'digest'
    }];
  }
  const signed = await issueStrictThenLoose({credential, suite: keys.blauw.suite});
  state.drc = signed;
  state.issued.push(signed);
  return signed;
}

// ---------------------------------------------------------------- http
const app = express();
app.use(express.json({limit: '256kb'}));

const wrap = handler => async (req, res) => {
  try {
    await handler(req, res);
  } catch(error) {
    const status = error instanceof BadRequest ? 400 : 500;
    if(status === 500) { console.error(error); }
    res.status(status).json({error: error.message});
  }
};

app.post('/issue', wrap(async (req, res) => res.json(await issueDrc(req.body ?? {}))));
app.get('/drc', (req, res) => state.drc ? res.json(state.drc) : res.status(404).json({error: 'no DRC issued yet'}));
app.get('/participant/:party', (req, res) => {
  const credential = participantCredentials[req.params.party];
  return credential ? res.json(credential) : res.status(404).json({error: 'unknown party'});
});
app.get('/trusted-list', (req, res) => res.json(trustedList));
app.get('/status/drc', (req, res) => res.json(drcStatus.credential));
app.get('/status/participants', (req, res) => res.json(participantStatus.credential));
app.get('/.well-known/did/:party.json', (req, res) => {
  const party = req.params.party;
  return keys[party] ? res.json(keys[party].didDocument) : res.status(404).json({error: 'unknown party'});
});
app.use(express.static(new URL('./public', import.meta.url).pathname));

export {
  app, state, keys, verifySuite, drcStatus, participantStatus, participantCredentials, trustedList, resetTrustedList,
  HOLDINGS, CUSTODIANS, PARTIES, CTX, V2, TRUSTED_LIST_URL, partyOfDid, sha256, now, wrap, BadRequest
};

if(import.meta.url === pathToFileURL(process.argv[1]).href) {
  app.listen(PORT, () => console.log(`agents-with-legal-agency on http://localhost:${PORT}`));
}
