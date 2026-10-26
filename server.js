// Agents with Legal Agency: the backend of the demo in public/index.html.
// One process, no network at runtime: every DID, context and status list is served from memory.
import express from 'express';
import {createHash, randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import * as vc from '@digitalbazaar/vc';
import {randomBytes} from 'node:crypto';
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


// ---------------------------------------------------------------- the door: a custodian verifies, validates, releases, and reports
const skipStatusHere = async () => ({verified: true}); // status is checked by the real library call in check 3
const usedChallenges = new Set();

/** Rood's agent: builds and signs the presentation for one door. Holder-bound: challenge and domain come from the custodian. */
async function presentAt({custodian, challenge, credentials}) {
  const presentation = vc.createPresentation({verifiableCredential: credentials, holder: didOf('rood')});
  return vc.signPresentation({
    presentation, suite: keys.rood.suite, documentLoader, challenge, domain: didOf(custodian)
  });
}

const findByType = (presentation, type) =>
  (presentation.verifiableCredential ?? []).find(c => (c.type ?? []).includes(type));
const asId = v => typeof v === 'object' ? v?.id : v;

/**
 * The eight checks of CLAUDE.md, in order, stopping at the first failure. Every verification is the library's own
 * (signatures, status list, challenge/domain); the validations are the rights holder's conditions, read from the DRC.
 */
async function custodianDecides({custodian, presentation, presentationText, challenge, requested}) {
  const me = didOf(custodian);
  const checks = [];
  const evaluated = [];
  const verification = {
    verifier: me, proofValid: false, statusChecked: false, credentialStatusResult: 'unknown',
    issuerOnTrustedList: false, trustedList: TRUSTED_LIST_URL
  };
  let data = null;
  let released = null;
  const check = (label, ok) => { checks.push([label, Boolean(ok)]); return Boolean(ok); };

  const drc = findByType(presentation, 'DataRightsCredential');
  const pc = findByType(presentation, 'iSHAREParticipantCredential');
  const subject = drc?.credentialSubject ?? {};
  const index = drc?.credentialStatus?.statusListIndex ?? '?';

  decide: {
    // 1. the rights holder's signature
    const drcResult = drc ?
      await vc.verifyCredential({credential: drc, suite: verifySuite, documentLoader, checkStatus: skipStatusHere}) :
      {verified: false};
    verification.proofValid = drcResult.verified;
    if(!check('Signature on DRC verifies (eddsa-rdfc-2022)', drcResult.verified)) { break decide; }

    // 2. the scheme, not the key, says who may issue data rights
    verification.issuerOnTrustedList = trustedAs(asId(drc.issuer), 'DataRightsIssuer');
    if(!check('Issuer on iSHARE trusted list (role DataRightsIssuer)', verification.issuerOnTrustedList)) { break decide; }

    // 3. revocation: the rights holder's own Bitstring Status List, signed by the same issuer
    const status = await checkStatus({credential: drc, documentLoader, suite: verifySuite});
    verification.statusChecked = status.verified;
    const revoked = !status.verified || status.results.some(r => r.status === true);
    verification.credentialStatusResult = !status.verified ? 'unknown' : revoked ? 'revoked' : 'valid';
    if(!check(`DRC not revoked (Bitstring Status List #${index})`, status.verified && !revoked)) { break decide; }

    // 4. the presenter is the holder the credential was issued to, and signed for this door and this challenge
    const vp = await vc.verify({
      presentation, suite: verifySuite, documentLoader, challenge, domain: me, checkStatus: skipStatusHere
    });
    const signer = presentation.proof?.verificationMethod?.split('#')[0];
    const holderOk = vp.presentationResult?.verified && presentation.holder === subject.id && signer === subject.id;
    if(!check(`Holder == presenter (${subject.id}, VP challenge + domain ok)`, holderOk)) { break decide; }

    // 5. the legal prerequisite: an iSHARE participant credential from the scheme, live, with the right role
    const pcResult = pc ?
      await vc.verifyCredential({credential: pc, suite: verifySuite, documentLoader, checkStatus: skipStatusHere}) :
      {verified: false};
    const pcStatus = pc ? await checkStatus({credential: pc, documentLoader, suite: verifySuite}) : {verified: false};
    const pcs = pc?.credentialSubject ?? {};
    const pcOk = pcResult.verified && pcStatus.verified && !pcStatus.results.some(r => r.status === true) &&
      asId(pc.issuer) === SCHEME && trustedAs(SCHEME, 'ParticipantCredentialIssuer') &&
      pcs.id === presentation.holder && (pcs.role ?? []).includes('DataConsumer') && pcs.status === 'active';
    if(!check('Participant credential valid · issued by scheme · role DataConsumer · active', pcOk)) { break decide; }

    // 6. the rights holder's conditions, validated against the participant credential and this door
    const cond = subject.conditions ?? {};
    const shared = (cond.dataspaces ?? []).filter(d => (pcs.dataspaces ?? []).includes(d));
    const dataspaceOk = !(cond.dataspaces ?? []).length || shared.length > 0;
    const compliantOk = !cond.ishareCompliant || pcs.accessionAgreement != null;
    const providersOk = !(cond.serviceProviders ?? []).length || cond.serviceProviders.includes(me);
    evaluated.push(
      {leftOperand: 'dataspaces', operator: 'intersects', rightOperand: (cond.dataspaces ?? []).join(','), result: dataspaceOk},
      {leftOperand: 'ishareCompliant', operator: 'eq', rightOperand: String(Boolean(cond.ishareCompliant)), result: compliantOk},
      {leftOperand: 'serviceProviders', operator: 'contains', rightOperand: (cond.serviceProviders ?? []).join(',') || '*', result: providersOk}
    );
    const label = `Conditions: dataspace ${shared[0] ?? (cond.dataspaces ?? []).join('/')} ${dataspaceOk ? '✓' : '✗'} · ` +
      `iSHARE compliant ${compliantOk ? '✓' : '✗'} · serviceProviders ${(cond.serviceProviders ?? []).length ? me : 'unrestricted'} ${providersOk ? '✓' : '✗'}`;
    if(!check(label, dataspaceOk && compliantOk && providersOk)) { break decide; }

    // 7. what this door holds, and no more than the credential grants
    const held = (subject.resource?.identifiers ?? []).find(id => HOLDINGS[custodian]?.[id]);
    const granted = subject.resource?.attributes ?? [];
    const wanted = requested?.length ? requested : granted;
    const outside = wanted.filter(a => !granted.includes(a));
    const actionOk = (subject.actions ?? []).includes('read');
    const resourceOk = Boolean(held) && outside.length === 0 && actionOk;
    if(!check(`Resource held here: ${held ?? (subject.resource?.identifiers ?? []).join(',')} · attributes ${wanted.join(',')} ⊆ granted`, resourceOk)) { break decide; }

    // 8. the licence travels with the data
    const licenses = subject.licenses ?? [];
    const record = HOLDINGS[custodian][held];
    released = wanted.filter(a => a in record);
    data = Object.fromEntries(released.map(a => [a, record[a]]));
    data.licence = licenses[0];
    if(!check(`Licence ${licenses.join(', ')} attached to response`, licenses.length > 0)) { data = null; released = null; break decide; }
  }

  const ok = checks.every(([, passed]) => passed);
  const failed = checks.find(([, passed]) => !passed)?.[0];
  const receipt = await issueReceipt({
    custodian, presentation, presentationText, drc, pc, verification, evaluated, ok, failed, released, requested
  });
  return {checks, ok, data, receipt};
}

/**
 * The receipt: a VerificationReceiptCredential (iSHARE verification-receipt draft, the proposal for the VC WG),
 * issued and signed by the custodian, delivered to the rights holder named by the DRC. It attests verification,
 * validation and access by digest, so the rights holder holds proof without the custodian's data or log.
 */
async function issueReceipt({custodian, presentation, presentationText, drc, pc, verification, evaluated, ok, failed, released}) {
  const presented = [drc, pc].filter(Boolean).map(c => ({
    id: c.id, type: c.type, issuer: asId(c.issuer), credentialDigest: sha256(JSON.stringify(c))
  }));
  const evidence = presented.map(c => ({
    id: c.id, type: ['Evidence', ...c.type.filter(t => t !== 'VerifiableCredential')], issuer: c.issuer, digestSRI: c.credentialDigest
  }));
  const rightsHolder = asId(drc?.issuer) ?? didOf('blauw');
  const subject = {
    id: `urn:uuid:${randomUUID()}`,
    receiptOf: {presentationDigest: sha256(presentationText), presentedCredentials: presented},
    presenter: presentation.holder,
    onBehalfOf: rightsHolder,
    verifiedAt: now(),
    verification,
    validation: {policySetRef: drc?.id ?? 'urn:ishare:policy-set:none', conditionsEvaluated: evaluated, effect: ok ? 'Permit' : 'Deny'},
    outcome: ok ? 'granted' : 'denied'
  };
  if(ok) {
    subject.access = {
      resource: {...drc.credentialSubject.resource, attributes: released},
      actions: drc.credentialSubject.actions, licenses: drc.credentialSubject.licenses,
      purpose: drc.credentialSubject.purpose, grantedAt: now()
    };
  } else {
    subject.denialReason = failed;
    subject.reason = failed;
  }
  const credential = {
    '@context': [V2, CTX.receipt],
    id: `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', 'VerificationReceiptCredential'],
    issuer: didOf(custodian),
    validFrom: now(),
    evidence,
    credentialSubject: subject
  };
  const signed = await issueStrictThenLoose({credential, suite: keys[custodian].suite});
  signed.delivery = await deliverReceipt(signed);
  return signed;
}

/** Delivery to the rights holder's inbox: an HTTP POST to /receipts when the server is up, the same code path otherwise. */
async function deliverReceipt(receipt) {
  const {delivery: _d, ...payload} = receipt;
  if(listening) {
    const res = await fetch(`http://127.0.0.1:${PORT}/receipts`, {
      method: 'POST', headers: {'content-type': 'application/vc'}, body: JSON.stringify(payload)
    });
    return {endpoint: '/receipts', status: res.status, ...(await res.json())};
  }
  return {endpoint: '/receipts', status: 201, ...(await blauwInbox(payload))};
}

/** Blauw's inbox: accepts a receipt only from a trusted DataProvider, about a credential Blauw issued, addressed to Blauw. */
async function blauwInbox(receipt) {
  const me = didOf('blauw');
  const result = await vc.verifyCredential({credential: receipt, suite: verifySuite, documentLoader});
  if(!result.verified) { throw new BadRequest(`receipt not verified: ${result.error?.message ?? 'bad proof'}`); }
  const issuer = asId(receipt.issuer);
  if(!trustedAs(issuer, 'DataProvider')) { throw new BadRequest(`${issuer} is not a trusted DataProvider`); }
  const s = receipt.credentialSubject ?? {};
  if(s.onBehalfOf !== me) { throw new BadRequest(`receipt is for ${s.onBehalfOf}, not ${me}`); }
  const drcRef = (s.receiptOf?.presentedCredentials ?? []).find(c => (c.type ?? []).includes('DataRightsCredential'));
  const issued = state.issued.find(d => d.id === drcRef?.id);
  const ledgerMatch = Boolean(issued) && sha256(JSON.stringify(issued)) === drcRef.credentialDigest;
  const entry = {receivedAt: now(), from: issuer, outcome: s.outcome, drc: drcRef?.id ?? null, ledgerMatch, receipt};
  state.receipts.unshift(entry);
  return {accepted: true, id: receipt.id, ledgerMatch};
}

let listening = false;

// ---------------------------------------------------------------- http
const app = express();
app.use(express.json({limit: '256kb', type: ['application/json', 'application/vc']}));

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

app.post('/visit/:custodian', wrap(async (req, res) => {
  const custodian = req.params.custodian;
  if(!CUSTODIANS.includes(custodian)) { throw new BadRequest(`unknown custodian; choose ${CUSTODIANS.join(' | ')}`); }
  if(!state.drc) { return res.status(409).json({error: 'no DRC issued yet: POST /issue first'}); }
  const requested = req.body?.attributes ?? (req.query.attributes ? String(req.query.attributes).split(',') : undefined);

  // the custodian challenges, the agent presents, the custodian decides
  const challenge = randomBytes(16).toString('base64url');
  const presentation = await presentAt({custodian, challenge, credentials: [participantCredentials.rood, state.drc]});
  const presentationText = JSON.stringify(presentation);
  if(usedChallenges.has(challenge)) { throw new BadRequest('challenge reuse'); }
  usedChallenges.add(challenge);
  const decision = await custodianDecides({custodian, presentation, presentationText, challenge, requested});
  if(decision.ok) { res.set('Link', decision.data.licence ? `<https://licenses.ishare.eu/${decision.data.licence}>; rel="license"` : ''); }
  res.status(decision.ok ? 200 : 403).json({...decision, presentation});
}));

app.post('/revoke', wrap(async (req, res) => {
  const target = req.body?.id ? state.issued.find(d => d.id === req.body.id) : state.drc;
  if(!target) { return res.status(404).json({error: 'no such DRC'}); }
  const index = Number(target.credentialStatus.statusListIndex);
  await drcStatus.set(index, true);
  res.json({ok: true, id: target.id, statusListIndex: index, statusListCredential: drcStatus.url, revokedAt: now()});
}));

app.delete('/trusted-list/:party', (req, res) => {
  const did = didOf(req.params.party);
  const before = trustedList.issuers.length;
  trustedList.issuers = trustedList.issuers.filter(i => i.did !== did);
  trustedList.publishedAt = now();
  res.json({ok: true, removed: before - trustedList.issuers.length, did, trustedList});
});
app.post('/trusted-list/reset', (req, res) => { resetTrustedList(); trustedList.publishedAt = now(); res.json({ok: true, trustedList}); });

app.post('/receipts', wrap(async (req, res) => {
  if(!req.is('application/vc') && !req.is('application/json')) {
    return res.status(415).json({error: 'send the receipt as application/vc'});
  }
  res.status(201).json(await blauwInbox(req.body));
}));
app.get('/receipts', (req, res) => res.json(state.receipts));

app.post('/reset', (req, res) => {
  resetTrustedList();
  state.receipts = [];
  res.json({ok: true});
});
app.get('/healthz', (req, res) => res.type('text').send('ok'));

app.use(express.static(new URL('./public', import.meta.url).pathname));

export {
  app, state, keys, verifySuite, drcStatus, participantStatus, participantCredentials, trustedList, resetTrustedList,
  HOLDINGS, CUSTODIANS, PARTIES, CTX, V2, TRUSTED_LIST_URL, partyOfDid, sha256, now, wrap, BadRequest
};

if(import.meta.url === pathToFileURL(process.argv[1]).href) {
  app.listen(PORT, () => { listening = true; console.log(`agents-with-legal-agency on http://localhost:${PORT}`); });
}
