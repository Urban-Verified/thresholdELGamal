// Generates a complete Variant-A / exact-mode ballot fixture using the SDK,
// including all randomness (sk, k, r_j) so the Python port can reproduce
// the bytes byte-for-byte.

import {
  initCurves,
  schnorrKeygen,
  schnorrSign,
  encrypt,
  sumCts,
  proveOR,
  proveBudgetExact,
  encodeBallotValidityProof,
  encodeSchnorr,
  seedBallotTranscript,
  rangeCandidates,
  canonicalBallotMessage,
  verifyBallot,
  G2Point,
} from '../../../shutter-voting-sdk/dist/index.js';
import { keccak256 } from 'viem';

await initCurves();

const Q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

// Pin every scalar deterministically so the Python port can reproduce.
const electionId = new Uint8Array(32);
for (let i = 0; i < 32; i++) electionId[i] = i + 1;        // 0x010203...20
const pseudonym = new Uint8Array(32);
for (let i = 0; i < 32; i++) pseudonym[i] = (i * 5) & 0xff;

const sk = 0x1111111111111111111111111111111111111111111111111111111111111111n;
const { vk } = schnorrKeygen(sk);

// Use a known scalar for the "election public key" — it must be a valid
// BLS12-381 G2 point. Easiest: mpk = mskGlobal · P2 for some scalar.
const mskGlobal = 0x2222222222222222222222222222222222222222222222222222222222222222n;
const mpk = G2Point.generator().mul(mskGlobal);

// 3 candidates, budget=1, exact, variant A. Vote for candidate 1.
const votes = [0n, 1n, 0n];
const params = { numCandidates: 3, budget: 1, mode: 'exact', variant: 'A' };

// Encrypt with PINNED randomness so we can reproduce.
const r0 = 0x3333333333333333333333333333333333333333333333333333333333333333n;
const r1 = 0x4444444444444444444444444444444444444444444444444444444444444444n;
const r2 = 0x5555555555555555555555555555555555555555555555555555555555555555n;
const rs = [r0, r1, r2];
const cts = votes.map((v, i) => encrypt(v, mpk, rs[i]).ct);

// Seed transcript and produce per-candidate range proofs.
const t = seedBallotTranscript(electionId, mpk, vk, cts, params);
const candidates = rangeCandidates(params.budget);

// Append b'ballot:range' || u16BE(j) per the SDK.
function u16BE(n) {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

const rangeProofs = [];
for (let j = 0; j < votes.length; j++) {
  t.append('ballot:range', u16BE(j));
  // Deterministic OR-prove inputs: pin both `w` for the real branch and
  // every simulated (e, z) pair so the Python port can reproduce.
  const sims = new Array(candidates.length).fill(null).map((_, i) => {
    if (i === Number(votes[j])) return null;            // real branch
    const e = (BigInt('0x' + (j * 31 + i * 13 + 7).toString(16).padStart(2, '0').repeat(32))) % Q;
    const z = (BigInt('0x' + (j * 17 + i * 11 + 5).toString(16).padStart(2, '0').repeat(32))) % Q;
    return { e, z };
  });
  const w = (BigInt('0x' + (j * 23 + 99).toString(16).padStart(2, '0').repeat(32))) % Q;
  const proof = proveOR(
    { ct: cts[j], mpk, candidates },
    { r: rs[j], trueIndex: Number(votes[j]) },
    t,
    { w, simulated: sims },
  );
  rangeProofs.push(proof);
}

// Aggregate and budget proof (exact).
const ctSum = sumCts(cts);
const rSum = rs.reduce((a, b) => a + b, 0n);
t.append('ballot:budget', new Uint8Array([0]));
const wBudget = (BigInt('0xaa'.repeat(32))) % Q;
const budgetProof = proveBudgetExact(
  { ctSum, mpk, budget: BigInt(params.budget) },
  { rSum },
  t,
  { w: wBudget },
);

// Encode validity proof.
const bvp = {
  version: 0x01,
  variant: 'A',
  rangeOrBit: rangeProofs,
  budget: budgetProof,
};
const zkProof = encodeBallotValidityProof(bvp);

// Canonical preimage + Schnorr.
const ciphertextBytes = cts.map((ct) => [ct.c1.toBytes(), ct.c2.toBytes()]);
const preimage = canonicalBallotMessage({
  electionId,
  pseudonym,
  ciphertexts: ciphertextBytes,
  zkProof,
});
const k = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbn % Q;
const sig = schnorrSign(sk, vk, keccak256(preimage, 'bytes'), k);

// Verify it ourselves before exporting.
const ok = verifyBallot(
  {
    electionId,
    pseudonym,
    vk: vk.toBytes(),
    ciphertexts: ciphertextBytes,
    zkProof,
    voterSignature: encodeSchnorr(sig),
    wrAttestation: new Uint8Array(0),
  },
  params,
  mpk,
  () => true,
);

const hex = (b) => Buffer.from(b).toString('hex');

const fixture = {
  name: 'ballot_variantA_exact_known',
  description: 'Voter ballot with pinned (sk, k, mpk-msk, r_j) for byte-for-byte interop.',
  version: 1,
  inputs: {
    electionId: hex(electionId),
    pseudonym: hex(pseudonym),
    sk: '0x' + sk.toString(16).padStart(64, '0'),
    k:  '0x' + k.toString(16).padStart(64, '0'),
    mpk_secret: '0x' + mskGlobal.toString(16).padStart(64, '0'),
    mpk: hex(mpk.toBytes()),
    vk: hex(vk.toBytes()),
    votes: votes.map(v => v.toString()),
    randomness: rs.map(r => '0x' + r.toString(16).padStart(64, '0')),
    range_proof_w: Array.from({length: votes.length}, (_, j) =>
      '0x' + ((BigInt('0x' + (j * 23 + 99).toString(16).padStart(2, '0').repeat(32))) % Q).toString(16).padStart(64, '0')),
    budget_proof_w: '0x' + wBudget.toString(16).padStart(64, '0'),
    params,
  },
  outputs: {
    ciphertexts: ciphertextBytes.map(([a, b]) => [hex(a), hex(b)]),
    zkProof: hex(zkProof),
    voterSignature: hex(encodeSchnorr(sig)),
    canonical_preimage: hex(preimage),
  },
  expected: { verifyBallot: ok.ok, reason: ok.ok ? null : ok.reason },
};

console.log(JSON.stringify(fixture, null, 2));
