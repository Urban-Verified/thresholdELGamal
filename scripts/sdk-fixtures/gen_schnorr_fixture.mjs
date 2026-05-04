// Generates an extended Schnorr fixture using the actual shutter-voting-sdk,
// including the (deterministic) sk and k scalars so the Python port can
// reproduce the signature byte-for-byte.

import {
  initCurves,
  schnorrKeygen,
  schnorrSign,
  schnorrVerify,
} from '../../../shutter-voting-sdk/dist/index.js';
import { encodeSchnorr } from '../../../shutter-voting-sdk/dist/index.js';

await initCurves();

// Use the same deterministic seed shape as the SDK's gen-vectors but expose
// sk/k explicitly. Pick scalars below the BLS12-381 curve order Q.
const Q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const sk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn % Q;
const k  = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321n % Q;

const msg = new Uint8Array(32);
for (let i = 0; i < 32; i++) msg[i] = (i * 7 + 3) & 0xff;

const { vk } = schnorrKeygen(sk);
const sig = schnorrSign(sk, vk, msg, k);
const ok = schnorrVerify(vk, msg, sig);

const fixture = {
  name: 'schnorr_known_sk_k',
  description: 'Schnorr signature with fixed sk and k for cross-impl interop.',
  version: 1,
  inputs: {
    sk: '0x' + sk.toString(16).padStart(64, '0'),
    k:  '0x' + k.toString(16).padStart(64, '0'),
    vk: Buffer.from(vk.toBytes()).toString('hex'),
    message: Buffer.from(msg).toString('hex'),
    R: Buffer.from(sig.R.toBytes()).toString('hex'),
    s: '0x' + sig.s.toString(16).padStart(64, '0'),
    sig_encoded: Buffer.from(encodeSchnorr(sig)).toString('hex'),
  },
  expected: { verify: ok },
};

console.log(JSON.stringify(fixture, null, 2));
