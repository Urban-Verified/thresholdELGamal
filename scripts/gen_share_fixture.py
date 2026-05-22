#!/usr/bin/env python3
"""
Cross-implementation interop fixture for shutter-voting-sdk.

Runs a real Feldman VSS DKG in-process (n=3, t=2), encrypts a known
plaintext under the joint key, and has each keyper produce a partial
decryption share whose DLEQ proof is computed under the shutter-voting-sdk's
*exact* Fiat-Shamir transcript (Merlin-style length-prefixed appends, dual
keccak256, mod-Q reduce). The output JSON files drop directly into the SDK's
tests/vectors/decrypt-share/ and tests/vectors/tally/ directories — the
existing voting.vectors.test.ts loader picks them up automatically and runs
verifyDecryptionShare / combineShares + BSGS against them.

Run:
    cd /Users/9to5mac/Desktop/code/brainbot/thresholdELGamal
    .venv/bin/python scripts/gen_share_fixture.py [--out <dir>]

Default --out: ./fixtures/

What is *NOT* interop-tested by these fixtures:
    Anything that uses thresholdElGamal's *own* SHA-256 transcript (the
    `prove_decryption_share` function in src/crypto/proofs.py). That
    transcript is incompatible with the SDK and is out of scope for this
    fixture — see the SDK's docs/actor-usage.md §4 for the SDK transcript
    shape this script mirrors.
"""

import argparse
import json
import sys
from pathlib import Path

# Make `crypto.*` (under src/) importable when running this from scripts/.
_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from crypto.dkg import KeyperDKGState  # noqa: E402
from crypto.primitives import (  # noqa: E402
    G2,
    CURVE_ORDER,
    FIELD_MODULUS,
    point_add,
    point_multiply,
    is_identity,
    random_scalar,
)

from Crypto.Hash import keccak as _keccak_mod  # noqa: E402

# ---------------------------------------------------------------------------
#  keccak256 (legacy / Ethereum), distinct from NIST SHA3-256 in hashlib
# ---------------------------------------------------------------------------

def keccak256(data: bytes) -> bytes:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ---------------------------------------------------------------------------
#  BLS12-381 G2 compressed encoding (zcash / blst layout, 96 bytes)
#
#  Layout (big-endian):
#      bytes[0..48] = x.c1   (top 3 bits hold flags)
#      bytes[48..96] = x.c0
#  Flags in top 3 bits of byte 0:
#      0x80 — compression flag (always 1 for compressed output)
#      0x40 — infinity flag    (1 iff identity element; x bytes then zero)
#      0x20 — y-sign flag      (1 iff y is the "lexicographically larger" root)
#  y-sign rule (per zcash / IETF BLS):
#      if y.c1 != 0: 1 iff y.c1 > (p-1)/2
#      else:         1 iff y.c0 > (p-1)/2
# ---------------------------------------------------------------------------

_HALF_P = (FIELD_MODULUS - 1) // 2


def compress_g2(point) -> bytes:
    if is_identity(point):
        out = bytearray(96)
        out[0] = 0xC0  # compressed + infinity
        return bytes(out)
    xy = point.to_xy_bytes_be()  # [x.c0(48) | x.c1(48) | y.c0(48) | y.c1(48)]
    x_c0, x_c1 = xy[0:48], xy[48:96]
    y_c0_int = int.from_bytes(xy[96:144], "big")
    y_c1_int = int.from_bytes(xy[144:192], "big")
    if y_c1_int != 0:
        y_sign = 1 if y_c1_int > _HALF_P else 0
    else:
        y_sign = 1 if y_c0_int > _HALF_P else 0
    out = bytearray(96)
    out[0:48] = x_c1
    out[48:96] = x_c0
    out[0] |= 0x80
    if y_sign:
        out[0] |= 0x20
    return bytes(out)


# Self-test: compressed encoding of the G2 generator must match the canonical
# value (zcash / IETF BLS spec). If this fires, the y-sign rule or byte order
# is wrong and the SDK's G2Point.fromBytes will reject every point we emit.
_G2_GEN_COMPRESSED_HEX = (
    "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049"
    "334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051"
    "c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
)
_actual = compress_g2(G2).hex()
assert _actual == _G2_GEN_COMPRESSED_HEX, (
    "BLS12-381 G2 compression self-test failed.\n"
    f"  expected (canonical generator): {_G2_GEN_COMPRESSED_HEX}\n"
    f"  got:                            {_actual}"
)


# ---------------------------------------------------------------------------
#  shutter-voting-sdk Transcript port
#
#  Mirrors src/voting/transcript.ts and src/crypto/hash.ts exactly:
#      - parts = [utf8(label), then for each append: u32be(len(tag)) || tag ||
#                                                     u32be(len(value)) || value]
#      - challenge(tag) = wide_reduce( keccak256(0x00 || DST || u32be(len(tag))
#                                                 || tag || *parts)
#                                       ‖ keccak256(0x01 || ...) )
#      - drawn challenge is folded back via append_scalar(tag + ":chal", e)
# ---------------------------------------------------------------------------

_DST_FIAT_SHAMIR = b"SHUTTER-VOTE-FS-v1"


def _u32be(n: int) -> bytes:
    return n.to_bytes(4, "big")


def _u16be(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _scalar_to_bytes(s: int) -> bytes:
    return (s % CURVE_ORDER).to_bytes(32, "big")


def _wide_reduce(b64: bytes) -> int:
    return int.from_bytes(b64, "big") % CURVE_ORDER


class SDKTranscript:
    def __init__(self, label: str):
        self.parts: list[bytes] = [label.encode("utf-8")]

    def append(self, tag: str, value: bytes) -> None:
        tb = tag.encode("utf-8")
        self.parts.append(_u32be(len(tb)))
        self.parts.append(tb)
        self.parts.append(_u32be(len(value)))
        self.parts.append(value)

    def append_point(self, tag: str, point) -> None:
        self.append(tag, compress_g2(point))

    def append_scalar(self, tag: str, s: int) -> None:
        self.append(tag, _scalar_to_bytes(s))

    def challenge(self, tag: str) -> int:
        tb = tag.encode("utf-8")
        head = _DST_FIAT_SHAMIR + _u32be(len(tb)) + tb
        preimage = head + b"".join(self.parts)
        h1 = keccak256(b"\x00" + preimage)
        h2 = keccak256(b"\x01" + preimage)
        e = _wide_reduce(h1 + h2)
        self.append_scalar(tag + ":chal", e)
        return e


# ---------------------------------------------------------------------------
#  Decryption-share DLEQ in the SDK's transcript shape
# ---------------------------------------------------------------------------

def prove_decryption_share_sdk(
    t: SDKTranscript,
    C1, C2, mpk_k, sigma, msk_k: int, keyper_index: int,
) -> tuple[int, int]:
    """
    Mirrors src/voting/decrypt.ts `partialDecrypt`:
        bindDecryptionShare(t, ctSum, mpk_k, keyperIndex)
        proveDLEQ({P2, mpk_k, C1, sigma}, witness=msk_k, t)
    Mutates `t`. Returns the (e, z) pair the SDK encodes as `dleq_proof`.
    """
    # bindDecryptionShare
    t.append_point("dec:C1", C1)
    t.append_point("dec:C2", C2)
    t.append_point("dec:mpk_k", mpk_k)
    t.append("dec:keyperIndex", _u16be(keyper_index))

    # proveDLEQ on { base1=P2, point1=mpk_k, base2=C1, point2=sigma }
    w = random_scalar()
    a1 = point_multiply(G2, w)   # w · base1
    a2 = point_multiply(C1, w)   # w · base2

    # bindStatementDLEQ
    t.append_point("dleq:base1", G2)
    t.append_point("dleq:base2", C1)
    t.append_point("dleq:point1", mpk_k)
    t.append_point("dleq:point2", sigma)

    t.append_point("dleq:a1", a1)
    t.append_point("dleq:a2", a2)
    e = t.challenge("dleq:e")
    z = (w + msk_k * e) % CURVE_ORDER
    return e, z


def encode_dleq(e: int, z: int) -> bytes:
    return _scalar_to_bytes(e) + _scalar_to_bytes(z)


# ---------------------------------------------------------------------------
#  DKG + ciphertext + per-keyper share generation
# ---------------------------------------------------------------------------

def run_dkg(n: int, t: int):
    """
    Runs the Feldman VSS DKG in-process. Returns:
        msk[k_zero_idx]      -> scalar (combined share for keyper k_zero_idx + 1)
        mpk_k[k_zero_idx]    -> G2 point
        joint_mpk            -> G2 point (= Σ dealers' γ₀ commitments)
    """
    keypers = [KeyperDKGState() for _ in range(n)]
    round1 = []
    for i, k in enumerate(keypers):
        commits, shares = k.round1(keyper_id=i + 1, n=n, t=t)
        round1.append((commits, shares))

    all_commitments = {i + 1: round1[i][0] for i in range(n)}

    msks: list[int] = []
    mpk_ks = []
    for i, k in enumerate(keypers):
        my_id = i + 1
        # Column of shares received by this keyper from every dealer.
        received = {dealer + 1: round1[dealer][1][my_id] for dealer in range(n)}
        msk_k, mpk_k = k.round2(all_commitments, received)
        msks.append(msk_k)
        mpk_ks.append(mpk_k)

    # Joint mpk = sum of γ₀ across dealers.
    joint_mpk = round1[0][0][0]
    for i in range(1, n):
        joint_mpk = point_add(joint_mpk, round1[i][0][0])

    return msks, mpk_ks, joint_mpk


def encrypt(plaintext: int, joint_mpk):
    """ElGamal in G2: C1 = r·P₂, C2 = r·mpk + m·P₂."""
    r = random_scalar()
    C1 = point_multiply(G2, r)
    C2 = point_add(point_multiply(joint_mpk, r), point_multiply(G2, plaintext))
    return C1, C2, r


# ---------------------------------------------------------------------------
#  Fixture writers
# ---------------------------------------------------------------------------

def write_decrypt_share_vector(
    out_dir: Path,
    name: str,
    description: str,
    transcript_label: str,
    C1, C2, mpk_k, msk_k: int, keyper_index: int,
) -> dict:
    sigma = point_multiply(C1, msk_k)
    t = SDKTranscript(transcript_label)
    e, z = prove_decryption_share_sdk(t, C1, C2, mpk_k, sigma, msk_k, keyper_index)
    vec = {
        "name": name,
        "description": description,
        "version": 1,
        "inputs": {
            "ct_sum": {
                "c1": compress_g2(C1).hex(),
                "c2": compress_g2(C2).hex(),
            },
            "committee_pk": compress_g2(mpk_k).hex(),
            "keyper_index": keyper_index,
            "transcript_label": transcript_label,
            "share": {
                "keyper_index": keyper_index,
                "sigma": compress_g2(sigma).hex(),
                "dleq_proof": encode_dleq(e, z).hex(),
            },
        },
        "expected": {"verify": True},
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.json").write_text(json.dumps(vec, indent=2) + "\n")
    return vec


def write_tally_vector(
    out_dir: Path,
    name: str,
    description: str,
    plaintext: int,
    upper_bound: int,
    C1, C2, mpk_ks, msks, n: int,
) -> dict:
    """
    Build a tally vector with all n keyper shares (since n=t+1 here, we use
    every keyper). The SDK's voting.vectors.test.ts tally case re-verifies
    each share's DLEQ via verifyDecryptionShare with transcript label
    f"vec:tally:share:{keyper_index}", then runs combineShares + BSGS.
    """
    shares = []
    for i in range(n):
        keyper_index = i + 1
        msk_k = msks[i]
        mpk_k = mpk_ks[i]
        sigma = point_multiply(C1, msk_k)
        # Per-share label MUST match what the SDK test uses on the verifier
        # side: see tests/voting.vectors.test.ts line ~214.
        label = f"vec:tally:share:{keyper_index}"
        t = SDKTranscript(label)
        e, z = prove_decryption_share_sdk(t, C1, C2, mpk_k, sigma, msk_k, keyper_index)
        shares.append({
            "keyper_index": keyper_index,
            "sigma": compress_g2(sigma).hex(),
            "dleq_proof": encode_dleq(e, z).hex(),
        })

    vec = {
        "name": name,
        "description": description,
        "version": 1,
        "inputs": {
            "ct_sum": {
                "c1": compress_g2(C1).hex(),
                "c2": compress_g2(C2).hex(),
            },
            "committee_pks": [compress_g2(p).hex() for p in mpk_ks],
            "alphas": [str(i + 1) for i in range(n)],
            "upper_bound": str(upper_bound),
            "shares": shares,
        },
        "expected": {"V": str(plaintext)},
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.json").write_text(json.dumps(vec, indent=2) + "\n")
    return vec


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parent.parent / "fixtures"),
        help="Output directory (default: ./fixtures/)",
    )
    args = ap.parse_args()
    out_root = Path(args.out)

    n, t = 3, 2
    plaintext = 7
    upper_bound = 1000  # generous; real elections set this to ℓ·B

    msks, mpk_ks, joint_mpk = run_dkg(n=n, t=t)
    C1, C2, _r = encrypt(plaintext, joint_mpk)

    # Per-keyper decrypt-share vectors → SDK's tests/vectors/decrypt-share/.
    decrypt_dir = out_root / "decrypt-share"
    for i in range(n):
        kid = i + 1
        write_decrypt_share_vector(
            out_dir=decrypt_dir,
            name=f"thresholdElGamal_dkg_keyper_{kid}",
            description=(
                f"Cross-impl interop: thresholdElGamal Feldman VSS DKG (n={n}, t={t}); "
                f"keyper {kid} produces a partial decryption share on Enc(m={plaintext}) "
                f"under the joint mpk. The DLEQ is generated with thresholdElGamal's "
                f"msk_k but under the SDK's exact Fiat-Shamir transcript (Merlin-style "
                f"length-prefixed appends, dual keccak256, mod-Q reduce), so the SDK's "
                f"verifyDecryptionShare accepts the wire bytes directly."
            ),
            transcript_label=f"interop:thresholdElGamal:dkg:share:{kid}",
            C1=C1, C2=C2,
            mpk_k=mpk_ks[i], msk_k=msks[i],
            keyper_index=kid,
        )

    # Combined tally vector → SDK's tests/vectors/tally/.
    tally_dir = out_root / "tally"
    write_tally_vector(
        out_dir=tally_dir,
        name="thresholdElGamal_dkg_combined",
        description=(
            f"Cross-impl interop: thresholdElGamal Feldman VSS DKG (n={n}, t={t}); "
            f"all {n} keypers' partial decryptions on Enc(m={plaintext}) "
            f"under the joint mpk. The SDK Lagrange-combines them and BSGS-recovers "
            f"the plaintext, asserting V == {plaintext}."
        ),
        plaintext=plaintext,
        upper_bound=upper_bound,
        C1=C1, C2=C2,
        mpk_ks=mpk_ks, msks=msks, n=n,
    )

    print(f"Wrote {n} decrypt-share vectors to {decrypt_dir}/")
    print(f"Wrote 1 tally vector to {tally_dir}/")


if __name__ == "__main__":
    main()
